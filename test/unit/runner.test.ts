/**
 * Runner Module Tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { run, runShell, createRunner } from '../../src/runner.js';
import { createHookManager, type HookContext } from '../../src/hooks.js';
import { createDefaultConfig } from '../../src/config.js';

describe('Runner Module', () => {
    let testDir: string;

    beforeEach(async () => {
        testDir = join(tmpdir(), `gluon-runner-test-${Date.now()}`);
        await mkdir(testDir, { recursive: true });
    });

    afterEach(async () => {
        await rm(testDir, { recursive: true, force: true });
    });

    describe('run', () => {
        it('should run a simple command and return exit code', async () => {
            const result = await run('echo', ['hello'], { passThrough: false });

            expect(result.exitCode).toBe(0);
            expect(result.sessionId).toMatch(/^ses_/);
            expect(result.durationMs).toBeGreaterThanOrEqual(0);
        });

        it('should return non-zero exit code for failing commands', async () => {
            const result = await run('node', ['-e', 'process.exit(42)'], { passThrough: false });

            expect(result.exitCode).toBe(42);
        });

        it('should inject GLUON_SESSION_ID into environment', async () => {
            const scriptPath = join(testDir, 'check-env.js');
            await writeFile(scriptPath, `
                if (!process.env.GLUON_SESSION_ID) {
                    console.error('GLUON_SESSION_ID not set');
                    process.exit(1);
                }
                if (!process.env.GLUON_SESSION_ID.startsWith('ses_')) {
                    console.error('Invalid session ID format');
                    process.exit(2);
                }
                process.exit(0);
            `);

            const result = await run('node', [scriptPath], { passThrough: false });

            expect(result.exitCode).toBe(0);
        });

        it('should merge custom environment variables', async () => {
            const scriptPath = join(testDir, 'check-custom-env.js');
            await writeFile(scriptPath, `
                if (process.env.CUSTOM_VAR !== 'custom_value') {
                    process.exit(1);
                }
                process.exit(0);
            `);

            const result = await run('node', [scriptPath], {
                env: { CUSTOM_VAR: 'custom_value' },
                passThrough: false,
            });

            expect(result.exitCode).toBe(0);
        });

        it('should use custom working directory', async () => {
            const scriptPath = join(testDir, 'check-cwd.js');
            const subDir = join(testDir, 'subdir');
            await mkdir(subDir);
            await writeFile(scriptPath, `
                if (!process.cwd().includes('subdir')) {
                    process.exit(1);
                }
                process.exit(0);
            `);

            const result = await run('node', [scriptPath], {
                cwd: subDir,
                passThrough: false,
            });

            expect(result.exitCode).toBe(0);
        });

        it('should reject for non-existent command', async () => {
            await expect(run('nonexistent-command-xyz', [], { passThrough: false }))
                .rejects.toThrow(/Failed to start command/);
        });
    });

    describe('hooks integration', () => {
        it('should execute lifecycle hooks', async () => {
            const hookManager = createHookManager();
            const executed: string[] = [];

            hookManager.on('beforeStart', () => { executed.push('beforeStart'); });
            hookManager.on('afterStart', () => { executed.push('afterStart'); });
            hookManager.on('beforeStop', () => { executed.push('beforeStop'); });
            hookManager.on('afterStop', () => { executed.push('afterStop'); });

            await run('echo', ['test'], { hookManager, passThrough: false });

            expect(executed).toContain('beforeStart');
            expect(executed).toContain('afterStart');
            expect(executed).toContain('beforeStop');
            expect(executed).toContain('afterStop');
        });

        it('should pass context to hooks', async () => {
            const hookManager = createHookManager();
            let capturedContext: HookContext | null = null;

            hookManager.on('afterStart', (ctx) => {
                capturedContext = ctx;
            });

            await run('echo', ['hello', 'world'], { hookManager, passThrough: false });

            expect(capturedContext).not.toBeNull();
            expect(capturedContext!.command).toBe('echo');
            expect(capturedContext!.args).toEqual(['hello', 'world']);
            expect(capturedContext!.pid).toBeGreaterThan(0);
        });

        it('should execute stream hooks for stdout', async () => {
            const hookManager = createHookManager();
            const chunks: Buffer[] = [];

            hookManager.on('stdout', (chunk) => {
                chunks.push(chunk);
            });

            const scriptPath = join(testDir, 'output-test.js');
            await writeFile(scriptPath, `console.log('test output');`);

            await run('node', [scriptPath], { hookManager, passThrough: true });

            expect(chunks.length).toBeGreaterThan(0);
            const output = Buffer.concat(chunks).toString();
            expect(output).toContain('test output');
        });
    });

    describe('runShell', () => {
        it('should run shell commands', async () => {
            const result = await runShell('echo "hello from shell"', { passThrough: false });

            expect(result.exitCode).toBe(0);
        });

        it('should support shell operators', async () => {
            const result = await runShell('echo a && echo b', { passThrough: false });

            expect(result.exitCode).toBe(0);
        });
    });

    describe('createRunner', () => {
        it('should create a configured runner function', async () => {
            const config = createDefaultConfig();
            const runner = createRunner(config);

            const result = await runner('echo', ['test']);

            expect(result.exitCode).toBe(0);
        });

        it('should pass environment to runner', async () => {
            const config = createDefaultConfig();
            const runner = createRunner(config);

            const scriptPath = join(testDir, 'runner-env.js');
            await writeFile(scriptPath, `
                process.exit(process.env.RUNNER_VAR === 'runner_value' ? 0 : 1);
            `);

            const result = await runner('node', [scriptPath], { RUNNER_VAR: 'runner_value' });

            expect(result.exitCode).toBe(0);
        });
    });
});
