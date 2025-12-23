/**
 * Gluon CLI Integration Tests
 *
 * End-to-end tests for all Gluon CLI commands.
 * Runs CLI commands in isolated temp directories.
 *
 * To run these tests:
 *   npm run test:integration
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createTestProject, type TestProject } from './setup.js';

describe('Gluon CLI Integration Tests', () => {
    let project: TestProject;

    beforeEach(async () => {
        project = await createTestProject();
    });

    afterEach(async () => {
        await project.cleanup();
    });

    // ========================================
    // Init Command Tests
    // ========================================
    describe('gln init', () => {
        it('should initialize a new project', async () => {
            const result = await project.run('init');

            expect(result.exitCode).toBe(0);
            expect(result.all).toContain('initialized');
            expect(await project.exists('.gluon/config.yaml')).toBe(true);
        });

        it('should prevent re-initialization', async () => {
            await project.run('init');
            const result = await project.runExpectFail('init');

            expect(result.exitCode).not.toBe(0);
            expect(result.all).toContain('already');
        });

        it('should create with custom project name', async () => {
            const result = await project.run('init', '--name', 'my-app');

            expect(result.exitCode).toBe(0);
            const config = await project.readFile('.gluon/config.yaml');
            expect(config).toContain('my-app');
        });
    });

    // ========================================
    // Run Command Tests
    // ========================================
    describe('gln run', () => {
        beforeEach(async () => {
            await project.run('init');
        });

        it('should run a simple command', async () => {
            // Use --no-network to avoid ESM module freezing issues
            const result = await project.run('run', '--no-network', '--', 'echo', 'hello');

            expect(result.exitCode).toBe(0);
            expect(result.all).toContain('hello');
        });

        it('should show session ID in output', async () => {
            const result = await project.run('run', '--no-network', '--', 'echo', 'test');

            expect(result.all).toContain('Session:');
        });

        it('should show monitoring mode', async () => {
            const result = await project.run('run', '--no-network', '--', 'echo', 'test');

            expect(result.all).toContain('Monitoring:');
        });

        it('should show local mode when not linked', async () => {
            const result = await project.run('run', '--no-network', '--', 'echo', 'test');

            expect(result.all).toContain('Local');
        });

        it('should preserve exit code from child process', async () => {
            const result = await project.runExpectFail('run', '--no-network', '--', 'node', '-e', 'process.exit(42)');

            expect(result.exitCode).toBe(42);
        });

        it('should run with --quiet flag', async () => {
            const result = await project.run('run', '--quiet', '--no-network', '--', 'echo', 'silent');

            expect(result.all).toContain('silent');
            expect(result.all).not.toContain('Session:');
        });
    });

    // ========================================
    // Status Command Tests
    // ========================================
    describe('gln status', () => {
        beforeEach(async () => {
            await project.run('init');
        });

        it('should show telemetry status', async () => {
            const result = await project.run('status');

            expect(result.exitCode).toBe(0);
            expect(result.all).toContain('Telemetry Status');
            expect(result.all).toContain('Total Events');
        });

        it('should accept --limit option', async () => {
            const result = await project.run('status', '--limit', '5');

            expect(result.exitCode).toBe(0);
        });

        it('should accept --type filter', async () => {
            const result = await project.run('status', '--type', 'secret_exposure');

            expect(result.exitCode).toBe(0);
        });

        it('should accept --severity filter', async () => {
            const result = await project.run('status', '--severity', 'critical');

            expect(result.exitCode).toBe(0);
        });
    });

    // ========================================
    // Config Command Tests
    // ========================================
    describe('gln config', () => {
        beforeEach(async () => {
            await project.run('init');
        });

        it('should show configuration', async () => {
            const result = await project.run('config');

            expect(result.exitCode).toBe(0);
        });

        it('should output config as JSON', async () => {
            const result = await project.run('config', '--json');

            expect(result.exitCode).toBe(0);
            // Should be valid JSON
            expect(() => JSON.parse(result.stdout)).not.toThrow();
        });
    });

    // ========================================
    // SBOM Command Tests
    // ========================================
    describe('gln sbom', () => {
        beforeEach(async () => {
            await project.run('init');
        });

        it('should generate SBOM in CycloneDX format', async () => {
            const result = await project.run('sbom', '--static', '--format', 'cyclonedx');

            expect(result.exitCode).toBe(0);
            // Static SBOM without package.json will show info message
            expect(result.all).toBeDefined();
        });

        it('should generate SBOM in SPDX format', async () => {
            const result = await project.run('sbom', '--static', '--format', 'spdx');

            expect(result.exitCode).toBe(0);
            // Static SBOM without package.json will show info message
            expect(result.all).toBeDefined();
        });
    });

    // ========================================
    // Help and Version Tests
    // ========================================
    describe('gln help/version', () => {
        it('should show help', async () => {
            const result = await project.run('--help');

            expect(result.exitCode).toBe(0);
            expect(result.all).toContain('gln');
            expect(result.all).toContain('init');
            expect(result.all).toContain('run');
            expect(result.all).toContain('status');
        });

        it('should show version', async () => {
            const result = await project.run('--version');

            expect(result.exitCode).toBe(0);
            expect(result.all).toMatch(/\d+\.\d+\.\d+/);
        });
    });

    // ========================================
    // Unlink Command Tests
    // ========================================
    describe('gln unlink', () => {
        beforeEach(async () => {
            await project.run('init');
        });

        it('should fail when not linked', async () => {
            const result = await project.runExpectFail('unlink');

            expect(result.exitCode).not.toBe(0);
            expect(result.all).toContain('not linked');
        });
    });
});
