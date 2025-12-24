/**
 * Config Module Tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdir, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
    createDefaultConfig,
    loadConfig,
    saveConfig,
    initConfig,
    isInitialized,
    getDefaultSecretPatterns,
    compileCustomPatterns,
} from '../../src/core/config.js';

describe('Config Module', () => {
    let testDir: string;

    beforeEach(async () => {
        testDir = join(tmpdir(), `gluon-test-${Date.now()}`);
        await mkdir(testDir, { recursive: true });
    });

    afterEach(async () => {
        await rm(testDir, { recursive: true, force: true });
    });

    describe('createDefaultConfig', () => {
        it('should create a config with default values', () => {
            const config = createDefaultConfig();

            expect(config.version).toBe('1');
            expect(config.projectName).toBe('gluon-project');
            expect(config.secrets.enabled).toBe(true);
            expect(config.network.enabled).toBe(true);
            expect(config.modules.enabled).toBe(true);
            expect(config.telemetry.enabled).toBe(true);
        });

        it('should use provided project name', () => {
            const config = createDefaultConfig('my-app');

            expect(config.projectName).toBe('my-app');
        });

        it('should have sensible default ignored domains', () => {
            const config = createDefaultConfig();

            expect(config.network.ignoredDomains).toContain('localhost');
            expect(config.network.ignoredDomains).toContain('127.0.0.1');
        });
    });

    describe('isInitialized', () => {
        it('should return false for uninitialized directory', async () => {
            const result = await isInitialized(testDir);

            expect(result).toBe(false);
        });

        it('should return true after initialization', async () => {
            await initConfig('test-project', testDir);
            const result = await isInitialized(testDir);

            expect(result).toBe(true);
        });
    });

    describe('initConfig', () => {
        it('should create config file in .dotset/gluon directory', async () => {
            const config = await initConfig('test-project', testDir);

            expect(config.projectName).toBe('test-project');

            const configPath = join(testDir, '.dotset', 'gluon', 'config.yaml');
            const content = await readFile(configPath, 'utf8');
            expect(content).toContain('test-project');
        });

        it('should throw if already initialized', async () => {
            await initConfig('test-project', testDir);

            await expect(initConfig('test-project', testDir)).rejects.toThrow(
                'already initialized'
            );
        });
    });

    describe('loadConfig', () => {
        it('should return default config if not initialized', async () => {
            const config = await loadConfig(testDir);

            expect(config.projectName).toBe('gluon-project');
        });

        it('should load saved config', async () => {
            await initConfig('loaded-project', testDir);
            const config = await loadConfig(testDir);

            expect(config.projectName).toBe('loaded-project');
        });
    });

    describe('saveConfig', () => {
        it('should save and reload config correctly', async () => {
            await initConfig('test-project', testDir);

            const config = await loadConfig(testDir);
            config.projectName = 'modified-project';
            config.secrets.enabled = false;

            await saveConfig(config, testDir);

            const reloaded = await loadConfig(testDir);
            expect(reloaded.projectName).toBe('modified-project');
            expect(reloaded.secrets.enabled).toBe(false);
        });
    });

    describe('getDefaultSecretPatterns', () => {
        it('should return array of regex patterns', () => {
            const patterns = getDefaultSecretPatterns();

            expect(Array.isArray(patterns)).toBe(true);
            expect(patterns.length).toBeGreaterThan(0);
            expect(patterns[0]).toBeInstanceOf(RegExp);
        });

        it('should match AWS access key pattern', () => {
            const patterns = getDefaultSecretPatterns();
            // This is the official AWS documentation example key
            const awsKey = 'AKIAIOSFODNN7EXAMPLE';

            const matched = patterns.some(p => p.test(awsKey));
            expect(matched).toBe(true);
        });

        it('should match Bearer token pattern', () => {
            const patterns = getDefaultSecretPatterns();
            const bearerToken = 'Bearer abcdefghijklmnopqrstuvwxyz';

            const matched = patterns.some(p => p.test(bearerToken));
            expect(matched).toBe(true);
        });
    });

    describe('compileCustomPatterns', () => {
        it('should compile enabled patterns', () => {
            const customPatterns = [
                { name: 'Test', pattern: 'TEST-[0-9]+', severity: 'high' as const, enabled: true },
                { name: 'Disabled', pattern: 'DISABLED', severity: 'low' as const, enabled: false },
            ];

            const compiled = compileCustomPatterns(customPatterns);

            expect(compiled.length).toBe(1);
            expect(compiled[0].test('TEST-123')).toBe(true);
        });

        it('should return empty array for no enabled patterns', () => {
            const customPatterns = [
                { name: 'Disabled', pattern: 'DISABLED', severity: 'low' as const, enabled: false },
            ];

            const compiled = compileCustomPatterns(customPatterns);

            expect(compiled.length).toBe(0);
        });
    });
});
