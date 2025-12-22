/**
 * Secrets Monitor Tests
 * 
 * Uses test patterns that won't trigger GitHub's push protection while still
 * validating the secret detection functionality.
 */

import { describe, it, expect } from 'vitest';
import {
    SecretsMonitor,
} from '../../src/monitors/secrets.js';
import { createDefaultConfig } from '../../src/core/config.js';

describe('Secrets Monitor', () => {
    const createMonitor = (configOverrides: Partial<ReturnType<typeof createDefaultConfig>> = {}) => {
        const config = {
            ...createDefaultConfig(),
            ...configOverrides,
        };
        return new SecretsMonitor(config);
    };

    describe('scan', () => {
        it('should detect AWS access key ID', () => {
            const monitor = createMonitor();
            // This is the official AWS example key ID that's safe to use in tests
            const input = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE';

            const matches = monitor.scan(input);

            expect(matches.length).toBeGreaterThan(0);
            expect(matches.some(m => m.patternName.includes('AWS'))).toBe(true);
        });

        it('should detect generic API key patterns', () => {
            const monitor = createMonitor();
            const input = '"api_key": "test1234567890abcdef"';

            const matches = monitor.scan(input);

            expect(matches.length).toBeGreaterThan(0);
            expect(matches.some(m => m.patternName.includes('API'))).toBe(true);
        });

        it('should detect generic secret patterns', () => {
            const monitor = createMonitor();
            const input = '"secret": "mysupersecretvalue123"';

            const matches = monitor.scan(input);

            expect(matches.length).toBeGreaterThan(0);
            expect(matches.some(m => m.patternName.toLowerCase().includes('secret'))).toBe(true);
        });

        it('should detect Bearer tokens', () => {
            const monitor = createMonitor();
            const input = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';

            const matches = monitor.scan(input);

            expect(matches.length).toBeGreaterThan(0);
            // Should match either JWT or Bearer token pattern
            expect(matches.some(m => m.patternName.includes('JWT') || m.patternName.includes('Bearer'))).toBe(true);
        });

        it('should not match normal text', () => {
            const monitor = createMonitor();
            const input = 'Hello, this is a normal log message without any secrets.';

            const matches = monitor.scan(input);

            expect(matches.length).toBe(0);
        });

        it('should return empty array when disabled', () => {
            const config = createDefaultConfig();
            config.secrets.enabled = false;
            const monitor = new SecretsMonitor(config);

            const input = 'AKIAIOSFODNN7EXAMPLE';
            const matches = monitor.scan(input);

            expect(matches.length).toBe(0);
        });

        it('should detect multiple secrets in same input', () => {
            const monitor = createMonitor();
            const input = `
                AWS Key: AKIAIOSFODNN7EXAMPLE
                Config: "api_key": "abcdefghijklmnop123"
            `;

            const matches = monitor.scan(input);

            expect(matches.length).toBeGreaterThanOrEqual(2);
        });
    });

    describe('redaction', () => {
        it('should redact matched secrets in snippet', () => {
            const monitor = createMonitor();
            const input = 'Using key: AKIAIOSFODNN7EXAMPLE here';

            const matches = monitor.scan(input);

            expect(matches.length).toBeGreaterThan(0);
            expect(matches[0].redactedSnippet).toContain('***');
            expect(matches[0].redactedSnippet).not.toContain('AKIAIOSFODNN7EXAMPLE');
        });

        it('should add ellipsis for long context', () => {
            const monitor = createMonitor();
            const input = 'A'.repeat(50) + 'AKIAIOSFODNN7EXAMPLE' + 'B'.repeat(50);

            const matches = monitor.scan(input);

            expect(matches.length).toBeGreaterThan(0);
            expect(matches[0].redactedSnippet).toMatch(/\.\.\./);
        });
    });

    describe('tracked environment variables', () => {
        it('should detect exposed env values', () => {
            // Set up env var
            process.env.TEST_SECRET = 'my-secret-value-12345';

            const config = createDefaultConfig();
            config.secrets.trackedEnvVars = ['TEST_SECRET'];
            const monitor = new SecretsMonitor(config);

            const input = 'Error: Failed with my-secret-value-12345';
            const matches = monitor.scan(input);

            expect(matches.length).toBeGreaterThan(0);
            expect(matches.some(m => m.patternName === 'ENV:TEST_SECRET')).toBe(true);

            // Cleanup
            delete process.env.TEST_SECRET;
        });

        it('should dynamically track new env vars', () => {
            process.env.DYNAMIC_SECRET = 'dynamic-value-xyz';

            const monitor = createMonitor();
            monitor.trackEnvVar('DYNAMIC_SECRET');

            const input = 'Log: dynamic-value-xyz appeared';
            const matches = monitor.scan(input);

            expect(matches.some(m => m.patternName === 'ENV:DYNAMIC_SECRET')).toBe(true);

            delete process.env.DYNAMIC_SECRET;
        });
    });

    describe('custom patterns', () => {
        it('should match custom patterns', () => {
            const config = createDefaultConfig();
            config.secrets.customPatterns = [
                {
                    name: 'Internal API Key',
                    pattern: 'MYAPP-[A-Z0-9]{16}',
                    severity: 'high',
                    enabled: true,
                },
            ];
            const monitor = new SecretsMonitor(config);

            const input = 'Using MYAPP-ABCDEF0123456789';
            const matches = monitor.scan(input);

            expect(matches.length).toBeGreaterThan(0);
            expect(matches.some(m => m.patternName === 'Internal API Key')).toBe(true);
        });

        it('should ignore disabled custom patterns', () => {
            const config = createDefaultConfig();
            config.secrets.customPatterns = [
                {
                    name: 'Disabled Pattern',
                    pattern: 'DISABLED-[0-9]+',
                    severity: 'low',
                    enabled: false,
                },
            ];
            const monitor = new SecretsMonitor(config);

            const input = 'Text with DISABLED-12345';
            const matches = monitor.scan(input);

            expect(matches.every(m => m.patternName !== 'Disabled Pattern')).toBe(true);
        });

        // Test that the real secret patterns exist and work with custom test pattern
        it('should include default patterns for real secrets', () => {
            const monitor = createMonitor();

            // Verify default patterns are loaded (without testing actual secret formats)
            expect(monitor.getPatternCount()).toBeGreaterThan(5);
        });
    });

    describe('stream hook', () => {
        it('should create working stream hook', () => {
            const monitor = createMonitor();
            const hook = monitor.createStreamHook('stdout');

            expect(typeof hook).toBe('function');
        });
    });

    describe('statistics', () => {
        it('should report pattern count', () => {
            const monitor = createMonitor();

            expect(monitor.getPatternCount()).toBeGreaterThan(0);
        });

        it('should report tracked env count', () => {
            const config = createDefaultConfig();
            process.env.COUNTER_TEST = 'value12345';
            config.secrets.trackedEnvVars = ['COUNTER_TEST'];
            const monitor = new SecretsMonitor(config);

            expect(monitor.getTrackedEnvCount()).toBe(1);

            delete process.env.COUNTER_TEST;
        });
    });
});
