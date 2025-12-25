/**
 * Secrets Monitor Unit Tests
 * 
 * Tests the secret detection and prevention functionality
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createSecretsMonitor, type SecretMatch } from './secrets.js';
import { createDefaultConfig, type GluonConfig } from '../core/config.js';

describe('SecretsMonitor', () => {
    let config: GluonConfig;

    // Test secret that matches Stripe pattern (sk_live_ + 24 chars)
    const TEST_STRIPE_SECRET = 'sk_live_not_a_real_secret_key_123';
    const TEST_STRIPE_TEST_SECRET = 'sk_test_not_a_real_secret_key_abc';

    beforeEach(() => {
        config = createDefaultConfig('test-project');
    });

    describe('Mode Configuration', () => {
        it('should default to detect mode', () => {
            const monitor = createSecretsMonitor(config);
            expect(monitor.getMode()).toBe('detect');
        });

        it('should respect mode from config', () => {
            config.secrets.mode = 'redact';
            const monitor = createSecretsMonitor(config);
            expect(monitor.getMode()).toBe('redact');
        });

        it('should allow runtime mode change', () => {
            const monitor = createSecretsMonitor(config);
            monitor.setMode('block');
            expect(monitor.getMode()).toBe('block');
        });
    });

    describe('Pattern Detection', () => {
        it('should detect Stripe secret key', () => {
            const monitor = createSecretsMonitor(config);
            const input = Buffer.from(`Processing payment with ${TEST_STRIPE_SECRET}...`);

            const matches = monitor.scan(input, 'stdout');

            expect(matches.length).toBe(1);
            expect(matches[0].patternName).toBe('Stripe Secret Key');
            expect(matches[0].severity).toBe('critical');
        });

        it('should detect GitHub personal tokens', () => {
            const monitor = createSecretsMonitor(config);
            const input = Buffer.from('Token: ghp_123456789012345678901234567890123456');

            const matches = monitor.scan(input, 'stdout');

            expect(matches.some((m: SecretMatch) => m.patternName === 'GitHub Personal Token')).toBe(true);
        });

        it('should detect AWS access keys', () => {
            const monitor = createSecretsMonitor(config);
            const input = Buffer.from('AWS Key: AKIAIOSFODNN7EXAMPLE');

            const matches = monitor.scan(input, 'stdout');

            expect(matches.some((m: SecretMatch) => m.patternName === 'AWS Access Key ID')).toBe(true);
        });

        it('should detect multiple secrets in same input', () => {
            const monitor = createSecretsMonitor(config);
            const input = Buffer.from(`Keys: ${TEST_STRIPE_SECRET} AKIAIOSFODNN7EXAMPLE`);

            const matches = monitor.scan(input, 'stdout');

            expect(matches.length).toBeGreaterThanOrEqual(2);
        });

        it('should return empty array when no secrets found', () => {
            const monitor = createSecretsMonitor(config);
            const input = Buffer.from('Hello world, no secrets here!');

            const matches = monitor.scan(input, 'stdout');

            expect(matches.length).toBe(0);
        });
    });

    describe('ENV Tracking', () => {
        it('should detect tracked env values', () => {
            const monitor = createSecretsMonitor(config);
            monitor.trackEnvVar('MY_SECRET', 'super-secret-value-123');

            const input = Buffer.from('Logging: super-secret-value-123');
            const matches = monitor.scan(input, 'stdout');

            expect(matches.some((m: SecretMatch) => m.patternName === 'ENV:MY_SECRET')).toBe(true);
        });

        it('should not track short values', () => {
            const monitor = createSecretsMonitor(config);
            monitor.trackEnvVar('SHORT', 'abc'); // Less than 8 chars

            const input = Buffer.from('Short: abc');
            const matches = monitor.scan(input, 'stdout');

            expect(matches.some((m: SecretMatch) => m.patternName === 'ENV:SHORT')).toBe(false);
        });
    });

    describe('Transform - Detect Mode', () => {
        it('should pass through unchanged in detect mode', () => {
            config.secrets.mode = 'detect';
            const monitor = createSecretsMonitor(config);

            const input = Buffer.from(`Secret: ${TEST_STRIPE_SECRET}`);
            const output = monitor.transform(input, 'stdout');

            expect(output).not.toBeNull();
            expect(output?.toString()).toBe(input.toString());
        });
    });

    describe('Transform - Redact Mode', () => {
        it('should replace secrets with redaction text', () => {
            config.secrets.mode = 'redact';
            config.secrets.redactText = '[REDACTED]';
            const monitor = createSecretsMonitor(config);

            const input = Buffer.from(`Secret: ${TEST_STRIPE_SECRET} end`);
            const output = monitor.transform(input, 'stdout');

            expect(output).not.toBeNull();
            const text = output?.toString();
            expect(text).toContain('[REDACTED]');
            expect(text).not.toContain('sk_live_12345');
        });

        it('should use custom redaction text', () => {
            config.secrets.mode = 'redact';
            const monitor = createSecretsMonitor(config);
            monitor.setRedactText('***CENSORED***');

            const input = Buffer.from(`API: ${TEST_STRIPE_SECRET}`);
            const output = monitor.transform(input, 'stdout');

            expect(output?.toString()).toContain('***CENSORED***');
        });

        it('should redact multiple secrets in same line', () => {
            config.secrets.mode = 'redact';
            config.secrets.redactText = '[X]';
            const monitor = createSecretsMonitor(config);

            const input = Buffer.from(`Key1: ${TEST_STRIPE_SECRET} Key2: ${TEST_STRIPE_TEST_SECRET}`);
            const output = monitor.transform(input, 'stdout');

            const text = output?.toString() ?? '';
            // Both should be redacted
            expect(text.match(/\[X\]/g)?.length).toBe(2);
        });
    });

    describe('Transform - Block Mode', () => {
        it('should return null when secrets detected', () => {
            config.secrets.mode = 'block';
            const monitor = createSecretsMonitor(config);

            const input = Buffer.from(`Secret: ${TEST_STRIPE_SECRET}`);
            const output = monitor.transform(input, 'stdout');

            expect(output).toBeNull();
        });

        it('should pass through when no secrets', () => {
            config.secrets.mode = 'block';
            const monitor = createSecretsMonitor(config);

            const input = Buffer.from('No secrets here');
            const output = monitor.transform(input, 'stdout');

            expect(output).not.toBeNull();
            expect(output?.toString()).toBe('No secrets here');
        });
    });

    describe('Exposure Counting', () => {
        it('should track exposure count', () => {
            const monitor = createSecretsMonitor(config);

            expect(monitor.getExposureCount()).toBe(0);

            monitor.scan(Buffer.from(TEST_STRIPE_SECRET), 'stdout');
            expect(monitor.getExposureCount()).toBe(1);

            monitor.scan(Buffer.from('AKIAIOSFODNN7EXAMPLE'), 'stdout');
            expect(monitor.getExposureCount()).toBe(2);
        });
    });

    describe('Disabled State', () => {
        it('should not scan when disabled', () => {
            config.secrets.enabled = false;
            const monitor = createSecretsMonitor(config);

            const input = Buffer.from(`Secret: ${TEST_STRIPE_SECRET}`);
            const matches = monitor.scan(input, 'stdout');

            expect(matches.length).toBe(0);
        });

        it('should pass through when disabled', () => {
            config.secrets.enabled = false;
            const monitor = createSecretsMonitor(config);

            const input = Buffer.from(`Secret: ${TEST_STRIPE_SECRET}`);
            const output = monitor.transform(input, 'stdout');

            expect(output).toBe(input);
        });
    });
});
