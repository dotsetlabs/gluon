/**
 * Telemetry Module Tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdir, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
    TelemetryCollector,
    createCollector,
    generateSessionId,
} from '../../src/telemetry.js';

describe('Telemetry Module', () => {
    let testDir: string;

    beforeEach(async () => {
        testDir = join(tmpdir(), `gluon-telemetry-test-${Date.now()}`);
        await mkdir(testDir, { recursive: true });
    });

    afterEach(async () => {
        await rm(testDir, { recursive: true, force: true });
    });

    describe('generateSessionId', () => {
        it('should generate unique session IDs', () => {
            const id1 = generateSessionId();
            const id2 = generateSessionId();

            expect(id1).not.toBe(id2);
            expect(id1).toMatch(/^ses_[a-z0-9]+_[a-z0-9]+$/);
        });
    });

    describe('TelemetryCollector', () => {
        const createTestConfig = (overrides: Partial<{ enabled: boolean; storagePath: string; bufferSize: number; flushIntervalMs: number }> = {}) => ({
            enabled: true,
            storagePath: join(testDir, 'telemetry.log'),
            bufferSize: 10,
            flushIntervalMs: 0, // Disable auto-flush for tests
            ...overrides,
        });

        describe('record', () => {
            it('should record events with correct structure', () => {
                const collector = new TelemetryCollector(createTestConfig());
                const event = collector.record('custom', 'Test message', { foo: 'bar' });

                expect(event.id).toMatch(/^evt_/);
                expect(event.type).toBe('custom');
                expect(event.message).toBe('Test message');
                expect(event.metadata).toEqual({ foo: 'bar' });
                expect(event.severity).toBe('info');
                expect(event.sessionId).toMatch(/^ses_/);
            });

            it('should not record events when disabled', () => {
                const collector = new TelemetryCollector(createTestConfig({ enabled: false }));
                collector.record('custom', 'Test');

                expect(collector.getBufferSize()).toBe(0);
            });

            it('should buffer events until flush', () => {
                const collector = new TelemetryCollector(createTestConfig());
                collector.record('custom', 'Event 1');
                collector.record('custom', 'Event 2');

                expect(collector.getBufferSize()).toBe(2);
            });
        });

        describe('recordSecretExposure', () => {
            it('should record secret exposure with critical severity', () => {
                const collector = new TelemetryCollector(createTestConfig());
                const event = collector.recordSecretExposure(
                    'Stripe Key',
                    'stdout',
                    '...sX_live_***...'
                );

                expect(event.type).toBe('secret_exposure');
                expect(event.severity).toBe('critical');
                expect(event.metadata.patternName).toBe('Stripe Key');
                expect(event.metadata.source).toBe('stdout');
            });
        });

        describe('recordNetworkConnection', () => {
            it('should record network connection', () => {
                const collector = new TelemetryCollector(createTestConfig());
                const event = collector.recordNetworkConnection(
                    'api.example.com',
                    443,
                    'https',
                    true
                );

                expect(event.type).toBe('network_connection');
                expect(event.severity).toBe('warning'); // isNew = true
                expect(event.metadata.host).toBe('api.example.com');
                expect(event.metadata.isNew).toBe(true);
            });
        });

        describe('recordProcessStart/Stop', () => {
            it('should record process lifecycle', () => {
                const collector = new TelemetryCollector(createTestConfig());

                const startEvent = collector.recordProcessStart('npm', ['start']);
                expect(startEvent.type).toBe('process_start');
                expect(startEvent.metadata.command).toBe('npm');

                const stopEvent = collector.recordProcessStop(0);
                expect(stopEvent.type).toBe('process_stop');
                expect(stopEvent.metadata.exitCode).toBe(0);
            });
        });

        describe('flush', () => {
            it('should write events to storage file', async () => {
                const storagePath = join(testDir, 'flush-test.log');
                const collector = new TelemetryCollector(createTestConfig({ storagePath }));

                collector.record('custom', 'Event 1');
                collector.record('custom', 'Event 2');

                const flushed = await collector.flush();
                expect(flushed).toBe(2);
                expect(collector.getBufferSize()).toBe(0);

                const content = await readFile(storagePath, 'utf8');
                const lines = content.trim().split('\n');
                expect(lines.length).toBe(2);

                const event1 = JSON.parse(lines[0]);
                expect(event1.message).toBe('Event 1');
            });

            it('should return 0 for empty buffer', async () => {
                const collector = new TelemetryCollector(createTestConfig());

                const flushed = await collector.flush();
                expect(flushed).toBe(0);
            });
        });

        describe('readEvents', () => {
            it('should read stored events', async () => {
                const storagePath = join(testDir, 'read-test.log');
                const collector = new TelemetryCollector(createTestConfig({ storagePath }));

                collector.record('custom', 'Event 1');
                collector.record('custom', 'Event 2');
                await collector.flush();

                const events = await collector.readEvents();
                expect(events.length).toBe(2);
                expect(events[0].message).toBe('Event 1');
            });

            it('should limit returned events', async () => {
                const storagePath = join(testDir, 'limit-test.log');
                const collector = new TelemetryCollector(createTestConfig({ storagePath }));

                for (let i = 0; i < 5; i++) {
                    collector.record('custom', `Event ${i}`);
                }
                await collector.flush();

                const events = await collector.readEvents(2);
                expect(events.length).toBe(2);
                expect(events[0].message).toBe('Event 3');
                expect(events[1].message).toBe('Event 4');
            });

            it('should return empty array if no events', async () => {
                const collector = new TelemetryCollector(createTestConfig());
                const events = await collector.readEvents();

                expect(events).toEqual([]);
            });
        });

        describe('getStats', () => {
            it('should return event statistics', async () => {
                const storagePath = join(testDir, 'stats-test.log');
                const collector = new TelemetryCollector(createTestConfig({ storagePath }));

                collector.record('custom', 'Info event', {}, 'info');
                collector.recordSecretExposure('Test', 'stdout', '...');
                collector.recordNetworkConnection('example.com', 443, 'https');

                await collector.flush();

                const stats = await collector.getStats();
                expect(stats.totalEvents).toBe(3);
                expect(stats.byType['custom']).toBe(1);
                expect(stats.byType['secret_exposure']).toBe(1);
                expect(stats.byType['network_connection']).toBe(1);
                expect(stats.bySeverity['critical']).toBe(1);
                expect(stats.sessions).toBe(1);
            });
        });

        describe('shutdown', () => {
            it('should flush remaining events', async () => {
                const storagePath = join(testDir, 'shutdown-test.log');
                const collector = new TelemetryCollector(createTestConfig({ storagePath }));

                collector.record('custom', 'Event 1');
                expect(collector.getBufferSize()).toBe(1);

                await collector.shutdown();
                expect(collector.getBufferSize()).toBe(0);

                const content = await readFile(storagePath, 'utf8');
                expect(content).toContain('Event 1');
            });
        });
    });

    describe('createCollector', () => {
        it('should create collector with custom session ID', () => {
            const config = {
                enabled: true,
                storagePath: join(testDir, 'test.log'),
                bufferSize: 10,
                flushIntervalMs: 0,
            };

            const collector = createCollector(config, undefined, 'ses_custom_id');

            expect(collector.getSessionId()).toBe('ses_custom_id');
        });
    });
});
