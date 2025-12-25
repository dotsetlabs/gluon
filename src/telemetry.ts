/**
 * Gluon Telemetry Module
 *
 * Handles collection, buffering, and storage of security telemetry events.
 * Events are collected during application runtime and can be:
 * - Stored locally for development review
 * - Sent to Gluon Cloud for persistent storage and analysis
 *
 * Event Types:
 * - secret_exposure: Potential secret detected in output
 * - network_connection: Outbound network activity
 * - module_load: Runtime module/dependency loaded
 * - process_lifecycle: Start, stop, crash events
 */

import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { type GluonConfig } from './config.js';

/**
 * Severity levels for telemetry events
 */
export type EventSeverity = 'info' | 'warning' | 'error' | 'critical';

/**
 * Event types for categorization
 */
export type EventType =
    | 'secret_exposure'
    | 'network_connection'
    | 'module_load'
    | 'process_start'
    | 'process_stop'
    | 'process_error'
    | 'config_change'
    | 'custom';

/**
 * Base telemetry event structure
 */
export interface TelemetryEvent {
    /** Unique event ID */
    id: string;
    /** Event type for categorization */
    type: EventType;
    /** ISO timestamp of when event occurred */
    timestamp: string;
    /** Severity level */
    severity: EventSeverity;
    /** Human-readable message */
    message: string;
    /** Additional context data */
    metadata: Record<string, unknown>;
    /** Process ID if applicable */
    pid?: number;
    /** Session ID for correlating events */
    sessionId: string;
    /** Whether the event has been synced to the cloud */
    synced?: boolean;
}

/**
 * Secret exposure event
 */
export interface SecretExposureEvent extends TelemetryEvent {
    type: 'secret_exposure';
    metadata: {
        /** Pattern name that matched */
        patternName: string;
        /** Where the exposure was detected */
        source: 'stdout' | 'stderr' | 'log' | 'network';
        /** Redacted/truncated snippet for context */
        snippet: string;
        /** Environment variable name if known */
        envVar?: string;
    };
}

/**
 * Network connection event
 */
export interface NetworkConnectionEvent extends TelemetryEvent {
    type: 'network_connection';
    metadata: {
        /** Target hostname/IP */
        host: string;
        /** Target port */
        port: number;
        /** Protocol (http, https, tcp, etc.) */
        protocol: string;
        /** Whether this is a new/unseen destination */
        isNew: boolean;
    };
}

/**
 * Module load event
 */
export interface ModuleLoadEvent extends TelemetryEvent {
    type: 'module_load';
    metadata: {
        /** Module name/path */
        moduleName: string;
        /** Module version if available */
        version?: string;
        /** Full resolved path */
        resolvedPath: string;
        /** Whether it's a core module */
        isCore: boolean;
    };
}

/**
 * Generates a unique event ID
 */
function generateEventId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 10);
    return `evt_${timestamp}_${random}`;
}

/**
 * Generates a session ID for correlating events within a run
 */
export function generateSessionId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    return `ses_${timestamp}_${random}`;
}

/**
 * Telemetry collector class
 *
 * Buffers events and flushes them to storage periodically or on demand.
 */
export class TelemetryCollector {
    private buffer: TelemetryEvent[] = [];
    private sessionId: string;
    private flushTimer: ReturnType<typeof setInterval> | null = null;
    private storagePath: string;
    private bufferSize: number;
    private flushIntervalMs: number;
    private enabled: boolean;
    private cloudProjectId?: string;

    constructor(config: GluonConfig['telemetry'], sessionId?: string) {
        this.sessionId = sessionId ?? generateSessionId();
        this.storagePath = config.storagePath;
        this.bufferSize = config.bufferSize;
        this.flushIntervalMs = config.flushIntervalMs;
        this.enabled = config.enabled;

        if (this.enabled && this.flushIntervalMs > 0) {
            this.startFlushTimer();
        }
    }

    /**
     * Sets the cloud project ID for synchronization
     */
    setCloudProjectId(projectId: string): void {
        this.cloudProjectId = projectId;
    }

    /**
     * Gets the current session ID
     */
    getSessionId(): string {
        return this.sessionId;
    }

    /**
     * Starts the periodic flush timer
     */
    private startFlushTimer(): void {
        if (this.flushTimer) return;

        this.flushTimer = setInterval(() => {
            this.flush().catch(err => {
                console.error('[Gluon] Failed to flush telemetry:', err);
            });
        }, this.flushIntervalMs);

        // Don't block process exit
        this.flushTimer.unref();
    }

    /**
     * Stops the flush timer
     */
    private stopFlushTimer(): void {
        if (this.flushTimer) {
            clearInterval(this.flushTimer);
            this.flushTimer = null;
        }
    }

    /**
     * Records a telemetry event
     */
    record(
        type: EventType,
        message: string,
        metadata: Record<string, unknown> = {},
        severity: EventSeverity = 'info'
    ): TelemetryEvent {
        const event: TelemetryEvent = {
            id: generateEventId(),
            type,
            timestamp: new Date().toISOString(),
            severity,
            message,
            metadata,
            pid: process.pid,
            sessionId: this.sessionId,
        };

        if (this.enabled) {
            this.buffer.push(event);

            // Auto-flush if buffer is full
            if (this.buffer.length >= this.bufferSize) {
                this.flush().catch(err => {
                    console.error('[Gluon] Failed to flush telemetry:', err);
                });
            }
        }

        return event;
    }

    /**
     * Records a secret exposure event
     */
    recordSecretExposure(
        patternName: string,
        source: 'stdout' | 'stderr' | 'log' | 'network',
        snippet: string,
        envVar?: string
    ): SecretExposureEvent {
        const event = this.record(
            'secret_exposure',
            `Potential secret detected in ${source}`,
            { patternName, source, snippet, envVar },
            'critical'
        ) as SecretExposureEvent;

        return event;
    }

    /**
     * Records a network connection event
     */
    recordNetworkConnection(
        host: string,
        port: number,
        protocol: string,
        isNew: boolean = false
    ): NetworkConnectionEvent {
        const event = this.record(
            'network_connection',
            `Outbound connection to ${host}:${port}`,
            { host, port, protocol, isNew },
            isNew ? 'warning' : 'info'
        ) as NetworkConnectionEvent;

        return event;
    }

    /**
     * Records a module load event
     */
    recordModuleLoad(
        moduleName: string,
        resolvedPath: string,
        version?: string,
        isCore: boolean = false
    ): ModuleLoadEvent {
        const event = this.record(
            'module_load',
            `Module loaded: ${moduleName}`,
            { moduleName, version, resolvedPath, isCore },
            'info'
        ) as ModuleLoadEvent;

        return event;
    }

    /**
     * Records process start
     */
    recordProcessStart(command: string, args: string[]): TelemetryEvent {
        return this.record(
            'process_start',
            `Process started: ${command}`,
            { command, args, startTime: Date.now() },
            'info'
        );
    }

    /**
     * Records process stop
     */
    recordProcessStop(exitCode: number, signal?: string): TelemetryEvent {
        return this.record(
            'process_stop',
            `Process exited with code ${exitCode}`,
            { exitCode, signal, endTime: Date.now() },
            exitCode === 0 ? 'info' : 'warning'
        );
    }

    /**
     * Flushes buffered events to storage
     */
    async asyncFlush(): Promise<number> {
        if (this.buffer.length === 0) return 0;

        const events = [...this.buffer];
        this.buffer = [];

        try {
            // Optional: Sync to cloud if project is linked
            if (this.cloudProjectId) {
                try {
                    await this.syncToCloud(events);
                    // Mark as synced if successful
                    events.forEach(e => e.synced = true);
                } catch (err) {
                    console.error('[Gluon] Cloud sync failed during flush:', (err as Error).message);
                    // If sync failed, we'll store them as unsynced
                }
            }

            // Ensure directory exists
            await mkdir(dirname(this.storagePath), { recursive: true });

            // Append events as newline-delimited JSON
            const lines = events.map(e => JSON.stringify(e)).join('\n') + '\n';
            await appendFile(this.storagePath, lines, 'utf8');

            return events.length;
        } catch (err) {
            // Put events back in buffer on failure to write locally
            this.buffer = [...events, ...this.buffer];
            throw err;
        }
    }

    /**
     * Wrapper for flush to maintain backward compatibility and handle async properly
     */
    async flush(): Promise<number> {
        return this.asyncFlush();
    }

    /**
     * Syncs events to cloud (stub - cloud sync handled at CLI layer)
     */
    private async syncToCloud(_events: TelemetryEvent[]): Promise<void> {
        // Cloud sync is now handled at the CLI layer using @dotsetlabs/core
        // This method is a stub for API compatibility
    }

    /**
     * Public method to sync all stored events to cloud
     */
    async syncAllToCloud(): Promise<number> {
        if (!this.cloudProjectId) {
            throw new Error('Project not linked to cloud');
        }

        const events = await this.readEvents();
        const unsyncedEvents = events.filter(e => !e.synced);

        if (unsyncedEvents.length === 0) return 0;

        // Sync only unsynced events
        await this.syncToCloud(unsyncedEvents);

        // Update local storage with synced state
        // This is simplified: rewrite the entire file
        // For very large logs, this should be optimized
        unsyncedEvents.forEach(e => e.synced = true);
        const allLines = events.map(e => JSON.stringify(e)).join('\n') + '\n';
        await writeFile(this.storagePath, allLines, 'utf8');

        return unsyncedEvents.length;
    }
    async readEvents(limit?: number): Promise<TelemetryEvent[]> {
        try {
            const content = await readFile(this.storagePath, 'utf8');
            const lines = content.trim().split('\n').filter(Boolean);
            const events = lines.map(line => JSON.parse(line) as TelemetryEvent);

            if (limit) {
                return events.slice(-limit);
            }
            return events;
        } catch (err) {
            if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
                return [];
            }
            throw err;
        }
    }

    /**
     * Gets summary statistics for stored events
     */
    async getStats(): Promise<{
        totalEvents: number;
        byType: Record<string, number>;
        bySeverity: Record<string, number>;
        sessions: number;
    }> {
        const events = await this.readEvents();

        const byType: Record<string, number> = {};
        const bySeverity: Record<string, number> = {};
        const sessions = new Set<string>();

        for (const event of events) {
            byType[event.type] = (byType[event.type] ?? 0) + 1;
            bySeverity[event.severity] = (bySeverity[event.severity] ?? 0) + 1;
            sessions.add(event.sessionId);
        }

        return {
            totalEvents: events.length,
            byType,
            bySeverity,
            sessions: sessions.size,
        };
    }

    /**
     * Gets the buffered event count
     */
    getBufferSize(): number {
        return this.buffer.length;
    }

    /**
     * Shuts down the collector, flushing remaining events
     */
    async shutdown(): Promise<void> {
        this.stopFlushTimer();
        await this.flush();
    }
}

/**
 * Creates a telemetry collector from config
 */
export function createCollector(
    config: GluonConfig['telemetry'],
    sessionId?: string
): TelemetryCollector {
    return new TelemetryCollector(config, sessionId);
}
