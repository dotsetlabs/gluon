/**
 * Gluon Network Monitor
 *
 * Tracks outbound network connections made by the application.
 * Detects unusual destinations and potential data exfiltration.
 *
 * Monitoring Capabilities:
 * - HTTP/HTTPS requests
 * - DNS resolutions
 * - Raw TCP connections
 * - New/unseen destination alerts
 */

import { type TelemetryCollector } from '../telemetry.js';
import { type GluonConfig } from '../config.js';

/**
 * Network connection record
 */
export interface ConnectionRecord {
    /** Target hostname or IP */
    host: string;
    /** Target port */
    port: number;
    /** Protocol (http, https, tcp, etc.) */
    protocol: string;
    /** Timestamp of first connection */
    firstSeen: string;
    /** Timestamp of last connection */
    lastSeen: string;
    /** Number of times connected */
    connectionCount: number;
}

/**
 * Network activity summary
 */
export interface NetworkSummary {
    /** Total unique hosts connected to */
    uniqueHosts: number;
    /** Total connections made */
    totalConnections: number;
    /** New hosts seen this session */
    newHosts: string[];
    /** Connection records by host */
    connections: Map<string, ConnectionRecord>;
}

/**
 * Network monitor class
 */
export class NetworkMonitor {
    private connections: Map<string, ConnectionRecord> = new Map();
    private seenHosts: Set<string> = new Set();
    private sessionNewHosts: string[] = [];
    private ignoredDomains: Set<string>;
    private alertOnNewDomains: boolean;
    private telemetry?: TelemetryCollector;
    private enabled: boolean;

    constructor(config: GluonConfig, telemetry?: TelemetryCollector) {
        this.enabled = config.network.enabled;
        this.telemetry = telemetry;
        this.ignoredDomains = new Set(config.network.ignoredDomains);
        this.alertOnNewDomains = config.network.alertOnNewDomains;
    }

    /**
     * Records a network connection
     */
    recordConnection(host: string, port: number, protocol: string = 'tcp'): ConnectionRecord | null {
        if (!this.enabled) return null;

        // Check if ignored
        if (this.isIgnored(host)) {
            return null;
        }

        const key = `${host}:${port}`;
        const now = new Date().toISOString();
        const isNew = !this.seenHosts.has(host);

        // Update or create record
        const existing = this.connections.get(key);
        if (existing) {
            existing.lastSeen = now;
            existing.connectionCount++;
        } else {
            const record: ConnectionRecord = {
                host,
                port,
                protocol,
                firstSeen: now,
                lastSeen: now,
                connectionCount: 1,
            };
            this.connections.set(key, record);
        }

        // Track new hosts
        if (isNew) {
            this.seenHosts.add(host);
            this.sessionNewHosts.push(host);
        }

        // Record telemetry
        this.telemetry?.recordNetworkConnection(host, port, protocol, isNew);

        return this.connections.get(key) ?? null;
    }

    /**
     * Checks if a host should be ignored
     */
    private isIgnored(host: string): boolean {
        // Direct match
        if (this.ignoredDomains.has(host)) {
            return true;
        }

        // Subdomain match
        for (const domain of this.ignoredDomains) {
            if (host.endsWith('.' + domain)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Adds a domain to the ignore list
     */
    ignore(domain: string): void {
        this.ignoredDomains.add(domain);
    }

    /**
     * Removes a domain from the ignore list
     */
    unignore(domain: string): void {
        this.ignoredDomains.delete(domain);
    }

    /**
     * Marks a host as "known" (won't trigger new host alerts)
     */
    markKnown(host: string): void {
        this.seenHosts.add(host);
    }

    /**
     * Gets the network activity summary
     */
    getSummary(): NetworkSummary {
        let totalConnections = 0;
        for (const record of this.connections.values()) {
            totalConnections += record.connectionCount;
        }

        return {
            uniqueHosts: this.seenHosts.size,
            totalConnections,
            newHosts: [...this.sessionNewHosts],
            connections: new Map(this.connections),
        };
    }

    /**
     * Gets connection records for a specific host
     */
    getHostConnections(host: string): ConnectionRecord[] {
        const records: ConnectionRecord[] = [];
        for (const [key, record] of this.connections) {
            if (record.host === host) {
                records.push(record);
            }
        }
        return records;
    }

    /**
     * Clears session-specific data (keeps baseline)
     */
    clearSession(): void {
        this.sessionNewHosts = [];
    }

    /**
     * Resets all data
     */
    reset(): void {
        this.connections.clear();
        this.seenHosts.clear();
        this.sessionNewHosts = [];
    }

    /**
     * Gets the count of unique destinations
     */
    getDestinationCount(): number {
        return this.connections.size;
    }

    /**
     * Gets new hosts seen this session
     */
    getNewHosts(): string[] {
        return [...this.sessionNewHosts];
    }
}

/**
 * Creates a network monitor from config
 */
export function createNetworkMonitor(
    config: GluonConfig,
    telemetry?: TelemetryCollector
): NetworkMonitor {
    return new NetworkMonitor(config, telemetry);
}

/**
 * Parses a URL and extracts host, port, protocol
 */
export function parseUrl(url: string): { host: string; port: number; protocol: string } | null {
    try {
        const parsed = new URL(url);
        const defaultPorts: Record<string, number> = {
            'http:': 80,
            'https:': 443,
            'ws:': 80,
            'wss:': 443,
            'ftp:': 21,
        };

        return {
            host: parsed.hostname,
            port: parsed.port ? parseInt(parsed.port, 10) : defaultPorts[parsed.protocol] ?? 0,
            protocol: parsed.protocol.replace(':', ''),
        };
    } catch {
        return null;
    }
}
