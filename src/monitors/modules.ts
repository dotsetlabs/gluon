/**
 * Gluon Module Monitor
 *
 * Tracks module/dependency loading at runtime.
 * Generates a runtime SBOM (Software Bill of Materials) based on actual imports.
 *
 * Tracking Capabilities:
 * - require() calls for CJS modules
 * - Dynamic import() statements
 * - Core Node.js modules
 * - Package version detection
 */

import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { type TelemetryCollector } from '../core/telemetry.js';
import { type GluonConfig } from '../core/config.js';

/**
 * Module record
 */
export interface ModuleRecord {
    /** Module name or path */
    name: string;
    /** Resolved absolute path */
    resolvedPath: string;
    /** Package version if available */
    version?: string;
    /** Whether it's a core Node.js module */
    isCore: boolean;
    /** Whether it's from node_modules */
    isNodeModules: boolean;
    /** Parent module that imported this */
    parent?: string;
    /** Timestamp of first load */
    firstLoaded: string;
    /** Number of times loaded */
    loadCount: number;
}

/**
 * SBOM (Software Bill of Materials) entry
 */
export interface SbomEntry {
    /** Package name */
    name: string;
    /** Package version */
    version: string;
    /** License if available */
    license?: string;
    /** Path to package */
    path: string;
}

/**
 * Module monitor class
 */
export class ModuleMonitor {
    private modules: Map<string, ModuleRecord> = new Map();
    private packages: Map<string, SbomEntry> = new Map();
    private ignoredPatterns: RegExp[];
    private generateSbom: boolean;
    private telemetry?: TelemetryCollector;
    private enabled: boolean;

    constructor(config: GluonConfig, telemetry?: TelemetryCollector) {
        this.enabled = config.modules.enabled;
        this.telemetry = telemetry;
        this.generateSbom = config.modules.generateSbom;

        // Compile ignore patterns
        this.ignoredPatterns = config.modules.ignoredPatterns.map(pattern => {
            // Convert glob-like patterns to regex
            const regexPattern = pattern
                .replace(/\*/g, '.*')
                .replace(/\//g, '\\/')
                .replace(/\./g, '\\.');
            return new RegExp(`^${regexPattern}$`);
        });
    }

    /**
     * Records a module load
     */
    async recordModuleLoad(
        moduleName: string,
        resolvedPath: string,
        parent?: string
    ): Promise<ModuleRecord | null> {
        if (!this.enabled) return null;

        // Check if ignored
        if (this.isIgnored(moduleName) || this.isIgnored(resolvedPath)) {
            return null;
        }

        const isCore = this.isCoreModule(moduleName);
        const isNodeModules = resolvedPath.includes('node_modules');
        const now = new Date().toISOString();

        // Update or create record
        const existing = this.modules.get(resolvedPath);
        if (existing) {
            existing.loadCount++;
            return existing;
        }

        // Get version for node_modules packages
        let version: string | undefined;
        if (isNodeModules && this.generateSbom) {
            version = await this.getPackageVersion(resolvedPath);
        }

        const record: ModuleRecord = {
            name: moduleName,
            resolvedPath,
            version,
            isCore,
            isNodeModules,
            parent,
            firstLoaded: now,
            loadCount: 1,
        };

        this.modules.set(resolvedPath, record);

        // Extract package for SBOM
        if (isNodeModules && this.generateSbom) {
            await this.extractPackageInfo(resolvedPath);
        }

        // Record telemetry
        this.telemetry?.recordModuleLoad(moduleName, resolvedPath, version, isCore);

        return record;
    }

    /**
     * Checks if a module should be ignored
     */
    private isIgnored(moduleId: string): boolean {
        return this.ignoredPatterns.some(pattern => pattern.test(moduleId));
    }

    /**
     * Checks if a module is a core Node.js module
     */
    private isCoreModule(moduleName: string): boolean {
        // Core modules start with 'node:' or are in the built-in list
        if (moduleName.startsWith('node:')) {
            return true;
        }

        const coreModules = new Set([
            'assert', 'buffer', 'child_process', 'cluster', 'console', 'constants',
            'crypto', 'dgram', 'dns', 'domain', 'events', 'fs', 'http', 'https',
            'module', 'net', 'os', 'path', 'perf_hooks', 'process', 'punycode',
            'querystring', 'readline', 'repl', 'stream', 'string_decoder', 'sys',
            'timers', 'tls', 'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib',
        ]);

        return coreModules.has(moduleName);
    }

    /**
     * Gets the package version from package.json
     */
    private async getPackageVersion(modulePath: string): Promise<string | undefined> {
        try {
            // Walk up to find package.json
            let dir = dirname(modulePath);
            while (dir !== '/') {
                const packageJsonPath = join(dir, 'package.json');
                try {
                    const content = await readFile(packageJsonPath, 'utf8');
                    const pkg = JSON.parse(content);
                    return pkg.version;
                } catch {
                    // Continue walking up
                }
                const parent = dirname(dir);
                if (parent === dir) break;
                dir = parent;
            }
        } catch {
            // Ignore errors
        }
        return undefined;
    }

    /**
     * Extracts package info for SBOM
     */
    private async extractPackageInfo(modulePath: string): Promise<void> {
        try {
            // Find the package.json
            let dir = dirname(modulePath);
            while (dir !== '/' && dir.includes('node_modules')) {
                const packageJsonPath = join(dir, 'package.json');
                try {
                    const content = await readFile(packageJsonPath, 'utf8');
                    const pkg = JSON.parse(content);

                    if (pkg.name && !this.packages.has(pkg.name)) {
                        this.packages.set(pkg.name, {
                            name: pkg.name,
                            version: pkg.version ?? 'unknown',
                            license: pkg.license,
                            path: dir,
                        });
                    }
                    return;
                } catch {
                    // Continue walking up
                }
                const parent = dirname(dir);
                if (parent === dir) break;
                dir = parent;
            }
        } catch {
            // Ignore errors
        }
    }

    /**
     * Gets all loaded modules
     */
    getModules(): ModuleRecord[] {
        return [...this.modules.values()];
    }

    /**
     * Gets the runtime SBOM
     */
    getSbom(): SbomEntry[] {
        return [...this.packages.values()];
    }

    /**
     * Gets module count by type
     */
    getModuleStats(): {
        total: number;
        core: number;
        nodeModules: number;
        local: number;
    } {
        let core = 0;
        let nodeModules = 0;
        let local = 0;

        for (const record of this.modules.values()) {
            if (record.isCore) {
                core++;
            } else if (record.isNodeModules) {
                nodeModules++;
            } else {
                local++;
            }
        }

        return {
            total: this.modules.size,
            core,
            nodeModules,
            local,
        };
    }

    /**
     * Exports SBOM as JSON
     */
    exportSbomJson(): string {
        const sbom = {
            bomFormat: 'GluonSBOM',
            specVersion: '1.0',
            serialNumber: `urn:uuid:${crypto.randomUUID()}`,
            version: 1,
            metadata: {
                timestamp: new Date().toISOString(),
                tools: [
                    {
                        vendor: 'dotset labs',
                        name: 'gluon',
                        version: '1.0.0',
                    },
                ],
            },
            components: this.getSbom().map(entry => ({
                type: 'library',
                name: entry.name,
                version: entry.version,
                licenses: entry.license ? [{ license: { id: entry.license } }] : [],
            })),
        };

        return JSON.stringify(sbom, null, 2);
    }

    /**
     * Clears all records
     */
    reset(): void {
        this.modules.clear();
        this.packages.clear();
    }
}

/**
 * Creates a module monitor from config
 */
export function createModuleMonitor(
    config: GluonConfig,
    telemetry?: TelemetryCollector
): ModuleMonitor {
    return new ModuleMonitor(config, telemetry);
}
