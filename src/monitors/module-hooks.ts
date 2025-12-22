/**
 * Gluon Module Hooks
 *
 * Patches Node.js's module loading system to track all modules/dependencies
 * loaded at runtime. This enables:
 * - Real-time dependency tracking
 * - Detection of unexpected module loads
 * - Runtime SBOM generation
 *
 * Implementation Strategy:
 * Hooks into Module._load to intercept require() calls. For ESM, uses
 * the process-level module resolution hooks where available.
 *
 * @module monitors/module-hooks
 */

import Module from 'node:module';
import { dirname, join } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import { type TelemetryCollector } from '../core/telemetry.js';

// Access internal Module._load via type assertion
type ModuleLoadFn = (request: string, parent: NodeModule | undefined, isMain: boolean) => unknown;
type NodeModule = {
    id: string;
    filename: string;
    loaded: boolean;
    parent?: NodeModule | null;
    children: NodeModule[];
    exports: unknown;
    paths: string[];
};

// Extend Module type to include _load and _resolveFilename
const ModuleInternal = Module as typeof Module & {
    _load: ModuleLoadFn;
    _resolveFilename: (request: string, parent: NodeModule | undefined, isMain: boolean) => string;
};

/**
 * Information about a loaded module
 */
export interface LoadedModule {
    /** Module name (package name or relative path) */
    name: string;
    /** Full resolved path */
    path: string;
    /** Package version if available */
    version?: string;
    /** Whether it's a Node.js core module */
    isCore: boolean;
    /** Whether it's a node_modules dependency */
    isNodeModules: boolean;
    /** Parent module that loaded this one */
    parent?: string;
    /** Timestamp when first loaded */
    loadedAt: string;
    /** Number of times this module was required */
    loadCount: number;
}

/**
 * SBOM component in CycloneDX-ish format
 */
export interface SBOMComponent {
    type: 'library';
    name: string;
    version: string;
    purl?: string;
    scope?: 'required' | 'optional' | 'dev';
}

/** Module tracker state */
const loadedModules = new Map<string, LoadedModule>();
const seenPaths = new Set<string>();
let telemetryCollector: TelemetryCollector | undefined;
let hooksInstalled = false;
let originalLoad: ModuleLoadFn | null = null;

/** Known node core modules */
const coreModules = new Set([
    'assert', 'async_hooks', 'buffer', 'child_process', 'cluster',
    'console', 'constants', 'crypto', 'dgram', 'diagnostics_channel',
    'dns', 'domain', 'events', 'fs', 'http', 'http2', 'https',
    'inspector', 'module', 'net', 'os', 'path', 'perf_hooks',
    'process', 'punycode', 'querystring', 'readline', 'repl',
    'stream', 'string_decoder', 'sys', 'timers', 'tls', 'trace_events',
    'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib',
    // Node.js prefixed versions
    'node:assert', 'node:async_hooks', 'node:buffer', 'node:child_process',
    'node:cluster', 'node:console', 'node:constants', 'node:crypto',
    'node:dgram', 'node:diagnostics_channel', 'node:dns', 'node:domain',
    'node:events', 'node:fs', 'node:http', 'node:http2', 'node:https',
    'node:inspector', 'node:module', 'node:net', 'node:os', 'node:path',
    'node:perf_hooks', 'node:process', 'node:punycode', 'node:querystring',
    'node:readline', 'node:repl', 'node:stream', 'node:string_decoder',
    'node:sys', 'node:timers', 'node:tls', 'node:trace_events', 'node:tty',
    'node:url', 'node:util', 'node:v8', 'node:vm', 'node:wasi',
    'node:worker_threads', 'node:zlib',
]);

/**
 * Extracts package info from a node_modules path
 */
function extractPackageInfo(modulePath: string): { name: string; version?: string } | null {
    const nodeModulesIndex = modulePath.lastIndexOf('node_modules');
    if (nodeModulesIndex === -1) return null;

    const afterNodeModules = modulePath.slice(nodeModulesIndex + 'node_modules'.length + 1);
    const parts = afterNodeModules.split(/[/\\]/);

    let packageName: string;
    let packageDir: string;

    // Handle scoped packages (@org/package)
    if (parts[0]?.startsWith('@') && parts.length >= 2) {
        packageName = `${parts[0]}/${parts[1]}`;
        packageDir = join(modulePath.slice(0, nodeModulesIndex), 'node_modules', parts[0], parts[1]);
    } else {
        packageName = parts[0] ?? '';
        packageDir = join(modulePath.slice(0, nodeModulesIndex), 'node_modules', parts[0] ?? '');
    }

    // Try to read package.json for version
    let version: string | undefined;
    try {
        const packageJsonPath = join(packageDir, 'package.json');
        if (existsSync(packageJsonPath)) {
            const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
            version = packageJson.version;
        }
    } catch {
        // Ignore errors reading package.json
    }

    return { name: packageName, version };
}

/**
 * Records a module load
 */
function recordModuleLoad(request: string, resolvedPath: string, parentPath?: string): LoadedModule {
    const isCore = coreModules.has(request) || request.startsWith('node:');
    const isNodeModules = resolvedPath.includes('node_modules');
    const isNew = !seenPaths.has(resolvedPath);

    let name = request;
    let version: string | undefined;

    // Extract package info for node_modules
    if (isNodeModules) {
        const pkgInfo = extractPackageInfo(resolvedPath);
        if (pkgInfo) {
            name = pkgInfo.name;
            version = pkgInfo.version;
        }
    }

    // Get or create module record
    let moduleInfo = loadedModules.get(resolvedPath);
    if (moduleInfo) {
        moduleInfo.loadCount++;
    } else {
        moduleInfo = {
            name,
            path: resolvedPath,
            version,
            isCore,
            isNodeModules,
            parent: parentPath,
            loadedAt: new Date().toISOString(),
            loadCount: 1,
        };
        loadedModules.set(resolvedPath, moduleInfo);
    }

    seenPaths.add(resolvedPath);

    // Record telemetry for new non-core modules
    if (isNew && !isCore && telemetryCollector) {
        telemetryCollector.recordModuleLoad(
            name,
            resolvedPath,
            version,
            isCore
        );
    }

    return moduleInfo;
}

/**
 * Creates a wrapped Module._load function
 */
function createLoadWrapper(original: ModuleLoadFn): ModuleLoadFn {
    return function wrappedLoad(
        this: unknown,
        request: string,
        parent: NodeModule | undefined,
        isMain: boolean
    ): unknown {
        // Call original first to let it resolve/load the module
        const result = original.call(this, request, parent, isMain);

        // Try to get the resolved path
        try {
            let resolvedPath: string | undefined;

            // Try to resolve the module path
            if (coreModules.has(request) || request.startsWith('node:')) {
                resolvedPath = request;
            } else if (parent) {
                try {
                    resolvedPath = ModuleInternal._resolveFilename(request, parent, isMain);
                } catch {
                    // Module might be dynamically generated
                    resolvedPath = request;
                }
            }

            if (resolvedPath) {
                recordModuleLoad(request, resolvedPath, parent?.filename);
            }
        } catch {
            // Don't let tracking errors affect module loading
        }

        return result;
    };
}

/**
 * Installs module tracking hooks
 *
 * @param collector - Optional telemetry collector for event logging
 */
export function installModuleHooks(collector?: TelemetryCollector): void {
    if (hooksInstalled) {
        if (collector) {
            telemetryCollector = collector;
        }
        return;
    }

    telemetryCollector = collector;

    // Store original and wrap
    originalLoad = ModuleInternal._load;
    ModuleInternal._load = createLoadWrapper(originalLoad);

    hooksInstalled = true;
}

/**
 * Removes module tracking hooks
 */
export function removeModuleHooks(): void {
    if (!hooksInstalled || !originalLoad) {
        return;
    }

    ModuleInternal._load = originalLoad;
    originalLoad = null;
    hooksInstalled = false;
}

/**
 * Gets all loaded modules
 */
export function getLoadedModules(): LoadedModule[] {
    return [...loadedModules.values()];
}

/**
 * Gets loaded modules filtered by type
 */
export function getModulesByType(options: {
    includeCore?: boolean;
    includeNodeModules?: boolean;
    includeLocal?: boolean;
} = {}): LoadedModule[] {
    const {
        includeCore = false,
        includeNodeModules = true,
        includeLocal = true,
    } = options;

    return [...loadedModules.values()].filter(m => {
        if (m.isCore && !includeCore) return false;
        if (m.isNodeModules && !includeNodeModules) return false;
        if (!m.isCore && !m.isNodeModules && !includeLocal) return false;
        return true;
    });
}

/**
 * Generates a runtime SBOM in CycloneDX-compatible format
 */
export function generateSBOM(projectName: string = 'runtime-sbom'): {
    bomFormat: 'CycloneDX';
    specVersion: '1.5';
    version: 1;
    metadata: {
        timestamp: string;
        tools: { vendor: string; name: string; version: string }[];
        component: { type: string; name: string };
    };
    components: SBOMComponent[];
} {
    const components: SBOMComponent[] = [];
    const seenPackages = new Set<string>();

    for (const module of loadedModules.values()) {
        // Only include node_modules dependencies
        if (!module.isNodeModules || module.isCore) continue;

        // Dedupe by name+version
        const key = `${module.name}@${module.version ?? 'unknown'}`;
        if (seenPackages.has(key)) continue;
        seenPackages.add(key);

        const component: SBOMComponent = {
            type: 'library',
            name: module.name,
            version: module.version ?? 'unknown',
        };

        // Add purl (package URL) for npm packages
        if (module.version) {
            component.purl = `pkg:npm/${module.name.replace(/\//g, '%2F')}@${module.version}`;
        }

        components.push(component);
    }

    return {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        metadata: {
            timestamp: new Date().toISOString(),
            tools: [{
                vendor: 'dotsetlabs',
                name: 'gluon',
                version: '1.0.0',
            }],
            component: {
                type: 'application',
                name: projectName,
            },
        },
        components,
    };
}

/**
 * Generates SBOM in SPDX format
 */
export function generateSPDX(projectName: string = 'runtime-sbom'): {
    spdxVersion: 'SPDX-2.3';
    dataLicense: 'CC0-1.0';
    SPDXID: string;
    name: string;
    documentNamespace: string;
    creationInfo: {
        created: string;
        creators: string[];
    };
    packages: {
        SPDXID: string;
        name: string;
        versionInfo: string;
        downloadLocation: string;
    }[];
} {
    const packages: {
        SPDXID: string;
        name: string;
        versionInfo: string;
        downloadLocation: string;
    }[] = [];
    const seenPackages = new Set<string>();

    let packageIndex = 0;
    for (const module of loadedModules.values()) {
        if (!module.isNodeModules || module.isCore) continue;

        const key = `${module.name}@${module.version ?? 'unknown'}`;
        if (seenPackages.has(key)) continue;
        seenPackages.add(key);

        packages.push({
            SPDXID: `SPDXRef-Package-${++packageIndex}`,
            name: module.name,
            versionInfo: module.version ?? 'unknown',
            downloadLocation: `https://www.npmjs.com/package/${module.name}`,
        });
    }

    return {
        spdxVersion: 'SPDX-2.3',
        dataLicense: 'CC0-1.0',
        SPDXID: 'SPDXRef-DOCUMENT',
        name: projectName,
        documentNamespace: `https://gluon.dotsetlabs.com/sbom/${projectName}/${Date.now()}`,
        creationInfo: {
            created: new Date().toISOString(),
            creators: ['Tool: gluon-1.0.0'],
        },
        packages,
    };
}

/**
 * Clears all recorded module data
 */
export function clearModuleData(): void {
    loadedModules.clear();
    seenPaths.clear();
}

/**
 * Gets module load statistics
 */
export function getModuleStats(): {
    total: number;
    core: number;
    nodeModules: number;
    local: number;
    uniquePackages: number;
} {
    let core = 0;
    let nodeModules = 0;
    let local = 0;
    const uniquePackages = new Set<string>();

    for (const module of loadedModules.values()) {
        if (module.isCore) {
            core++;
        } else if (module.isNodeModules) {
            nodeModules++;
            uniquePackages.add(module.name);
        } else {
            local++;
        }
    }

    return {
        total: loadedModules.size,
        core,
        nodeModules,
        local,
        uniquePackages: uniquePackages.size,
    };
}

/**
 * Checks if hooks are installed
 */
export function areModuleHooksInstalled(): boolean {
    return hooksInstalled;
}
