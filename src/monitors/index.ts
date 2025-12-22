/**
 * Gluon Monitors Index
 *
 * Re-exports all monitor modules for convenient access.
 */

// Core monitors (data structures and tracking)
export { SecretsMonitor, createSecretsMonitor, type SecretMatch } from './secrets.js';
export { NetworkMonitor, createNetworkMonitor, parseUrl, type ConnectionRecord, type NetworkSummary } from './network.js';
export { ModuleMonitor, createModuleMonitor, type ModuleRecord, type SbomEntry } from './modules.js';

// Runtime hooks (for intercepting Node.js internals)
export {
    installNetworkHooks,
    removeNetworkHooks,
    unregisterMonitor as unregisterNetworkMonitor,
    areHooksInstalled as areNetworkHooksInstalled,
} from './network-hooks.js';

export {
    installModuleHooks,
    removeModuleHooks,
    getLoadedModules,
    getModulesByType,
    generateSBOM,
    generateSPDX,
    getModuleStats,
    clearModuleData,
    areModuleHooksInstalled,
    type LoadedModule,
    type SBOMComponent,
} from './module-hooks.js';
