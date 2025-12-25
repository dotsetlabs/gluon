/**
 * @dotsetlabs/gluon
 * 
 * Security SDK for the dotset platform.
 * Runtime telemetry, secret leak detection, and network monitoring.
 * 
 * @example Using subpath imports (recommended)
 * ```typescript
 * import { HookManager } from '@dotsetlabs/gluon/hooks';
 * import { TelemetryCollector } from '@dotsetlabs/gluon/telemetry';
 * import { SecretsMonitor, NetworkMonitor } from '@dotsetlabs/gluon/monitors';
 * ```
 * 
 * @packageDocumentation
 */

// Re-export core types and classes
export { HookManager } from './hooks.js';
export { TelemetryCollector } from './telemetry.js';

// Re-export monitors
export {
    SecretsMonitor,
    NetworkMonitor,
    ModuleMonitor,
    createSecretsMonitor,
    createNetworkMonitor,
    createModuleMonitor,
} from './monitors/index.js';
