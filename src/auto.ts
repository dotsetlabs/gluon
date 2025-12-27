/**
 * Gluon Auto-Instrumentation
 * 
 * Automatically initializes Gluon monitors and hooks when required.
 * Configured via environment variables when spawned by 'dotset run'.
 */

import { loadConfig, isInitialized } from './config.js';
import { createCollector } from './telemetry.js';
import { installNetworkHooks, createNetworkMonitor } from './monitors/index.js';
import { installServerHooks } from './monitors/server-hooks.js';

async function autoInit() {
    try {
        if (!process.env.GLUON_SESSION_ID) {
            return;
        }

        const initialized = await isInitialized();
        if (!initialized) {
            return;
        }

        const config = await loadConfig();
        if (!config) {
            return;
        }

        const telemetry = createCollector(config.telemetry, config.lagrangian, process.env.GLUON_SESSION_ID);

        // Install general monitors
        if (config.network.enabled) {
            const networkMonitor = createNetworkMonitor(config, telemetry);
            installNetworkHooks(networkMonitor);
        }

        // Install Lagrangian server hooks
        installServerHooks(telemetry);

        console.log(`[Gluon] Auto-instrumentation active (Session: ${process.env.GLUON_SESSION_ID})`);
    } catch (err) {
        console.error('[Gluon] Auto-init failed:', err);
    }
}

autoInit();
