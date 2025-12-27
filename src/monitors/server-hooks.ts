/**
 * Gluon Server Hooks
 *
 * Patches Node.js's http and https modules to intercept inbound
 * HTTP requests. This enables Lagrangian to capture crash context.
 */

import type * as httpType from 'node:http';
import type * as httpsType from 'node:https';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const http = require('node:http');
const https = require('node:https');
import { type TelemetryCollector } from '../telemetry.js';

let hooksInstalled = false;
let originalCreateServer: typeof httpType.createServer | null = null;
let originalHttpsCreateServer: typeof httpsType.createServer | null = null;

/**
 * Registers server hooks
 */
export function installServerHooks(telemetry: TelemetryCollector): void {
    if (hooksInstalled) return;

    originalCreateServer = http.createServer;
    originalHttpsCreateServer = https.createServer;

    // Patch http.createServer
    (http as any).createServer = function (...args: any[]) {
        const server = (originalCreateServer as any).apply(this, args);
        instrumentServer(server, telemetry);
        return server;
    };

    // Patch https.createServer
    (https as any).createServer = function (...args: any[]) {
        const server = (originalHttpsCreateServer as any).apply(this, args);
        instrumentServer(server, telemetry);
        return server;
    };

    hooksInstalled = true;
}

/**
 * Instruments an HTTP/S server instance
 */
function instrumentServer(server: httpType.Server | httpsType.Server, telemetry: TelemetryCollector): void {
    server.on('request', (req: httpType.IncomingMessage, res: httpType.ServerResponse) => {
        const startTime = Date.now();
        const chunks: Buffer[] = [];

        req.on('data', (chunk: Buffer) => {
            chunks.push(chunk);
        });

        res.on('finish', () => {
            const durationMs = Date.now() - startTime;
            const statusCode = res.statusCode;

            // For Lagrangian prototype, we capture on any 5xx error
            if (statusCode >= 500) {
                const body = Buffer.concat(chunks).toString('utf8');
                const headers: Record<string, string> = {};
                for (const [key, value] of Object.entries(req.headers)) {
                    if (value) {
                        headers[key] = Array.isArray(value) ? value.join(', ') : (value as string);
                    }
                }

                telemetry.recordHttpInteraction(
                    req.method || 'GET',
                    req.url || '/',
                    headers,
                    statusCode,
                    body,
                    durationMs
                );
            }
        });
    });
}

/**
 * Removes server hooks
 */
export function removeServerHooks(): void {
    if (!hooksInstalled) return;

    if (originalCreateServer) {
        (http as any).createServer = originalCreateServer;
    }
    if (originalHttpsCreateServer) {
        (https as any).createServer = originalHttpsCreateServer;
    }

    hooksInstalled = false;
}
