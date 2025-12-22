/**
 * Gluon Network Hooks
 *
 * Patches Node.js's http, https, and net modules to intercept all outbound
 * network connections. This enables runtime monitoring of:
 * - HTTP/HTTPS requests
 * - Raw TCP connections
 * - TLS connections
 *
 * Implementation Strategy:
 * Uses module hooking to wrap the native request methods. This approach
 * is non-invasive and doesn't require any changes to application code.
 *
 * @module monitors/network-hooks
 */

import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import { URL } from 'node:url';
import { type NetworkMonitor, parseUrl } from './network.js';

/** Original references to Node.js methods */
interface OriginalMethods {
    httpRequest: typeof http.request;
    httpGet: typeof http.get;
    httpsRequest: typeof https.request;
    httpsGet: typeof https.get;
    netConnect: typeof net.connect;
    netCreateConnection: typeof net.createConnection;
}

/** Whether hooks have been installed */
let hooksInstalled = false;

/** Original method references for cleanup */
let originalMethods: OriginalMethods | null = null;

/** Registered network monitors */
const monitors = new Set<NetworkMonitor>();

/**
 * Extracts host, port, and protocol from http/https request options
 */
function extractRequestInfo(
    urlOrOptions: string | URL | http.RequestOptions,
    options?: http.RequestOptions,
    protocol: 'http' | 'https' = 'http'
): { host: string; port: number; protocol: string; path: string } | null {
    try {
        let host: string | undefined;
        let port: number | undefined;
        let path: string = '/';

        if (typeof urlOrOptions === 'string') {
            const parsed = parseUrl(urlOrOptions);
            if (parsed) {
                host = parsed.host;
                port = parsed.port;
            }
            try {
                const url = new URL(urlOrOptions);
                path = url.pathname + url.search;
            } catch {
                // Not a full URL
            }
        } else if (urlOrOptions instanceof URL) {
            host = urlOrOptions.hostname;
            port = urlOrOptions.port
                ? parseInt(urlOrOptions.port, 10)
                : protocol === 'https' ? 443 : 80;
            path = urlOrOptions.pathname + urlOrOptions.search;
        } else {
            // It's RequestOptions
            host = urlOrOptions.hostname ?? urlOrOptions.host?.split(':')[0];
            port = urlOrOptions.port
                ? (typeof urlOrOptions.port === 'string' ? parseInt(urlOrOptions.port, 10) : urlOrOptions.port)
                : protocol === 'https' ? 443 : 80;
            path = urlOrOptions.path ?? '/';
        }

        // Apply overrides from options parameter
        if (options) {
            if (options.hostname || options.host) {
                host = options.hostname ?? options.host?.split(':')[0];
            }
            if (options.port) {
                port = typeof options.port === 'string' ? parseInt(options.port, 10) : options.port;
            }
            if (options.path) {
                path = options.path;
            }
        }

        if (!host) return null;

        return {
            host,
            port: port ?? (protocol === 'https' ? 443 : 80),
            protocol,
            path,
        };
    } catch {
        return null;
    }
}

/**
 * Notifies all registered monitors of a connection
 */
function notifyMonitors(host: string, port: number, protocol: string): void {
    for (const monitor of monitors) {
        try {
            monitor.recordConnection(host, port, protocol);
        } catch (err) {
            // Don't let monitor errors affect the application
            console.error('[Gluon] Monitor error:', err);
        }
    }
}

/**
 * Creates a wrapped version of http.request/https.request
 */
function createRequestWrapper(
    original: typeof http.request,
    protocol: 'http' | 'https'
): typeof http.request {
    // Use function declaration to preserve `this` binding
    const wrapped = function (
        this: unknown,
        urlOrOptions: string | URL | http.RequestOptions,
        optionsOrCallback?: http.RequestOptions | ((res: http.IncomingMessage) => void),
        callback?: (res: http.IncomingMessage) => void
    ): http.ClientRequest {
        // Parse the arguments
        let options: http.RequestOptions | undefined;
        let cb: ((res: http.IncomingMessage) => void) | undefined;

        if (typeof optionsOrCallback === 'function') {
            cb = optionsOrCallback;
        } else {
            options = optionsOrCallback;
            cb = callback;
        }

        // Extract connection info
        const info = extractRequestInfo(urlOrOptions, options, protocol);
        if (info) {
            notifyMonitors(info.host, info.port, info.protocol);
        }

        // Call original - use apply for proper this binding
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return (original as any).apply(this, arguments);
    };

    return wrapped as typeof http.request;
}

/**
 * Creates a wrapped version of http.get/https.get
 */
function createGetWrapper(
    original: typeof http.get,
    protocol: 'http' | 'https'
): typeof http.get {
    const wrapped = function (
        this: unknown,
        urlOrOptions: string | URL | http.RequestOptions,
        optionsOrCallback?: http.RequestOptions | ((res: http.IncomingMessage) => void),
        callback?: (res: http.IncomingMessage) => void
    ): http.ClientRequest {
        // Parse the arguments
        let options: http.RequestOptions | undefined;
        let cb: ((res: http.IncomingMessage) => void) | undefined;

        if (typeof optionsOrCallback === 'function') {
            cb = optionsOrCallback;
        } else {
            options = optionsOrCallback;
            cb = callback;
        }

        // Extract connection info
        const info = extractRequestInfo(urlOrOptions, options, protocol);
        if (info) {
            notifyMonitors(info.host, info.port, info.protocol);
        }

        // Call original - use apply for proper this binding
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return (original as any).apply(this, arguments);
    };

    return wrapped as typeof http.get;
}

/**
 * Creates a wrapped version of net.connect/net.createConnection
 */
function createNetConnectWrapper(
    original: typeof net.connect
): typeof net.connect {
    const wrapped = function (this: unknown, ...args: unknown[]): net.Socket {
        // Parse connection options
        let host: string | undefined;
        let port: number | undefined;

        const firstArg = args[0];
        if (typeof firstArg === 'number') {
            // net.connect(port, host?, callback?)
            port = firstArg;
            host = typeof args[1] === 'string' ? args[1] : 'localhost';
        } else if (typeof firstArg === 'string') {
            // net.connect(path) - Unix socket, skip
        } else if (typeof firstArg === 'object' && firstArg !== null) {
            // net.connect(options, callback?)
            const opts = firstArg as net.NetConnectOpts;
            if ('port' in opts) {
                port = opts.port;
                host = opts.host ?? 'localhost';
            }
        }

        if (host && port) {
            notifyMonitors(host, port, 'tcp');
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return (original as any).apply(this, args);
    };

    return wrapped as typeof net.connect;
}

/**
 * Installs network interception hooks
 *
 * This patches Node.js's http, https, and net modules to intercept
 * all outbound connections. Safe to call multiple times.
 *
 * @param monitor - NetworkMonitor instance to receive connection events
 */
export function installNetworkHooks(monitor: NetworkMonitor): void {
    // Register the monitor
    monitors.add(monitor);

    // Only install hooks once
    if (hooksInstalled) {
        return;
    }

    // Store original methods
    originalMethods = {
        httpRequest: http.request,
        httpGet: http.get,
        httpsRequest: https.request,
        httpsGet: https.get,
        netConnect: net.connect,
        netCreateConnection: net.createConnection,
    };

    // Install HTTP hooks
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (http as any).request = createRequestWrapper(originalMethods.httpRequest, 'http');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (http as any).get = createGetWrapper(originalMethods.httpGet, 'http');

    // Install HTTPS hooks
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (https as any).request = createRequestWrapper(originalMethods.httpsRequest, 'https');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (https as any).get = createGetWrapper(originalMethods.httpsGet, 'https');

    // Install net hooks
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (net as any).connect = createNetConnectWrapper(originalMethods.netConnect);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (net as any).createConnection = createNetConnectWrapper(originalMethods.netCreateConnection);

    hooksInstalled = true;
}

/**
 * Removes network interception hooks and restores original methods
 */
export function removeNetworkHooks(): void {
    if (!hooksInstalled || !originalMethods) {
        return;
    }

    // Restore original methods
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (http as any).request = originalMethods.httpRequest;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (http as any).get = originalMethods.httpGet;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (https as any).request = originalMethods.httpsRequest;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (https as any).get = originalMethods.httpsGet;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (net as any).connect = originalMethods.netConnect;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (net as any).createConnection = originalMethods.netCreateConnection;

    // Clear state
    monitors.clear();
    originalMethods = null;
    hooksInstalled = false;
}

/**
 * Removes a specific monitor from receiving events
 */
export function unregisterMonitor(monitor: NetworkMonitor): void {
    monitors.delete(monitor);
}

/**
 * Checks if hooks are currently installed
 */
export function areHooksInstalled(): boolean {
    return hooksInstalled;
}

/**
 * Gets the number of registered monitors
 */
export function getMonitorCount(): number {
    return monitors.size;
}
