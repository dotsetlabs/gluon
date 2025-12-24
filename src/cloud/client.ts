/**
 * Gluon Cloud Client
 *
 * API client for communicating with Gluon Cloud.
 * Handles telemetry sync, project management, and alerts.
 *
 * Note: This is a stub for future implementation.
 */

import { getAccessToken } from './auth.js';
import type {
    DeviceCodeResponse,
    DevicePollResponse,
    User,
    ApiError,
    RefreshResponse
} from './types.js';

/** Default API URL */
const DEFAULT_API_URL = 'https://api.dotsetlabs.com';

/**
 * Get headers with optional beta password for private beta access.
 * Set DOTSET_BETA_PASSWORD env var to authenticate against beta API.
 */
function getBaseHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
    };

    const betaPassword = process.env.DOTSET_BETA_PASSWORD;
    if (betaPassword) {
        headers['X-Beta-Password'] = betaPassword;
    }

    return headers;
}

/**
 * Gluon Cloud API client
 */
export class GluonCloudClient {
    private apiUrl: string;

    constructor(apiUrl: string = DEFAULT_API_URL) {
        this.apiUrl = apiUrl;
    }

    /**
     * Internal request handler with soft error support
     */
    private async _request<T>(
        method: string,
        path: string,
        body?: unknown,
        options: { softError?: boolean } = {}
    ): Promise<T | null> {
        try {
            const accessToken = await getAccessToken();

            const response = await fetch(`${this.apiUrl}${path}`, {
                method,
                headers: {
                    ...getBaseHeaders(),
                    'Authorization': `Bearer ${accessToken}`,
                },
                body: body ? JSON.stringify(body) : undefined,
            });

            if (!response.ok) {
                const error = await response.json().catch(() => ({ message: 'Request failed' })) as ApiError & { code?: string };
                if (response.status === 401 && error.code === 'BETA_ACCESS_REQUIRED') {
                    if (options.softError) return null;
                    throw new Error('Beta access required. Set DOTSET_BETA_PASSWORD environment variable.');
                }
                if (options.softError) return null;
                throw new Error(error.message || `API error: ${response.status}`);
            }

            return response.json() as Promise<T>;
        } catch (err) {
            if (options.softError) return null;
            throw err;
        }
    }

    /**
     * Standard request handler (throws on error)
     */
    private async request<T>(
        method: string,
        path: string,
        body?: unknown
    ): Promise<T> {
        const result = await this._request<T>(method, path, body);
        return result!;
    }

    /**
     * Makes an unauthenticated API request (for login)
     */
    private async publicRequest<T>(
        method: string,
        path: string,
        body?: unknown
    ): Promise<T> {
        const response = await fetch(`${this.apiUrl}${path}`, {
            method,
            headers: getBaseHeaders(),
            body: body ? JSON.stringify(body) : undefined,
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({ message: 'Request failed' })) as ApiError;
            throw new Error(error.message || `API error: ${response.status}`);
        }

        return response.json() as Promise<T>;
    }

    /**
     * Starts the device authentication flow
     */
    async getDeviceCode(): Promise<DeviceCodeResponse> {
        return this.publicRequest('POST', '/auth/device');
    }

    /**
     * Polls for the device token
     */
    async pollDeviceToken(deviceCode: string): Promise<DevicePollResponse> {
        return this.publicRequest('POST', '/auth/device/poll', { deviceCode });
    }

    /**
     * Refreshes tokens
     */
    async refreshTokens(refreshToken: string): Promise<RefreshResponse> {
        return this.publicRequest('POST', '/auth/refresh', { refreshToken });
    }

    /**
     * Gets current user info
     */
    async getWhoami(): Promise<User> {
        return this.request('GET', '/auth/me');
    }

    /**
     * Creates a new project (with Gluon enabled)
     */
    async createProject(name: string): Promise<{ id: string; name: string }> {
        return this.request('POST', '/projects', { name, gluonEnabled: true });
    }

    /**
     * Gets project details
     */
    async getProject(projectId: string): Promise<{ id: string; name: string }> {
        return this.request('GET', `/projects/${projectId}`);
    }

    /**
     * Lists user's Gluon-enabled projects
     */
    async listProjects(): Promise<Array<{ id: string; name: string }>> {
        return this.request('GET', '/projects?filter=gluon');
    }

    /**
     * Syncs telemetry events to cloud
     */
    async syncTelemetry(
        projectId: string,
        events: unknown[],
        options: { softError?: boolean } = {}
    ): Promise<{ synced: number } | null> {
        return this._request<{ synced: number }>('POST', `/projects/${projectId}/gluon/telemetry`, {
            events,
        }, options);
    }

    /**
     * Gets alerts for a project
     */
    async getAlerts(projectId: string): Promise<unknown[]> {
        return this.request('GET', `/projects/${projectId}/gluon/alerts`);
    }

    /**
     * Acknowledges an alert
     */
    async acknowledgeAlert(projectId: string, alertId: string): Promise<void> {
        return this.request('POST', `/projects/${projectId}/gluon/alerts/${alertId}/ack`);
    }

    /**
     * Links to an Axion project (deprecated - use unified projects)
     */
    async linkAxionProject(gluonProjectId: string, axionProjectId: string): Promise<void> {
        return this.request('POST', `/projects/${gluonProjectId}/gluon/link-axion`, { axionProjectId });
    }
}

/**
 * Global client instance
 */
export const cloudClient = new GluonCloudClient(
    process.env.GLUON_API_URL ?? DEFAULT_API_URL
);
