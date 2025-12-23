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
     * Makes an authenticated API request
     */
    private async request<T>(
        method: string,
        path: string,
        body?: unknown
    ): Promise<T> {
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
                throw new Error('Beta access required. Set DOTSET_BETA_PASSWORD environment variable.');
            }
            throw new Error(error.message || `API error: ${response.status}`);
        }

        return response.json() as Promise<T>;
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
     * Creates a new project
     */
    async createProject(name: string, axionProjectId?: string): Promise<{ id: string; name: string }> {
        return this.request('POST', '/gluon/projects', { name, axionProjectId });
    }

    /**
     * Gets project details
     */
    async getProject(projectId: string): Promise<{ id: string; name: string }> {
        return this.request('GET', `/gluon/projects/${projectId}`);
    }

    /**
     * Lists user's projects
     */
    async listProjects(): Promise<Array<{ id: string; name: string }>> {
        return this.request('GET', '/gluon/projects');
    }

    /**
     * Syncs telemetry events to cloud
     */
    async syncTelemetry(
        projectId: string,
        events: unknown[]
    ): Promise<{ synced: number }> {
        return this.request('POST', `/gluon/projects/${projectId}/telemetry`, {
            events,
        });
    }

    /**
     * Gets alerts for a project
     */
    async getAlerts(projectId: string): Promise<unknown[]> {
        return this.request('GET', `/gluon/projects/${projectId}/alerts`);
    }

    /**
     * Acknowledges an alert
     */
    async acknowledgeAlert(projectId: string, alertId: string): Promise<void> {
        return this.request('POST', `/gluon/projects/${projectId}/alerts/${alertId}/ack`);
    }

    /**
     * Links to an Axion project
     */
    async linkAxionProject(gluonProjectId: string, axionProjectId: string): Promise<void> {
        return this.request('POST', `/gluon/projects/${gluonProjectId}/link-axion`, { axionProjectId });
    }
}

/**
 * Global client instance
 */
export const cloudClient = new GluonCloudClient(
    process.env.GLUON_API_URL ?? DEFAULT_API_URL
);
