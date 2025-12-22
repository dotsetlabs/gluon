/**
 * Gluon Cloud Authentication
 *
 * Handles authentication with Gluon Cloud for syncing telemetry and alerts.
 * Follows same patterns as Axion for shared SSO experience.
 *
 * Note: This is a stub for future implementation.
 */

import { readFile, writeFile, mkdir, access, constants } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { CONFIG_DIR } from '../core/config.js';

/** Credentials storage filename */
const CREDENTIALS_FILE = 'credentials.json';

/**
 * Stored credentials
 */
export interface GluonCredentials {
    /** Access token */
    accessToken: string;
    /** Refresh token */
    refreshToken?: string;
    /** Token expiry timestamp */
    expiresAt: string;
    /** User email */
    email: string;
    /** User ID */
    userId: string;
}

/**
 * Cloud configuration stored per project
 */
export interface CloudConfig {
    /** Linked project ID */
    projectId: string;
    /** API URL */
    apiUrl: string;
    /** When project was linked */
    linkedAt: string;
}

/**
 * Gets the credentials file path
 */
function getCredentialsPath(): string {
    // Store in user home directory for global access
    const homeDir = process.env.HOME ?? process.env.USERPROFILE ?? '.';
    return join(homeDir, '.gluon', CREDENTIALS_FILE);
}

/**
 * Gets the cloud config path for a project
 */
function getCloudConfigPath(workDir: string): string {
    return join(workDir, CONFIG_DIR, 'cloud.json');
}

/**
 * Checks if the user is authenticated
 */
export async function isAuthenticated(): Promise<boolean> {
    try {
        const credentials = await loadCredentials();
        if (!credentials) return false;

        // Check if token is expired
        const expiresAt = new Date(credentials.expiresAt);
        return expiresAt > new Date();
    } catch {
        return false;
    }
}

/**
 * Loads stored credentials
 */
export async function loadCredentials(): Promise<GluonCredentials | null> {
    try {
        const content = await readFile(getCredentialsPath(), 'utf8');
        return JSON.parse(content) as GluonCredentials;
    } catch {
        return null;
    }
}

/**
 * Refreshes the access token using the stored refresh token
 */
async function refreshAccessToken(refreshToken: string): Promise<GluonCredentials> {
    const { cloudClient } = await import('./client.js');
    const response = await cloudClient.refreshTokens(refreshToken);

    const credentials = await loadCredentials();
    if (!credentials) throw new Error('Failed to load credentials during refresh');

    const updated: GluonCredentials = {
        ...credentials,
        accessToken: response.accessToken,
        refreshToken: response.refreshToken,
        expiresAt: new Date(response.expiresAt * 1000).toISOString(),
    };

    await saveCredentials(updated);
    return updated;
}

/**
 * Gets a valid access token, refreshing if necessary
 */
export async function getAccessToken(): Promise<string> {
    const credentials = await loadCredentials();
    if (!credentials) {
        throw new Error('Not authenticated. Run "gluon login" first.');
    }

    const expiresAt = new Date(credentials.expiresAt);
    const now = new Date();

    // Refresh if expired or expiring in the next 5 minutes
    if (expiresAt.getTime() - now.getTime() < 5 * 60 * 1000) {
        if (!credentials.refreshToken) {
            throw new Error('Session expired and no refresh token available. Please login again.');
        }

        try {
            const updated = await refreshAccessToken(credentials.refreshToken);
            return updated.accessToken;
        } catch (err) {
            throw new Error(`Session expired and refresh failed: ${(err as Error).message}`);
        }
    }

    return credentials.accessToken;
}

/**
 * Saves credentials securely with restricted file permissions
 */
export async function saveCredentials(credentials: GluonCredentials): Promise<void> {
    const credPath = getCredentialsPath();
    await mkdir(dirname(credPath), { recursive: true, mode: 0o700 });
    await writeFile(credPath, JSON.stringify(credentials, null, 2), {
        encoding: 'utf8',
        mode: 0o600, // Owner read/write only - matches Axion pattern
    });
}

/**
 * Clears stored credentials
 */
export async function clearCredentials(): Promise<void> {
    try {
        const { unlink } = await import('node:fs/promises');
        await unlink(getCredentialsPath());
    } catch {
        // Ignore if file doesn't exist
    }
}

/**
 * Gets the current user info
 */
export async function getCurrentUser(): Promise<{ email: string; userId: string } | null> {
    const credentials = await loadCredentials();
    if (!credentials) return null;

    return {
        email: credentials.email,
        userId: credentials.userId,
    };
}

/**
 * Checks if a project is linked to cloud
 */
export async function isCloudLinked(workDir: string = process.cwd()): Promise<boolean> {
    try {
        await access(getCloudConfigPath(workDir), constants.F_OK);
        return true;
    } catch {
        return false;
    }
}

/**
 * Loads cloud config for a project
 */
export async function loadCloudConfig(workDir: string = process.cwd()): Promise<CloudConfig | null> {
    try {
        const content = await readFile(getCloudConfigPath(workDir), 'utf8');
        return JSON.parse(content) as CloudConfig;
    } catch {
        return null;
    }
}

/**
 * Saves cloud config for a project
 */
export async function saveCloudConfig(workDir: string, config: CloudConfig): Promise<void> {
    const configPath = getCloudConfigPath(workDir);
    await mkdir(dirname(configPath), { recursive: true });
    await writeFile(configPath, JSON.stringify(config, null, 2), 'utf8');
}

/**
 * Unlinks a project from cloud
 */
export async function unlinkCloud(workDir: string = process.cwd()): Promise<void> {
    try {
        const { unlink } = await import('node:fs/promises');
        await unlink(getCloudConfigPath(workDir));
    } catch {
        // Ignore if file doesn't exist
    }
}
