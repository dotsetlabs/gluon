/**
 * Gluon Axion Integration Module
 *
 * Deep integration with @dotsetlabs/axion when present in a project.
 * Enables enhanced secret detection by tracking actual ENV values from Axion.
 *
 * Features:
 * - Auto-detect Axion projects (.axion directory)
 * - Track runtime process.env values when Axion injects them
 * - Provide rich alerts with Axion project context
 * - Cross-link Gluon and Axion projects in cloud
 */

import { readFile, access, constants } from 'node:fs/promises';
import { join } from 'node:path';
import { type GluonConfig, type AxionIntegration } from '../core/config.js';

/** Axion configuration directory */
const AXION_CONFIG_DIR = '.axion';

/** Axion cloud config filename */
const AXION_CLOUD_CONFIG = 'cloud.json';

/** Axion manifest filename */
const AXION_MANIFEST = '.axion.env';

/** Axion session ID env var (set by axn run) */
const AXION_SESSION_ENV = 'AXION_SESSION_ID';

/**
 * Axion project info when detected
 */
export interface AxionProjectInfo {
    /** Whether Axion is detected */
    detected: boolean;
    /** Path to Axion config directory */
    configPath?: string;
    /** Axion project ID if linked to cloud */
    projectId?: string;
    /** Project name if available */
    projectName?: string;
    /** Whether the project is linked to Axion Cloud */
    isCloudLinked: boolean;
    /** Whether currently running under axn run */
    isAxionSession: boolean;
    /** Axion session ID if running under axn run */
    sessionId?: string;
}

/**
 * Axion cloud config structure
 */
interface AxionCloudConfig {
    projectId: string;
    apiUrl: string;
    linkedAt: string;
}

/**
 * Detects if Axion is present in the project
 *
 * @param workDir - Working directory to check
 * @returns Whether Axion is detected
 */
export async function detectAxion(workDir: string = process.cwd()): Promise<boolean> {
    const axionPath = join(workDir, AXION_CONFIG_DIR);
    try {
        await access(axionPath, constants.F_OK);
        return true;
    } catch {
        return false;
    }
}

/**
 * Checks if currently running under axn run
 */
export function isAxionSession(): boolean {
    return !!process.env[AXION_SESSION_ENV];
}

/**
 * Gets the Axion session ID if running under axn run
 */
export function getAxionSessionId(): string | undefined {
    return process.env[AXION_SESSION_ENV];
}

/**
 * Gets detailed Axion project information
 *
 * @param workDir - Working directory to check
 * @returns Axion project info
 */
export async function getAxionInfo(workDir: string = process.cwd()): Promise<AxionProjectInfo> {
    const axionPath = join(workDir, AXION_CONFIG_DIR);
    const detected = await detectAxion(workDir);

    if (!detected) {
        return {
            detected: false,
            isCloudLinked: false,
            isAxionSession: isAxionSession(),
            sessionId: getAxionSessionId(),
        };
    }

    // Check for cloud config
    let projectId: string | undefined;
    let isCloudLinked = false;

    try {
        const cloudConfigPath = join(axionPath, AXION_CLOUD_CONFIG);
        const content = await readFile(cloudConfigPath, 'utf8');
        const cloudConfig = JSON.parse(content) as AxionCloudConfig;
        projectId = cloudConfig.projectId;
        isCloudLinked = true;
    } catch {
        // No cloud config
    }

    return {
        detected: true,
        configPath: axionPath,
        projectId,
        isCloudLinked,
        isAxionSession: isAxionSession(),
        sessionId: getAxionSessionId(),
    };
}

/**
 * Gets all current ENV variables that might be Axion-managed secrets
 * Uses pattern matching and value inspection
 *
 * @returns Map of ENV variable names to their redacted lengths
 */
export function detectPotentialSecrets(): Map<string, { name: string; length: number; pattern: string }> {
    const secretPatterns: { pattern: RegExp; description: string }[] = [
        { pattern: /^.*_KEY$/i, description: 'API Key' },
        { pattern: /^.*_SECRET$/i, description: 'Secret' },
        { pattern: /^.*_TOKEN$/i, description: 'Token' },
        { pattern: /^.*_PASSWORD$/i, description: 'Password' },
        { pattern: /^.*_API_KEY$/i, description: 'API Key' },
        { pattern: /^.*_AUTH$/i, description: 'Auth' },
        { pattern: /^.*_CREDENTIAL/i, description: 'Credential' },
        { pattern: /^DATABASE_URL$/i, description: 'Database URL' },
        { pattern: /^REDIS_URL$/i, description: 'Redis URL' },
        { pattern: /^MONGODB_URI$/i, description: 'MongoDB URI' },
        { pattern: /^POSTGRES.*/i, description: 'Postgres' },
        { pattern: /^MYSQL.*/i, description: 'MySQL' },
        { pattern: /^STRIPE_/i, description: 'Stripe' },
        { pattern: /^AWS_/i, description: 'AWS' },
        { pattern: /^GITHUB_/i, description: 'GitHub' },
        { pattern: /^GOOGLE_/i, description: 'Google' },
        { pattern: /^OPENAI_/i, description: 'OpenAI' },
        { pattern: /^ANTHROPIC_/i, description: 'Anthropic' },
        { pattern: /^SENDGRID_/i, description: 'SendGrid' },
        { pattern: /^TWILIO_/i, description: 'Twilio' },
    ];

    const potentialSecrets = new Map<string, { name: string; length: number; pattern: string }>();

    for (const [key, value] of Object.entries(process.env)) {
        if (!value) continue;

        // Check if the name matches secret patterns
        for (const { pattern, description } of secretPatterns) {
            if (pattern.test(key)) {
                // Only include if value is long enough to be a secret (8+ chars)
                if (value.length >= 8) {
                    potentialSecrets.set(key, {
                        name: key,
                        length: value.length,
                        pattern: description,
                    });
                    break;
                }
            }
        }
    }

    return potentialSecrets;
}

/**
 * Gets the actual secret values for monitoring
 * Returns a map of variable names to their values (for pattern matching during monitoring)
 * 
 * WARNING: This returns actual secret values - use only for in-memory pattern matching
 */
export function getSecretValuesForMonitoring(): Map<string, string> {
    const secrets = detectPotentialSecrets();
    const values = new Map<string, string>();

    for (const { name } of secrets.values()) {
        const value = process.env[name];
        if (value && value.length >= 8) {
            values.set(name, value);
        }
    }

    return values;
}

/**
 * Updates Gluon config with Axion detection results
 *
 * @param config - Current Gluon config
 * @param workDir - Working directory
 * @returns Updated config with Axion integration info
 */
export async function updateAxionIntegration(
    config: GluonConfig,
    workDir: string = process.cwd()
): Promise<GluonConfig> {
    const info = await getAxionInfo(workDir);

    const axion: AxionIntegration = {
        enabled: config.axion.enabled && info.detected,
        detected: info.detected,
        configPath: info.configPath,
        projectId: info.projectId,
    };

    // If Axion is detected and enabled, auto-populate tracked env vars
    if (axion.enabled && axion.detected) {
        const secrets = detectPotentialSecrets();
        const secretNames = [...secrets.keys()];

        // Merge with existing tracked vars (don't overwrite user config)
        const trackedSet = new Set([
            ...config.secrets.trackedEnvVars,
            ...secretNames,
        ]);

        return {
            ...config,
            axion,
            secrets: {
                ...config.secrets,
                trackedEnvVars: [...trackedSet],
            },
        };
    }

    return {
        ...config,
        axion,
    };
}

/**
 * Gets the secrets to track based on Axion integration
 * If Axion is integrated, auto-detect potential secrets from ENV
 *
 * @param config - Gluon configuration
 * @returns Array of ENV variable names to track
 */
export function getSecretsToTrack(config: GluonConfig): string[] {
    // Start with user-configured secrets
    const secrets = new Set(config.secrets.trackedEnvVars);

    // If Axion integration is enabled, add auto-detected secrets
    if (config.axion.enabled && config.axion.detected) {
        const autoDetected = detectPotentialSecrets();
        for (const name of autoDetected.keys()) {
            secrets.add(name);
        }
    }

    return [...secrets];
}

/**
 * Formats an alert message with Axion context if available
 *
 * @param baseMessage - The base alert message
 * @param config - Gluon configuration
 * @param envVarName - Optional ENV variable name for context
 * @returns Formatted message with Axion context
 */
export function formatAlertWithAxionContext(
    baseMessage: string,
    config: GluonConfig,
    envVarName?: string
): string {
    if (!config.axion.detected) {
        return baseMessage;
    }

    let context = baseMessage;

    if (config.axion.projectId) {
        context += `\n   Axion Project: ${config.axion.projectId}`;
    }

    if (envVarName) {
        const secrets = detectPotentialSecrets();
        const secretInfo = secrets.get(envVarName);
        if (secretInfo) {
            context += `\n   Secret Type: ${secretInfo.pattern} (${secretInfo.length} chars)`;
        }
        context += `\n   This secret may be managed by Axion. Check your .axion.env manifest.`;
    }

    return context;
}

/**
 * Redacts a value if it matches any known secrets
 * Used to sanitize output before logging
 */
export function redactSecrets(text: string, secrets: Map<string, string>): string {
    let redacted = text;
    for (const [name, value] of secrets) {
        if (value.length >= 8 && redacted.includes(value)) {
            // Redact with [REDACTED:VAR_NAME]
            redacted = redacted.replaceAll(value, `[REDACTED:${name}]`);
        }
    }
    return redacted;
}
