/**
 * Gluon Configuration Module
 *
 * Handles loading and managing project configuration from .gluon/config.yaml.
 * Configuration defines monitoring rules, alert thresholds, and integration settings.
 *
 * Default Configuration:
 * - Secret patterns: Common API key formats, passwords, tokens
 * - Network monitoring: All outbound connections
 * - Module tracking: All require/import statements
 */

import { readFile, writeFile, mkdir, access, constants } from 'node:fs/promises';
import { join } from 'node:path';
import yaml from 'yaml';

/** Configuration directory name */
export const CONFIG_DIR = '.dotset/gluon';

/** Configuration filename */
export const CONFIG_FILENAME = 'config.yaml';

/** Default secret patterns to detect */
const DEFAULT_SECRET_PATTERNS = [
    // API Keys
    /sk[-_]live[-_][a-zA-Z0-9]{24,}/gi,          // Stripe secret key
    /sk[-_]test[-_][a-zA-Z0-9]{24,}/gi,          // Stripe test key
    /AIza[0-9A-Za-z-_]{35}/gi,                   // Google API key
    /ghp_[a-zA-Z0-9]{36}/gi,                     // GitHub personal token
    /gho_[a-zA-Z0-9]{36}/gi,                     // GitHub OAuth token
    /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/gi, // GitHub fine-grained PAT

    // AWS
    /AKIA[0-9A-Z]{16}/gi,                        // AWS Access Key ID
    /[a-zA-Z0-9/+]{40}/gi,                       // AWS Secret Access Key (loose)

    // Common patterns
    /['"][a-zA-Z0-9_-]*(?:api[-_]?key|secret|password|token|auth)['"]?\s*[:=]\s*['"][^'"]{8,}['"]/gi,

    // Bearer tokens in headers
    /Bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/gi, // JWT
    /Bearer\s+[a-zA-Z0-9]{20,}/gi,               // Generic bearer
];

/**
 * Secret protection mode
 * - detect: Log exposure but allow output (default)
 * - redact: Replace secrets with redaction text
 * - block: Suppress output containing secrets entirely
 */
export type SecretMode = 'detect' | 'redact' | 'block';

/**
 * Secret pattern configuration
 */
export interface SecretPattern {
    /** Pattern name for identification */
    name: string;
    /** Regex pattern to match */
    pattern: string;
    /** Severity level */
    severity: 'low' | 'medium' | 'high' | 'critical';
    /** Whether this pattern is enabled */
    enabled: boolean;
}

/**
 * Network monitoring configuration
 */
export interface NetworkConfig {
    /** Whether network monitoring is enabled */
    enabled: boolean;
    /** Domains to ignore (e.g., localhost, internal services) */
    ignoredDomains: string[];
    /** Alert on connections to new domains */
    alertOnNewDomains: boolean;
}

/**
 * Module tracking configuration
 */
export interface ModuleConfig {
    /** Whether module tracking is enabled */
    enabled: boolean;
    /** Patterns to ignore (e.g., node_modules internals) */
    ignoredPatterns: string[];
    /** Generate runtime SBOM */
    generateSbom: boolean;
}

/**
 * Telemetry configuration
 */
export interface TelemetryConfig {
    /** Whether telemetry collection is enabled */
    enabled: boolean;
    /** Local storage file path */
    storagePath: string;
    /** Maximum events to buffer before flush */
    bufferSize: number;
    /** Flush interval in milliseconds */
    flushIntervalMs: number;
}

/**
 * Lagrangian (Crash Replay) configuration
 */
export interface LagrangianConfig {
    /** Whether crash replay capture is enabled */
    enabled: boolean;
    /** Whether to capture request bodies (can track sensitive data) */
    captureBodies: boolean;
    /** Headers to ignore (redact) */
    ignoredHeaders: string[];
    /** URL paths to ignore completely */
    ignoredPaths: string[];
}

/**
 * Subscription tier type
 */
export type SubscriptionTier = 'free' | 'pro' | 'business';

/**
 * Tier pricing information
 */
export interface TierPricing {
    /** Monthly price in USD */
    monthlyPrice: number;
    /** Annual price in USD */
    annualPrice: number;
}

/**
 * Tier limits configuration
 */
export interface TierLimits {
    /** Maximum number of projects */
    maxProjects: number;
    /** Telemetry retention in days */
    retentionDays: number;
    /** Whether custom patterns are allowed */
    customPatternsAllowed: boolean;
    /** Whether SBOM export is allowed */
    sbomExportAllowed: boolean;
    /** Whether cloud sync is available */
    cloudSyncAllowed: boolean;
    /** Whether webhook alerts are available */
    webhooksAllowed: boolean;
}

/**
 * Tier pricing by plan
 */
export const TIER_PRICING: Record<SubscriptionTier, TierPricing> = {
    free: { monthlyPrice: 0, annualPrice: 0 },
    pro: { monthlyPrice: 10, annualPrice: 95 },
    business: { monthlyPrice: 25, annualPrice: 240 },
};

/**
 * Tier limits by plan
 * 
 * Gluon Pricing Strategy (2025):
 * - Free: Generous to drive adoption (3 projects, 14-day retention)
 * - Pro ($10/mo): Individual developers, unlimited projects, 30-day retention
 * - Business ($25/mo): Growing apps, 90-day retention, SBOM, webhooks
 */
export const TIER_LIMITS: Record<SubscriptionTier, TierLimits> = {
    free: {
        maxProjects: 3,
        retentionDays: 14,
        customPatternsAllowed: false,
        sbomExportAllowed: false,
        cloudSyncAllowed: false,
        webhooksAllowed: false,
    },
    pro: {
        maxProjects: Infinity,
        retentionDays: 30,
        customPatternsAllowed: true,
        sbomExportAllowed: false,
        cloudSyncAllowed: true,
        webhooksAllowed: false,
    },
    business: {
        maxProjects: Infinity,
        retentionDays: 90,
        customPatternsAllowed: true,
        sbomExportAllowed: true,
        cloudSyncAllowed: true,
        webhooksAllowed: true,
    },
};

/**
 * Complete Gluon project configuration
 */
export interface GluonConfig {
    /** Configuration version for migrations */
    version: string;
    /** Project name */
    projectName: string;
    /** Current subscription tier */
    tier: SubscriptionTier;
    /** Secret detection and prevention settings */
    secrets: {
        /** Whether secret monitoring is enabled */
        enabled: boolean;
        /** Protection mode: detect, redact, or block */
        mode: SecretMode;
        /** Text to replace secrets with in redact mode */
        redactText: string;
        /** Whether to show alerts even in redact/block modes */
        alertOnExposure: boolean;
        /** Custom patterns to detect */
        customPatterns: SecretPattern[];
        /** Environment variable names to track (values are sensitive) */
        trackedEnvVars: string[];
    };
    /** Network monitoring settings */
    network: NetworkConfig;
    /** Module tracking settings */
    modules: ModuleConfig;
    /** Telemetry settings */
    telemetry: TelemetryConfig;
    /** Cloud integration settings */
    cloud: {
        enabled: boolean;
        apiUrl: string;
        projectId?: string;
    };
    /** Lagrangian settings */
    lagrangian: LagrangianConfig;
}

/**
 * Creates a default configuration object
 */
export function createDefaultConfig(projectName?: string): GluonConfig {
    return {
        version: '1',
        projectName: projectName ?? 'gluon-project',
        tier: 'free',
        secrets: {
            enabled: true,
            mode: 'detect',
            redactText: '[REDACTED]',
            alertOnExposure: true,
            customPatterns: [],
            trackedEnvVars: [],
        },
        network: {
            enabled: true,
            ignoredDomains: ['localhost', '127.0.0.1', '::1'],
            alertOnNewDomains: true,
        },
        modules: {
            enabled: true,
            ignoredPatterns: ['node:*', 'node_modules/.pnpm/*'],
            generateSbom: true,
        },
        telemetry: {
            enabled: true,
            storagePath: '.dotset/gluon/telemetry.log',
            bufferSize: 100,
            flushIntervalMs: 5000,
        },
        cloud: {
            enabled: false,
            apiUrl: 'https://api.dotsetlabs.com',
        },
        lagrangian: {
            enabled: true,
            captureBodies: true,
            ignoredHeaders: ['authorization', 'cookie', 'set-cookie', 'x-api-key'],
            ignoredPaths: [],
        },
    };
}

/**
 * Gets the current tier limits based on configuration
 */
export function getTierLimits(config: GluonConfig): TierLimits {
    return TIER_LIMITS[config.tier];
}

/**
 * Checks if a feature is available in the current tier
 */
export function isFeatureAllowed(
    config: GluonConfig,
    feature: keyof Omit<TierLimits, 'maxProjects' | 'maxTeamMembers' | 'retentionDays'>
): boolean {
    return TIER_LIMITS[config.tier][feature];
}

/**
 * Gets the path to the config directory
 */
export function getConfigDir(workDir: string = process.cwd()): string {
    return join(workDir, CONFIG_DIR);
}

/**
 * Gets the path to the config file
 */
export function getConfigPath(workDir: string = process.cwd()): string {
    return join(getConfigDir(workDir), CONFIG_FILENAME);
}

/**
 * Checks if a Gluon project is initialized in the given directory
 */
export async function isInitialized(workDir: string = process.cwd()): Promise<boolean> {
    try {
        await access(getConfigPath(workDir), constants.F_OK);
        return true;
    } catch {
        return false;
    }
}

/**
 * Loads the project configuration
 *
 * @param workDir - Working directory (defaults to cwd)
 * @returns The loaded configuration, or default if not found
 */
export async function loadConfig(workDir: string = process.cwd()): Promise<GluonConfig> {
    const configPath = getConfigPath(workDir);

    try {
        const content = await readFile(configPath, 'utf8');
        const loaded = yaml.parse(content) as Partial<GluonConfig>;

        // Merge with defaults to handle missing fields
        const defaults = createDefaultConfig();
        return {
            ...defaults,
            ...loaded,
            secrets: { ...defaults.secrets, ...loaded.secrets },
            network: { ...defaults.network, ...loaded.network },
            modules: { ...defaults.modules, ...loaded.modules },
            telemetry: { ...defaults.telemetry, ...loaded.telemetry },
            cloud: { ...defaults.cloud, ...loaded.cloud },
            lagrangian: { ...defaults.lagrangian, ...loaded.lagrangian },
        };
    } catch (err) {
        if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
            return createDefaultConfig();
        }
        throw err;
    }
}

/**
 * Saves the project configuration
 *
 * @param config - Configuration to save
 * @param workDir - Working directory (defaults to cwd)
 */
export async function saveConfig(
    config: GluonConfig,
    workDir: string = process.cwd()
): Promise<void> {
    const configPath = getConfigPath(workDir);
    const configDir = getConfigDir(workDir);

    // Ensure directory exists
    await mkdir(configDir, { recursive: true });

    // Serialize and write
    const content = yaml.stringify(config, {
        indent: 2,
        sortMapEntries: false,
    });

    await writeFile(configPath, content, 'utf8');
}

/**
 * Initializes a new Gluon project
 *
 * @param projectName - Name for the project
 * @param workDir - Working directory
 * @returns The created configuration
 */
export async function initConfig(
    projectName?: string,
    workDir: string = process.cwd()
): Promise<GluonConfig> {
    if (await isInitialized(workDir)) {
        throw new Error('Project already initialized. Delete .dotset/gluon/ to reinitialize.');
    }

    const config = createDefaultConfig(projectName);
    await saveConfig(config, workDir);

    return config;
}

/**
 * Gets the compiled default secret patterns
 *
 * @returns Array of RegExp patterns for secret detection
 */
export function getDefaultSecretPatterns(): RegExp[] {
    return [...DEFAULT_SECRET_PATTERNS];
}

/**
 * Compiles custom patterns from config into RegExp objects
 *
 * @param patterns - Custom pattern configurations
 * @returns Array of compiled RegExp patterns
 */
export function compileCustomPatterns(patterns: SecretPattern[]): RegExp[] {
    return patterns
        .filter(p => p.enabled)
        .map(p => new RegExp(p.pattern, 'gi'));
}
