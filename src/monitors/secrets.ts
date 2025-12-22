/**
 * Gluon Secrets Monitor
 *
 * Detects potential secret exposure in application output.
 * Scans stdout/stderr streams for patterns matching API keys, tokens, passwords, etc.
 *
 * Detection Strategy:
 * 1. Pattern matching: Uses regex patterns for known secret formats
 * 2. ENV value tracking: Compares output against known sensitive env values
 * 3. Contextual analysis: Considers surrounding content for false positive reduction
 */

import { type TelemetryCollector } from '../core/telemetry.js';
import { type HookManager, type HookContext } from '../core/hooks.js';
import { type GluonConfig } from '../core/config.js';

/**
 * Secret detection result
 */
export interface SecretMatch {
    /** Pattern name that matched */
    patternName: string;
    /** Starting position in the chunk */
    start: number;
    /** Ending position in the chunk */
    end: number;
    /** Redacted snippet for logging */
    redactedSnippet: string;
    /** Original matched text (for internal use only) */
    matchedText: string;
    /** Severity of the match */
    severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Named pattern with metadata
 */
interface NamedPattern {
    name: string;
    pattern: RegExp;
    severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Default patterns with names and severity
 */
const DEFAULT_NAMED_PATTERNS: NamedPattern[] = [
    // High-value API keys
    { name: 'Stripe Secret Key', pattern: /sk[-_]live[-_][a-zA-Z0-9]{24,}/gi, severity: 'critical' },
    { name: 'Stripe Test Key', pattern: /sk[-_]test[-_][a-zA-Z0-9]{24,}/gi, severity: 'high' },
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z-_]{35}/gi, severity: 'critical' },
    { name: 'GitHub Personal Token', pattern: /ghp_[a-zA-Z0-9]{36}/gi, severity: 'critical' },
    { name: 'GitHub OAuth Token', pattern: /gho_[a-zA-Z0-9]{36}/gi, severity: 'critical' },
    { name: 'GitHub Fine-grained PAT', pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/gi, severity: 'critical' },

    // AWS
    { name: 'AWS Access Key ID', pattern: /AKIA[0-9A-Z]{16}/gi, severity: 'critical' },

    // JWT tokens
    { name: 'JWT Token', pattern: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/gi, severity: 'high' },

    // Bearer tokens
    { name: 'Bearer Token', pattern: /Bearer\s+[a-zA-Z0-9_-]{20,}/gi, severity: 'high' },

    // Generic patterns (lower severity due to false positives)
    { name: 'Generic API Key', pattern: /['"]?[a-zA-Z_]*api[-_]?key['"]?\s*[:=]\s*['"][^'"]{16,}['"]/gi, severity: 'medium' },
    { name: 'Generic Secret', pattern: /['"]?[a-zA-Z_]*secret['"]?\s*[:=]\s*['"][^'"]{16,}['"]/gi, severity: 'medium' },
    { name: 'Generic Password', pattern: /['"]?password['"]?\s*[:=]\s*['"][^'"]{8,}['"]/gi, severity: 'medium' },
];

/**
 * Secrets monitor class
 */
export class SecretsMonitor {
    private patterns: NamedPattern[];
    private trackedEnvValues: Map<string, string> = new Map();
    private telemetry?: TelemetryCollector;
    private enabled: boolean;

    constructor(config: GluonConfig, telemetry?: TelemetryCollector) {
        this.enabled = config.secrets.enabled;
        this.telemetry = telemetry;

        // Build pattern list
        this.patterns = [...DEFAULT_NAMED_PATTERNS];

        // Add custom patterns from config
        for (const custom of config.secrets.customPatterns) {
            if (custom.enabled) {
                this.patterns.push({
                    name: custom.name,
                    pattern: new RegExp(custom.pattern, 'gi'),
                    severity: custom.severity,
                });
            }
        }

        // Track env values
        for (const envVar of config.secrets.trackedEnvVars) {
            const value = process.env[envVar];
            if (value && value.length >= 8) {
                this.trackedEnvValues.set(envVar, value);
            }
        }
    }

    /**
     * Scans a buffer for potential secrets
     */
    scan(data: Buffer | string, source: 'stdout' | 'stderr' = 'stdout'): SecretMatch[] {
        if (!this.enabled) return [];

        const text = typeof data === 'string' ? data : data.toString('utf8');
        const matches: SecretMatch[] = [];

        // Check against patterns
        for (const { name, pattern, severity } of this.patterns) {
            // Reset pattern state
            pattern.lastIndex = 0;

            let match: RegExpExecArray | null;
            while ((match = pattern.exec(text)) !== null) {
                const matchedText = match[0];
                const result: SecretMatch = {
                    patternName: name,
                    start: match.index,
                    end: match.index + matchedText.length,
                    redactedSnippet: this.redact(text, match.index, matchedText.length),
                    matchedText,
                    severity,
                };

                matches.push(result);

                // Record telemetry
                this.telemetry?.recordSecretExposure(
                    name,
                    source,
                    result.redactedSnippet
                );
            }
        }

        // Check against tracked env values
        for (const [envVar, value] of this.trackedEnvValues) {
            if (text.includes(value)) {
                const index = text.indexOf(value);
                const result: SecretMatch = {
                    patternName: `ENV:${envVar}`,
                    start: index,
                    end: index + value.length,
                    redactedSnippet: this.redact(text, index, value.length),
                    matchedText: value,
                    severity: 'critical',
                };

                matches.push(result);

                this.telemetry?.recordSecretExposure(
                    `ENV:${envVar}`,
                    source,
                    result.redactedSnippet,
                    envVar
                );
            }
        }

        return matches;
    }

    /**
     * Redacts sensitive content, keeping context
     */
    private redact(text: string, start: number, length: number): string {
        const contextBefore = 20;
        const contextAfter = 20;

        const snippetStart = Math.max(0, start - contextBefore);
        const snippetEnd = Math.min(text.length, start + length + contextAfter);

        let snippet = text.slice(snippetStart, snippetEnd);

        // Replace the matched portion with asterisks
        const relativeStart = start - snippetStart;
        const beforeMatch = snippet.slice(0, relativeStart);
        const afterMatch = snippet.slice(relativeStart + length);
        const redacted = '*'.repeat(Math.min(length, 16));

        snippet = beforeMatch + redacted + afterMatch;

        // Add ellipsis if truncated
        if (snippetStart > 0) snippet = '...' + snippet;
        if (snippetEnd < text.length) snippet = snippet + '...';

        // Replace newlines for display
        return snippet.replace(/\n/g, '\\n').replace(/\r/g, '\\r');
    }

    /**
     * Adds an environment variable to track
     */
    trackEnvVar(name: string): void {
        const value = process.env[name];
        if (value && value.length >= 8) {
            this.trackedEnvValues.set(name, value);
        }
    }

    /**
     * Creates a stream hook for monitoring
     */
    createStreamHook(source: 'stdout' | 'stderr'): (chunk: Buffer, context: HookContext) => void {
        return (chunk: Buffer) => {
            this.scan(chunk, source);
        };
    }

    /**
     * Registers hooks with a hook manager
     */
    registerHooks(hookManager: HookManager): void {
        hookManager.on('stdout', this.createStreamHook('stdout'));
        hookManager.on('stderr', this.createStreamHook('stderr'));
    }

    /**
     * Gets pattern count
     */
    getPatternCount(): number {
        return this.patterns.length;
    }

    /**
     * Gets tracked env var count
     */
    getTrackedEnvCount(): number {
        return this.trackedEnvValues.size;
    }
}

/**
 * Creates a secrets monitor from config
 */
export function createSecretsMonitor(
    config: GluonConfig,
    telemetry?: TelemetryCollector
): SecretsMonitor {
    return new SecretsMonitor(config, telemetry);
}
