/**
 * Gluon CI/CD Output Formats Module
 *
 * Provides output formatting for CI/CD integration:
 * - SARIF (Static Analysis Results Interchange Format) for GitHub Security
 * - JSON for generic CI pipelines
 * - JUnit XML for test frameworks
 *
 * These formats enable integration with:
 * - GitHub Code Scanning (SARIF)
 * - GitLab Security Dashboard
 * - Jenkins, CircleCI, etc.
 */

import { type TelemetryEvent, type EventSeverity } from '../core/telemetry.js';

/**
 * SARIF severity levels
 */
type SarifLevel = 'error' | 'warning' | 'note' | 'none';

/**
 * Maps Gluon severity to SARIF levels
 */
function toSarifLevel(severity: EventSeverity): SarifLevel {
    switch (severity) {
        case 'critical':
        case 'error':
            return 'error';
        case 'warning':
            return 'warning';
        case 'info':
        default:
            return 'note';
    }
}

/**
 * SARIF Rule definition
 */
interface SarifRule {
    id: string;
    name: string;
    shortDescription: { text: string };
    fullDescription: { text: string };
    helpUri?: string;
    properties: {
        precision: 'very-high' | 'high' | 'medium' | 'low';
        'security-severity'?: string;
    };
}

/**
 * Default SARIF rules for Gluon event types
 */
const SARIF_RULES: Record<string, SarifRule> = {
    secret_exposure: {
        id: 'gluon/secret-exposure',
        name: 'SecretExposure',
        shortDescription: { text: 'Potential secret detected in output' },
        fullDescription: { text: 'A pattern matching a secret (API key, password, token) was detected in application output. This may indicate accidental credential exposure.' },
        helpUri: 'https://dotsetlabs.com/gluon/docs/secret-exposure',
        properties: {
            precision: 'high',
            'security-severity': '8.0',
        },
    },
    network_connection: {
        id: 'gluon/unauthorized-network',
        name: 'UnauthorizedNetwork',
        shortDescription: { text: 'Unexpected network connection' },
        fullDescription: { text: 'An outbound network connection was made to an unrecognized host. This may indicate supply chain attack or data exfiltration.' },
        helpUri: 'https://dotsetlabs.com/gluon/docs/network-monitoring',
        properties: {
            precision: 'medium',
            'security-severity': '5.0',
        },
    },
    module_load: {
        id: 'gluon/suspicious-module',
        name: 'SuspiciousModule',
        shortDescription: { text: 'Unexpected module loaded' },
        fullDescription: { text: 'A module was loaded that was not expected. This may indicate dependency confusion or compromised package.' },
        helpUri: 'https://dotsetlabs.com/gluon/docs/module-tracking',
        properties: {
            precision: 'medium',
            'security-severity': '6.0',
        },
    },
    process_error: {
        id: 'gluon/process-error',
        name: 'ProcessError',
        shortDescription: { text: 'Process error occurred' },
        fullDescription: { text: 'The monitored process encountered an error.' },
        helpUri: 'https://dotsetlabs.com/gluon/docs/monitoring',
        properties: {
            precision: 'high',
        },
    },
};

/**
 * Generates SARIF 2.1.0 output from telemetry events
 *
 * @param events - Telemetry events to convert
 * @param projectName - Project name for the run
 * @param workDir - Working directory for file paths
 * @returns SARIF document as object
 */
export function generateSarif(
    events: TelemetryEvent[],
    projectName: string,
    workDir: string = process.cwd()
): object {
    // Filter to security-relevant events
    const securityEvents = events.filter(e =>
        e.type === 'secret_exposure' ||
        e.type === 'network_connection' ||
        e.type === 'module_load' ||
        e.type === 'process_error'
    );

    // Collect unique rules used
    const rulesUsed = new Map<string, SarifRule>();
    const results: object[] = [];

    for (const event of securityEvents) {
        const rule = SARIF_RULES[event.type];
        if (!rule) continue;

        rulesUsed.set(rule.id, rule);

        results.push({
            ruleId: rule.id,
            level: toSarifLevel(event.severity),
            message: {
                text: event.message,
            },
            locations: [{
                physicalLocation: {
                    artifactLocation: {
                        uri: workDir,
                        uriBaseId: '%SRCROOT%',
                    },
                },
            }],
            fingerprints: {
                'gluon/event/id/v1': event.id,
                'gluon/session/id/v1': event.sessionId,
            },
            properties: {
                eventType: event.type,
                timestamp: event.timestamp,
                metadata: event.metadata,
            },
        });
    }

    return {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [{
            tool: {
                driver: {
                    name: 'Gluon',
                    organization: 'Dotset Labs',
                    version: '1.0.0',
                    informationUri: 'https://dotsetlabs.com/gluon',
                    rules: [...rulesUsed.values()],
                },
            },
            invocations: [{
                executionSuccessful: true,
                endTimeUtc: new Date().toISOString(),
            }],
            results,
            originalUriBaseIds: {
                '%SRCROOT%': {
                    uri: `file://${workDir}/`,
                },
            },
        }],
    };
}

/**
 * Generates JSON report from telemetry events
 */
export function generateJsonReport(
    events: TelemetryEvent[],
    projectName: string,
    workDir: string = process.cwd()
): object {
    const summary = {
        critical: 0,
        error: 0,
        warning: 0,
        info: 0,
    };

    for (const event of events) {
        summary[event.severity]++;
    }

    return {
        reportFormat: 'gluon-json-v1',
        generatedAt: new Date().toISOString(),
        project: {
            name: projectName,
            workDir,
        },
        summary: {
            totalEvents: events.length,
            bySeverity: summary,
        },
        events: events.map(e => ({
            id: e.id,
            type: e.type,
            severity: e.severity,
            message: e.message,
            timestamp: e.timestamp,
            sessionId: e.sessionId,
            metadata: e.metadata,
        })),
    };
}

/**
 * Gets the appropriate exit code based on events
 *
 * @param events - Telemetry events
 * @param failOn - Minimum severity to fail on
 * @returns Exit code (0 = success, non-zero = failure)
 */
export function getExitCode(
    events: TelemetryEvent[],
    failOn: EventSeverity = 'error'
): number {
    const severityLevel: Record<EventSeverity, number> = {
        critical: 4,
        error: 3,
        warning: 2,
        info: 1,
    };

    const threshold = severityLevel[failOn];

    for (const event of events) {
        if (severityLevel[event.severity] >= threshold) {
            return 1;
        }
    }

    return 0;
}

/**
 * Formats a summary line for CI output
 */
export function formatCiSummary(events: TelemetryEvent[]): string {
    const counts = { critical: 0, error: 0, warning: 0, info: 0 };

    for (const event of events) {
        counts[event.severity]++;
    }

    const parts: string[] = [];
    if (counts.critical) parts.push(`${counts.critical} critical`);
    if (counts.error) parts.push(`${counts.error} errors`);
    if (counts.warning) parts.push(`${counts.warning} warnings`);
    if (counts.info) parts.push(`${counts.info} info`);

    if (parts.length === 0) {
        return '✅ No security issues detected';
    }

    const icon = counts.critical || counts.error ? '❌' : '⚠️';
    return `${icon} Gluon found: ${parts.join(', ')}`;
}
