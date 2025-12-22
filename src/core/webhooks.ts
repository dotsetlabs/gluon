/**
 * Gluon Webhook Alerts Module
 *
 * Dispatches security alerts to configured webhook endpoints.
 * Supports Slack, Discord, generic HTTP webhooks, and custom formats.
 *
 * Features:
 * - Multiple webhook endpoints per project
 * - Payload formatting (Slack, Discord, JSON)
 * - Retry with exponential backoff
 * - Severity-based filtering
 */

import { type TelemetryEvent, type EventSeverity } from '../core/telemetry.js';

/**
 * Webhook payload format
 */
export type WebhookFormat = 'json' | 'slack' | 'discord';

/**
 * Webhook endpoint configuration
 */
export interface WebhookConfig {
    /** Unique identifier for this webhook */
    id: string;
    /** Display name */
    name: string;
    /** Webhook URL (must be HTTPS) */
    url: string;
    /** Payload format */
    format: WebhookFormat;
    /** Minimum severity to trigger (info, warning, error, critical) */
    minSeverity: EventSeverity;
    /** Event types to send (empty = all) */
    eventTypes: string[];
    /** Whether this webhook is enabled */
    enabled: boolean;
    /** Custom headers to include */
    headers?: Record<string, string>;
    /** Secret for HMAC signature (optional) */
    secret?: string;
}

/**
 * Webhook delivery result
 */
export interface WebhookDeliveryResult {
    webhookId: string;
    success: boolean;
    statusCode?: number;
    error?: string;
    timestamp: string;
    retryCount: number;
}

/**
 * Severity levels for filtering (lower = more severe)
 */
const SEVERITY_LEVELS: Record<EventSeverity, number> = {
    critical: 0,
    error: 1,
    warning: 2,
    info: 3,
};

/**
 * Checks if an event meets the minimum severity threshold
 */
function meetsSeverityThreshold(event: TelemetryEvent, minSeverity: EventSeverity): boolean {
    return SEVERITY_LEVELS[event.severity] <= SEVERITY_LEVELS[minSeverity];
}

/**
 * Formats event for Slack webhook
 */
function formatSlackPayload(event: TelemetryEvent, projectName: string): object {
    const severityEmoji = {
        critical: '🚨',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️',
    };

    const severityColor = {
        critical: '#dc2626',
        error: '#ef4444',
        warning: '#f59e0b',
        info: '#3b82f6',
    };

    return {
        attachments: [{
            color: severityColor[event.severity],
            blocks: [
                {
                    type: 'section',
                    text: {
                        type: 'mrkdwn',
                        text: `${severityEmoji[event.severity]} *Gluon Security Alert*\n${event.message}`,
                    },
                },
                {
                    type: 'context',
                    elements: [
                        {
                            type: 'mrkdwn',
                            text: `*Project:* ${projectName} | *Type:* ${event.type} | *Severity:* ${event.severity}`,
                        },
                    ],
                },
                {
                    type: 'context',
                    elements: [
                        {
                            type: 'mrkdwn',
                            text: `*Session:* \`${event.sessionId}\` | *Time:* ${new Date(event.timestamp).toLocaleString()}`,
                        },
                    ],
                },
            ],
        }],
    };
}

/**
 * Formats event for Discord webhook
 */
function formatDiscordPayload(event: TelemetryEvent, projectName: string): object {
    const severityEmoji = {
        critical: '🚨',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️',
    };

    const severityColor = {
        critical: 0xdc2626,
        error: 0xef4444,
        warning: 0xf59e0b,
        info: 0x3b82f6,
    };

    return {
        embeds: [{
            title: `${severityEmoji[event.severity]} Gluon Security Alert`,
            description: event.message,
            color: severityColor[event.severity],
            fields: [
                { name: 'Project', value: projectName, inline: true },
                { name: 'Type', value: event.type, inline: true },
                { name: 'Severity', value: event.severity, inline: true },
                { name: 'Session', value: `\`${event.sessionId}\``, inline: false },
            ],
            timestamp: event.timestamp,
            footer: { text: 'Gluon Security by Dotset Labs' },
        }],
    };
}

/**
 * Formats event as JSON payload
 */
function formatJsonPayload(event: TelemetryEvent, projectName: string): object {
    return {
        source: 'gluon',
        version: '1.0',
        projectName,
        event: {
            id: event.id,
            type: event.type,
            severity: event.severity,
            message: event.message,
            metadata: event.metadata,
            sessionId: event.sessionId,
            timestamp: event.timestamp,
            pid: event.pid,
        },
    };
}

/**
 * Formats an event for the specified webhook format
 */
export function formatWebhookPayload(
    event: TelemetryEvent,
    format: WebhookFormat,
    projectName: string
): object {
    switch (format) {
        case 'slack':
            return formatSlackPayload(event, projectName);
        case 'discord':
            return formatDiscordPayload(event, projectName);
        case 'json':
        default:
            return formatJsonPayload(event, projectName);
    }
}

/**
 * Computes HMAC signature for webhook payload
 */
async function computeSignature(payload: string, secret: string): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
    return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Dispatches an event to a webhook endpoint
 */
export async function dispatchWebhook(
    webhook: WebhookConfig,
    event: TelemetryEvent,
    projectName: string,
    maxRetries: number = 3
): Promise<WebhookDeliveryResult> {
    // Check if event passes filters
    if (!meetsSeverityThreshold(event, webhook.minSeverity)) {
        return {
            webhookId: webhook.id,
            success: true,
            timestamp: new Date().toISOString(),
            retryCount: 0,
        };
    }

    if (webhook.eventTypes.length > 0 && !webhook.eventTypes.includes(event.type)) {
        return {
            webhookId: webhook.id,
            success: true,
            timestamp: new Date().toISOString(),
            retryCount: 0,
        };
    }

    const payload = formatWebhookPayload(event, webhook.format, projectName);
    const payloadString = JSON.stringify(payload);

    // Build headers
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'User-Agent': 'Gluon-Webhook/1.0',
        ...webhook.headers,
    };

    // Add HMAC signature if secret is configured
    if (webhook.secret) {
        const signature = await computeSignature(payloadString, webhook.secret);
        headers['X-Gluon-Signature'] = `sha256=${signature}`;
    }

    // Retry loop with exponential backoff
    let lastError: string | undefined;
    let statusCode: number | undefined;

    for (let retry = 0; retry <= maxRetries; retry++) {
        try {
            const response = await fetch(webhook.url, {
                method: 'POST',
                headers,
                body: payloadString,
            });

            statusCode = response.status;

            if (response.ok) {
                return {
                    webhookId: webhook.id,
                    success: true,
                    statusCode,
                    timestamp: new Date().toISOString(),
                    retryCount: retry,
                };
            }

            lastError = `HTTP ${response.status}: ${response.statusText}`;

            // Don't retry on 4xx errors (client error)
            if (response.status >= 400 && response.status < 500) {
                break;
            }

        } catch (err) {
            lastError = (err as Error).message;
        }

        // Wait before retry (exponential backoff: 1s, 2s, 4s)
        if (retry < maxRetries) {
            await new Promise(resolve => setTimeout(resolve, Math.pow(2, retry) * 1000));
        }
    }

    return {
        webhookId: webhook.id,
        success: false,
        statusCode,
        error: lastError,
        timestamp: new Date().toISOString(),
        retryCount: maxRetries,
    };
}

/**
 * Dispatches an event to all configured webhooks
 */
export async function dispatchToAllWebhooks(
    webhooks: WebhookConfig[],
    event: TelemetryEvent,
    projectName: string
): Promise<WebhookDeliveryResult[]> {
    const enabledWebhooks = webhooks.filter(w => w.enabled);

    const results = await Promise.all(
        enabledWebhooks.map(webhook => dispatchWebhook(webhook, event, projectName))
    );

    return results;
}

/**
 * Creates a default webhook configuration
 */
export function createDefaultWebhookConfig(
    name: string,
    url: string,
    format: WebhookFormat = 'json'
): WebhookConfig {
    return {
        id: `wh_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
        name,
        url,
        format,
        minSeverity: 'warning',
        eventTypes: [],
        enabled: true,
    };
}

/**
 * Validates a webhook URL
 */
export function validateWebhookUrl(url: string): { valid: boolean; error?: string } {
    try {
        const parsed = new URL(url);

        if (parsed.protocol !== 'https:') {
            return { valid: false, error: 'Webhook URL must use HTTPS' };
        }

        return { valid: true };
    } catch {
        return { valid: false, error: 'Invalid URL format' };
    }
}
