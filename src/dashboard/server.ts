/**
 * Gluon Local Dashboard Server
 * 
 * A simple HTTP server that serves a web-based dashboard for viewing
 * local telemetry data without requiring cloud sync.
 */

import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createCollector, type TelemetryEvent } from '../core/telemetry.js';
import { loadConfig, type GluonConfig } from '../core/config.js';
import { isCloudLinked, loadCloudConfig } from '../cloud/auth.js';

const DEFAULT_PORT = 3333;

/**
 * Dashboard HTML template with embedded CSS and JS
 */
function generateDashboardHTML(data: {
    projectName: string;
    stats: { totalEvents: number; sessions: number; byType: Record<string, number>; bySeverity: Record<string, number> };
    events: TelemetryEvent[];
    isCloudLinked: boolean;
    cloudProjectId?: string;
}): string {
    const eventsJSON = JSON.stringify(data.events.slice(-100).reverse());
    const statsJSON = JSON.stringify(data.stats);

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gluon Dashboard - ${data.projectName}</title>
    <style>
        :root {
            --bg: #0a0a0b;
            --surface: #141416;
            --surface-hover: #1e1e21;
            --border: rgba(255,255,255,0.08);
            --text: #e4e4e7;
            --text-muted: #71717a;
            --primary: #8b5cf6;
            --primary-dim: rgba(139,92,246,0.2);
            --success: #22c55e;
            --warning: #eab308;
            --error: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.5;
            padding: 24px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 32px;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border);
        }
        h1 {
            font-size: 24px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        h1 span { color: var(--primary); }
        .mode-badge {
            font-size: 12px;
            font-weight: 600;
            padding: 6px 12px;
            border-radius: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .mode-badge.local { background: var(--surface); color: var(--text-muted); border: 1px solid var(--border); }
        .mode-badge.cloud { background: var(--primary-dim); color: var(--primary); }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }
        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }
        .stat-label {
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }
        .stat-value { font-size: 32px; font-weight: 700; }
        .stat-value.primary { color: var(--primary); }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
        }
        .card-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
        }
        .event-list { max-height: 500px; overflow-y: auto; }
        .event-item {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            padding: 12px 20px;
            border-bottom: 1px solid var(--border);
        }
        .event-item:last-child { border-bottom: none; }
        .event-item:hover { background: var(--surface-hover); }
        .event-severity {
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            padding: 4px 8px;
            border-radius: 4px;
            min-width: 60px;
            text-align: center;
        }
        .event-severity.info { background: rgba(100,116,139,0.2); color: #94a3b8; }
        .event-severity.warning { background: rgba(234,179,8,0.2); color: var(--warning); }
        .event-severity.error, .event-severity.critical { background: rgba(239,68,68,0.2); color: var(--error); }
        .event-content { flex: 1; min-width: 0; }
        .event-message {
            font-family: ui-monospace, monospace;
            font-size: 13px;
            word-break: break-word;
        }
        .event-meta {
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 4px;
        }
        .empty-state {
            text-align: center;
            padding: 48px;
            color: var(--text-muted);
        }
        .refresh-btn {
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
        }
        .refresh-btn:hover { background: var(--surface-hover); border-color: var(--primary); }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1><span>◆</span> Gluon - ${data.projectName}</h1>
            <div style="display: flex; gap: 12px; align-items: center;">
                <span class="mode-badge ${data.isCloudLinked ? 'cloud' : 'local'}">
                    ${data.isCloudLinked ? '☁️ Cloud' : '📍 Local'}
                </span>
                <button class="refresh-btn" onclick="location.reload()">⟳ Refresh</button>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Events</div>
                <div class="stat-value primary" id="stat-total">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Sessions</div>
                <div class="stat-value" id="stat-sessions">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Secret Exposures</div>
                <div class="stat-value" style="color: var(--error)" id="stat-secrets">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Network Connections</div>
                <div class="stat-value" id="stat-network">0</div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">Recent Events</div>
            <div class="event-list" id="event-list"></div>
        </div>
    </div>

    <script>
        const stats = ${statsJSON};
        const events = ${eventsJSON};

        // Update stats
        document.getElementById('stat-total').textContent = stats.totalEvents;
        document.getElementById('stat-sessions').textContent = stats.sessions;
        document.getElementById('stat-secrets').textContent = stats.byType.secret_exposure || 0;
        document.getElementById('stat-network').textContent = stats.byType.network_connection || 0;

        // Render events
        const eventList = document.getElementById('event-list');
        if (events.length === 0) {
            eventList.innerHTML = '<div class="empty-state">No events recorded yet. Run a command with <code>gln run</code>.</div>';
        } else {
            eventList.innerHTML = events.map(event => \`
                <div class="event-item">
                    <span class="event-severity \${event.severity}">\${event.severity}</span>
                    <div class="event-content">
                        <div class="event-message">\${escapeHtml(event.message || event.type)}</div>
                        <div class="event-meta">\${event.type} · \${new Date(event.timestamp).toLocaleString()}</div>
                    </div>
                </div>
            \`).join('');
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>`;
}

/**
 * Start the dashboard server
 */
export async function startDashboardServer(
    config: GluonConfig,
    port: number = DEFAULT_PORT
): Promise<{ url: string; close: () => void }> {
    const telemetry = createCollector(config.telemetry);
    const cloudLinked = await isCloudLinked();
    const cloudConfig = cloudLinked ? await loadCloudConfig() : null;

    const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
        try {
            // Simple routing
            if (req.url === '/' || req.url === '/index.html') {
                const stats = await telemetry.getStats();
                const events = await telemetry.readEvents(100);

                const html = generateDashboardHTML({
                    projectName: config.projectName,
                    stats,
                    events,
                    isCloudLinked: cloudLinked,
                    cloudProjectId: cloudConfig?.projectId,
                });

                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(html);
            } else if (req.url === '/api/stats') {
                const stats = await telemetry.getStats();
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(stats));
            } else if (req.url === '/api/events') {
                const events = await telemetry.readEvents(100);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(events));
            } else {
                res.writeHead(404);
                res.end('Not Found');
            }
        } catch (error) {
            console.error('Dashboard error:', error);
            res.writeHead(500);
            res.end('Internal Server Error');
        }
    });

    return new Promise((resolve, reject) => {
        server.listen(port, () => {
            const url = `http://localhost:${port}`;
            resolve({
                url,
                close: () => server.close(),
            });
        });

        server.on('error', reject);
    });
}

export { DEFAULT_PORT };
