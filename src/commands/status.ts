import { Command } from 'commander';
import { colors, success, error, info } from '../utils/ui.js';
import {
    isInitialized,
    loadConfig,
} from '../core/config.js';
import { createCollector } from '../core/telemetry.js';

export function registerStatusCommand(program: Command) {
    /**
     * Status Command
     * Shows telemetry status and summary
     */
    program
        .command('status')
        .description('Show telemetry status and summary')
        .option('-n, --limit <count>', 'Number of recent events to show', '10')
        .option('-t, --type <type>', 'Filter by event type (e.g., secret_exposure, network_connection)')
        .option('-s, --severity <level>', 'Filter by severity (info, warning, error, critical)')
        .option('--since <duration>', 'Filter events from duration ago (e.g., 1h, 24h, 7d)')
        .action(async (options: { limit: string; type?: string; severity?: string; since?: string }) => {
            try {
                if (!(await isInitialized())) {
                    error('Project not initialized. Run "gln init" first.');
                }

                const config = await loadConfig();
                const telemetry = createCollector(config.telemetry);

                const stats = await telemetry.getStats();
                const limit = parseInt(options.limit, 10);
                let recentEvents = await telemetry.readEvents(limit * 10); // Read more to allow filtering

                // Apply filters
                if (options.type) {
                    recentEvents = recentEvents.filter(e => e.type === options.type);
                }
                if (options.severity) {
                    recentEvents = recentEvents.filter(e => e.severity === options.severity);
                }
                if (options.since) {
                    const match = options.since.match(/^(\d+)([hdm])$/);
                    if (match) {
                        const amount = parseInt(match[1], 10);
                        const unit = match[2];
                        const ms = unit === 'h' ? amount * 60 * 60 * 1000 :
                            unit === 'd' ? amount * 24 * 60 * 60 * 1000 :
                                amount * 60 * 1000; // 'm' for minutes
                        const since = Date.now() - ms;
                        recentEvents = recentEvents.filter(e => new Date(e.timestamp).getTime() >= since);
                    }
                }

                // Apply limit after filtering
                recentEvents = recentEvents.slice(-limit);

                console.log(colors.bold('\n📊 Gluon Telemetry Status\n'));

                // Show active filters
                const activeFilters: string[] = [];
                if (options.type) activeFilters.push(`type=${options.type}`);
                if (options.severity) activeFilters.push(`severity=${options.severity}`);
                if (options.since) activeFilters.push(`since=${options.since}`);
                if (activeFilters.length > 0) {
                    console.log(colors.dim(`Filters: ${activeFilters.join(', ')}\n`));
                }

                console.log(colors.bold('Summary:'));
                console.log(`  Total Events: ${colors.cyan(stats.totalEvents.toString())}`);
                console.log(`  Sessions: ${colors.cyan(stats.sessions.toString())}`);
                console.log();

                if (Object.keys(stats.byType).length > 0) {
                    console.log(colors.bold('Events by Type:'));
                    for (const [type, count] of Object.entries(stats.byType)) {
                        const color = type === 'secret_exposure' ? colors.red : colors.cyan;
                        console.log(`  ${type}: ${color(count.toString())}`);
                    }
                    console.log();
                }

                if (Object.keys(stats.bySeverity).length > 0) {
                    console.log(colors.bold('Events by Severity:'));
                    for (const [severity, count] of Object.entries(stats.bySeverity)) {
                        const color = severity === 'critical' ? colors.red :
                            severity === 'error' ? colors.red :
                                severity === 'warning' ? colors.yellow : colors.dim;
                        console.log(`  ${severity}: ${color(count.toString())}`);
                    }
                    console.log();
                }

                if (recentEvents.length > 0) {
                    console.log(colors.bold(`Recent Events (${recentEvents.length}${activeFilters.length > 0 ? ' filtered' : ''}):`));
                    for (const event of recentEvents.reverse()) {
                        const severityColor = event.severity === 'critical' ? colors.red :
                            event.severity === 'warning' ? colors.yellow : colors.dim;
                        const time = new Date(event.timestamp).toLocaleTimeString();
                        console.log(`  ${colors.dim(time)} [${severityColor(event.severity)}] ${event.message}`);
                    }
                    console.log();
                } else {
                    if (activeFilters.length > 0) {
                        info('No events match the specified filters.');
                    } else {
                        info('No events recorded yet. Run a command with "gln run" to collect telemetry.');
                    }
                }
            } catch (err: any) {
                error(err.message);
            }
        });
}
