import { Command } from 'commander';
import { colors, success, error, info } from '../utils/ui.js';
import {
    isInitialized,
    loadConfig,
} from '../core/config.js';

export function registerDashboardCommand(program: Command) {
    /**
     * dashboard command
     */
    program
        .command('dashboard')
        .description('Start a local web dashboard to view telemetry')
        .option('-p, --port <port>', 'Port to serve dashboard on', '3333')
        .option('--no-open', 'Do not open browser automatically')
        .action(async (options: { port: string; open?: boolean }) => {
            try {
                if (!(await isInitialized())) {
                    error('Project not initialized. Run "gln init" first.');
                }

                const config = await loadConfig();
                const port = parseInt(options.port, 10);

                info('Starting Gluon Dashboard...');

                // Dynamically import to avoid loading at startup
                const { startDashboardServer } = await import('../dashboard/server.js');
                const { url } = await startDashboardServer(config, port);

                success(`Dashboard running at ${colors.cyan(url)}`);
                console.log(colors.dim('Press Ctrl+C to stop'));

                // Open browser if not disabled
                if (options.open !== false) {
                    const { exec } = await import('node:child_process');
                    const openCommand = process.platform === 'darwin' ? 'open' :
                        process.platform === 'win32' ? 'start' : 'xdg-open';
                    exec(`${openCommand} ${url}`);
                }

                // Keep the process running
                await new Promise(() => { }); // Never resolves
            } catch (err: any) {
                error(err.message);
            }
        });
}
