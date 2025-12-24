import { Command } from 'commander';
import { colors, success, error, info } from '../utils/ui.js';
import {
    isAuthenticated,
    isCloudLinked,
    loadCloudConfig,
} from '../cloud/auth.js';
import { loadConfig } from '../core/config.js';
import { createCollector } from '../core/telemetry.js';

export function registerPushCommand(program: Command) {
    /**
     * push command
     */
    program
        .command('push')
        .description('Sync all local telemetry to Gluon Cloud')
        .action(async () => {
            try {
                if (!(await isAuthenticated())) {
                    error('Not authenticated. Run "gln login" first.');
                }

                if (!(await isCloudLinked())) {
                    error('Project not linked to cloud. Run "gln link <projectId>" first.');
                }

                const cloudConfig = await loadCloudConfig();
                if (!cloudConfig) {
                    error('Failed to load cloud configuration.');
                }

                const config = await loadConfig();
                const telemetry = createCollector(config.telemetry);
                telemetry.setCloudProjectId(cloudConfig!.projectId);

                info(`Pushing telemetry to ${colors.cyan(cloudConfig!.projectId)}...`);
                const synced = await telemetry.syncAllToCloud();

                if (synced > 0) {
                    success(`Successfully synced ${synced} event(s) to Gluon Cloud.`);
                } else {
                    info('No new telemetry events to sync.');
                }
            } catch (err: any) {
                error(err.message);
            }
        });
}
