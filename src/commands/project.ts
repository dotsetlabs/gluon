import { Command } from 'commander';
import { colors, success, error, info } from '../utils/ui.js';
import { cloudClient } from '../cloud/client.js';
import {
    isAuthenticated,
    isCloudLinked,
    loadCloudConfig,
    saveCloudConfig,
    unlinkCloud,
} from '../cloud/auth.js';

export function registerProjectCommands(program: Command) {
    /**
     * link command
     */
    program
        .command('link <projectId>')
        .description('Link current project to Gluon Cloud project')
        .action(async (projectId) => {
            try {
                if (!(await isAuthenticated())) {
                    error('Not authenticated. Run "gln login" first.');
                }

                info(`Linking project ${colors.cyan(projectId)}...`);

                // Verify project exists
                await cloudClient.getProject(projectId);

                await saveCloudConfig(process.cwd(), {
                    projectId,
                    apiUrl: cloudClient['apiUrl'],
                    linkedAt: new Date().toISOString(),
                });

                success(`Successfully linked to project ${projectId}`);
            } catch (err: any) {
                error(err.message);
            }
        });

    /**
     * unlink command
     */
    program
        .command('unlink')
        .description('Unlink current project from Gluon Cloud')
        .action(async () => {
            try {
                if (!(await isCloudLinked())) {
                    error('Project is not linked to cloud.');
                }

                const cloudConfig = await loadCloudConfig();
                const projectId = cloudConfig?.projectId ?? 'unknown';

                await unlinkCloud(process.cwd());

                success(`Unlinked from cloud project ${colors.cyan(projectId)}`);
                info('Local telemetry will no longer sync to cloud.');
            } catch (err: any) {
                error(err.message);
            }
        });
}
