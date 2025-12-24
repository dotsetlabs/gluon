import { Command } from 'commander';
import { colors, success, error, info } from '../utils/ui.js';
import { cloudClient } from '../cloud/client.js';
import {
    isInitialized,
    initConfig,
    getTierLimits,
} from '../core/config.js';
import {
    isAuthenticated,
    saveCloudConfig,
} from '../cloud/auth.js';
import { basename } from 'node:path';

export function registerInitCommand(program: Command) {
    /**
     * Initialize Command
     * Sets up a new Gluon project
     */
    program
        .command('init')
        .description('Initialize a new Gluon project')
        .option('--name <name>', 'Project name')
        .option('--cloud', 'Initialize with cloud project')
        .action(async (options: { name?: string; cloud?: boolean }) => {
            try {
                if (await isInitialized()) {
                    error('Project already initialized. Delete .dotset/gluon/ to reinitialize.');
                }

                const projectName = options.name ?? basename(process.cwd());

                // Handle cloud initialization if requested
                let cloudProject: { id: string; name: string } | undefined;
                if (options.cloud) {
                    if (!(await isAuthenticated())) {
                        info('You are not logged in. Cloud project creation requires authentication.');
                        info('Run "gln login" first, or initialize without --cloud.');
                        process.exit(1);
                    }

                    info(`Creating cloud project "${projectName}"...`);
                    cloudProject = await cloudClient.createProject(projectName);

                    await saveCloudConfig(process.cwd(), {
                        projectId: cloudProject.id,
                        apiUrl: cloudClient['apiUrl'],
                        linkedAt: new Date().toISOString(),
                    });
                }

                const config = await initConfig(projectName);

                success('Gluon project initialized!');
                console.log();
                info(`Configuration saved to ${colors.cyan('.dotset/gluon/config.yaml')}`);
                if (cloudProject) {
                    info(`Linked to cloud project: ${colors.green(cloudProject.id)}`);
                }
                console.log();

                console.log(colors.bold('Configuration:'));
                console.log(`  Project Name: ${colors.cyan(config.projectName)}`);
                console.log(`  Plan: ${colors.cyan(config.tier.charAt(0).toUpperCase() + config.tier.slice(1))}`);
                console.log(`  Retention: ${colors.cyan(getTierLimits(config).retentionDays.toString())} days`);
                console.log(`  Secret Detection: ${config.secrets.enabled ? colors.green('Enabled') : colors.dim('Disabled')}`);
                console.log(`  Network Monitoring: ${config.network.enabled ? colors.green('Enabled') : colors.dim('Disabled')}`);
                console.log(`  Module Tracking: ${config.modules.enabled ? colors.green('Enabled') : colors.dim('Disabled')}`);
                console.log();

                console.log(colors.bold('📥 Next steps:'));
                console.log(`   1. Run your app with monitoring: ${colors.cyan('gln run -- npm start')}`);
                console.log(`   2. View telemetry: ${colors.cyan('gln status')}`);
                console.log(`   3. Customize settings: ${colors.cyan('gln config')}`);
                console.log();

                console.log(colors.yellow('⚠️  Important:'));
                console.log('   Add .dotset/ to your .gitignore');
            } catch (err: any) {
                error(err.message);
            }
        });
}
