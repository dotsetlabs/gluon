import { Command } from 'commander';
import { colors, success, error } from '../utils/ui.js';
import {
    loadConfig,
    saveConfig,
    isInitialized,
    getConfigDir,
} from '../core/config.js';

export function registerConfigCommand(program: Command) {
    /**
     * Config Command
     * View or edit configuration
     */
    program
        .command('config')
        .description('View or edit configuration')
        .option('--get <key>', 'Get a configuration value')
        .option('--set <key=value>', 'Set a configuration value')
        .option('--json', 'Output as JSON')
        .action(async (options: { get?: string; set?: string; json?: boolean }) => {
            try {
                if (!(await isInitialized())) {
                    error('Project not initialized. Run "gln init" first.');
                }

                const config = await loadConfig();

                if (options.json) {
                    console.log(JSON.stringify(config, null, 2));
                    return;
                }

                if (options.get) {
                    const keys = options.get.split('.');
                    let value: unknown = config;
                    for (const key of keys) {
                        value = (value as Record<string, unknown>)?.[key];
                    }
                    console.log(value !== undefined ? JSON.stringify(value, null, 2) : 'undefined');
                    return;
                }

                if (options.set) {
                    const [path, value] = options.set.split('=');
                    if (!path || value === undefined) {
                        error('Invalid format. Use --set key.path=value');
                    }

                    // Parse value
                    let parsedValue: unknown;
                    if (value === 'true') parsedValue = true;
                    else if (value === 'false') parsedValue = false;
                    else if (!isNaN(Number(value))) parsedValue = Number(value);
                    else parsedValue = value;

                    // Set value
                    const keys = path.split('.');
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                    let target: Record<string, unknown> = config as unknown as Record<string, unknown>;
                    for (let i = 0; i < keys.length - 1; i++) {
                        target = target[keys[i]] as Record<string, unknown>;
                    }
                    target[keys[keys.length - 1]] = parsedValue;

                    await saveConfig(config);
                    success(`Set ${path} = ${JSON.stringify(parsedValue)}`);
                    return;
                }

                // Default: show config summary
                console.log(colors.bold('\n⚙️  Gluon Configuration\n'));
                console.log(`  ${colors.bold('Project Name:')} ${config.projectName}`);
                console.log(`  ${colors.bold('Config Path:')} ${getConfigDir()}/config.yaml`);
                console.log();

                console.log(colors.bold('Secrets Detection:'));
                console.log(`  Enabled: ${config.secrets.enabled ? colors.green('Yes') : colors.dim('No')}`);
                console.log(`  Custom Patterns: ${config.secrets.customPatterns.length}`);
                console.log(`  Tracked ENV Vars: ${config.secrets.trackedEnvVars.length}`);
                console.log();

                console.log(colors.bold('Network Monitoring:'));
                console.log(`  Enabled: ${config.network.enabled ? colors.green('Yes') : colors.dim('No')}`);
                console.log(`  Alert on New Domains: ${config.network.alertOnNewDomains ? colors.green('Yes') : colors.dim('No')}`);
                console.log(`  Ignored Domains: ${config.network.ignoredDomains.length}`);
                console.log();

                console.log(colors.bold('Module Tracking:'));
                console.log(`  Enabled: ${config.modules.enabled ? colors.green('Yes') : colors.dim('No')}`);
                console.log(`  Generate SBOM: ${config.modules.generateSbom ? colors.green('Yes') : colors.dim('No')}`);
                console.log();

                console.log(colors.bold('Telemetry:'));
                console.log(`  Enabled: ${config.telemetry.enabled ? colors.green('Yes') : colors.dim('No')}`);
                console.log(`  Storage: ${config.telemetry.storagePath}`);
                console.log(`  Buffer Size: ${config.telemetry.bufferSize} events`);
                console.log();

                console.log(colors.dim(`Use ${colors.cyan('gln config --json')} for full output.`));
            } catch (err: any) {
                error(err.message);
            }
        });
}
