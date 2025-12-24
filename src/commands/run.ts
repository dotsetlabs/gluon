import { Command } from 'commander';
import { colors, success, error, info, warn } from '../utils/ui.js';
import { basename, join } from 'node:path';
import { writeFile } from 'node:fs/promises';
import {
    loadConfig,
    createDefaultConfig,
    isInitialized,
    type GluonConfig,
} from '../core/config.js';
import {
    isCloudLinked,
    loadCloudConfig,
} from '../cloud/auth.js';
import { createCollector, generateSessionId } from '../core/telemetry.js';
import { createHookManager } from '../core/hooks.js';
import { run, type RunResult } from '../core/runner.js';
import { createSecretsMonitor } from '../monitors/secrets.js';
import { createNetworkMonitor } from '../monitors/network.js';
import { installNetworkHooks, removeNetworkHooks } from '../monitors/network-hooks.js';
import {
    installModuleHooks,
    removeModuleHooks,
    generateSBOM,
    generateSPDX,
    getModuleStats,
} from '../monitors/module-hooks.js';

export function registerRunCommand(program: Command) {
    /**
     * Run Command
     * Executes a command with security monitoring
     */
    program
        .command('run')
        .description('Run a command with security monitoring')
        .argument('<command...>', 'Command and arguments to run')
        .option('--no-secrets', 'Disable secret detection')
        .option('--no-network', 'Disable network monitoring')
        .option('--no-modules', 'Disable module tracking')
        .option('--sbom', 'Generate SBOM after run')
        .option('--sbom-format <format>', 'SBOM format (cyclonedx or spdx)', 'cyclonedx')
        .allowUnknownOption()
        .action(async (commandArgs: string[], options: {
            secrets?: boolean;
            network?: boolean;
            modules?: boolean;
            sbom?: boolean;
            sbomFormat?: string;
        }) => {
            try {
                const opts = program.opts();
                const quiet = opts.quiet ?? false;
                const verbose = opts.verbose ?? false;

                // Load config
                let config: GluonConfig;
                if (await isInitialized()) {
                    config = await loadConfig();
                } else {
                    // Use defaults for uninitialized projects
                    if (!quiet) {
                        warn('Project not initialized. Using default configuration.');
                        info(`Run ${colors.cyan('gln init')} to create a configuration file.`);
                        console.log();
                    }
                    config = createDefaultConfig();
                }

                // Apply command-line overrides
                if (options.secrets === false) {
                    config.secrets.enabled = false;
                }
                if (options.network === false) {
                    config.network.enabled = false;
                }
                if (options.modules === false) {
                    config.modules.enabled = false;
                }

                // Create telemetry collector
                const sessionId = generateSessionId();
                const telemetry = createCollector(config.telemetry, sessionId);

                // Link to cloud if configured
                if (await isCloudLinked()) {
                    const cloudConfig = await loadCloudConfig();
                    if (cloudConfig) {
                        telemetry.setCloudProjectId(cloudConfig.projectId);
                    }
                }

                // Create monitors
                const secretsMonitor = createSecretsMonitor(config, telemetry);
                const networkMonitor = createNetworkMonitor(config, telemetry);
                const hookManager = createHookManager();

                // Register secret detection hooks
                secretsMonitor.registerHooks(hookManager);

                // Install network interception if enabled
                if (config.network.enabled) {
                    installNetworkHooks(networkMonitor);
                }

                // Install module tracking if enabled
                if (config.modules.enabled) {
                    installModuleHooks(telemetry);
                }

                // Separate the command from its arguments
                const [command, ...args] = commandArgs;

                if (!command) {
                    error('No command specified. Usage: gln run -- <command>');
                }

                if (!quiet) {
                    const monitors: string[] = [];
                    if (config.secrets.enabled) monitors.push('secrets');
                    if (config.network.enabled) monitors.push('network');
                    if (config.modules.enabled) monitors.push('modules');

                    // Show mode (local vs cloud)
                    const cloudConfig = await isCloudLinked() ? await loadCloudConfig() : null;
                    const modeText = cloudConfig
                        ? `☁️  Cloud (${colors.cyan(cloudConfig.projectId)})`
                        : `📍 Local only`;

                    console.log(colors.dim(`[Gluon] Session: ${sessionId}`));
                    console.log(colors.dim(`[Gluon] Mode: ${modeText}`));
                    console.log(colors.dim(`[Gluon] Monitoring: ${monitors.join(', ')}`));
                    console.log(colors.dim(`[Gluon] Command: ${command} ${args.join(' ')}`));
                    console.log();
                }

                // Run the command with monitoring
                const result: RunResult = await run(command, args, {
                    hookManager,
                    telemetry,
                });

                // Cleanup hooks
                if (config.network.enabled) {
                    removeNetworkHooks();
                }
                if (config.modules.enabled) {
                    removeModuleHooks();
                }

                // Flush telemetry
                await telemetry.shutdown();

                // Show summary
                if (!quiet) {
                    console.log();
                    console.log(colors.dim(`[Gluon] Process exited with code ${result.exitCode}`));
                    console.log(colors.dim(`[Gluon] Duration: ${result.durationMs}ms`));

                    // Show network summary if verbose
                    if (verbose && config.network.enabled) {
                        const netSummary = networkMonitor.getSummary();
                        if (netSummary.uniqueHosts > 0) {
                            console.log();
                            console.log(colors.bold('Network Activity:'));
                            console.log(`  Unique hosts: ${colors.cyan(netSummary.uniqueHosts.toString())}`);
                            console.log(`  Total connections: ${colors.cyan(netSummary.totalConnections.toString())}`);
                            if (netSummary.newHosts.length > 0) {
                                console.log(`  New hosts: ${colors.yellow(netSummary.newHosts.join(', '))}`);
                            }
                        }
                    }

                    // Show module summary if verbose
                    if (verbose && config.modules.enabled) {
                        const modStats = getModuleStats();
                        if (modStats.total > 0) {
                            console.log();
                            console.log(colors.bold('Module Activity:'));
                            console.log(`  Loaded modules: ${colors.cyan(modStats.total.toString())}`);
                            console.log(`  Unique packages: ${colors.cyan(modStats.uniquePackages.toString())}`);
                        }
                    }
                }

                // Show security alerts
                const stats = await telemetry.getStats();
                const secretExposures = stats.byType['secret_exposure'] ?? 0;
                const networkConnections = stats.byType['network_connection'] ?? 0;

                if (!quiet) {
                    if (secretExposures > 0) {
                        console.log();
                        console.log(colors.red(`⚠️  ${secretExposures} potential secret exposure(s) detected!`));
                        console.log(`   Run ${colors.cyan('gln status')} for details.`);
                    }

                    if (networkConnections > 0 && verbose) {
                        console.log();
                        console.log(colors.dim(`📡 ${networkConnections} network connection(s) tracked.`));
                    }
                }

                // Generate SBOM if requested
                if (options.sbom && config.modules.enabled) {
                    const projectName = basename(process.cwd());
                    const sbom = options.sbomFormat === 'spdx'
                        ? generateSPDX(projectName)
                        : generateSBOM(projectName);

                    const filename = options.sbomFormat === 'spdx'
                        ? 'gluon-sbom.spdx.json'
                        : 'gluon-sbom.cdx.json';

                    await writeFile(filename, JSON.stringify(sbom, null, 2), 'utf8');
                    info(`SBOM written to ${colors.cyan(filename)}`);
                }

                process.exit(result.exitCode);
            } catch (err: any) {
                error(err.message);
            }
        });
}
