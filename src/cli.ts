/**
 * Gluon CLI
 *
 * Command-line interface for the Gluon security telemetry platform.
 *
 * Commands:
 *   init                   Initialize a new Gluon project
 *   run -- <command>       Run a command with security monitoring
 *   status                 Show telemetry status and summary
 *   dashboard              Launch local development dashboard
 *   config                 View or edit configuration
 *   sbom                   Generate runtime SBOM
 *
 * Global Options:
 *   --quiet               Suppress Gluon output
 *   --verbose             Show detailed output
 */

import { Command } from 'commander';
import { basename } from 'node:path';
import { writeFile } from 'node:fs/promises';
import {
    loadConfig,
    saveConfig,
    initConfig,
    isInitialized,
    getConfigDir,
    getTierLimits,
    isFeatureAllowed,
    TIER_LIMITS,
    type GluonConfig,
} from './core/config.js';
import {
    isAuthenticated,
    loadCredentials,
    saveCredentials,
    clearCredentials,
    isCloudLinked,
    loadCloudConfig,
    saveCloudConfig,
    unlinkCloud,
} from './cloud/auth.js';
import { cloudClient } from './cloud/client.js';
import { createCollector, generateSessionId } from './core/telemetry.js';
import { createHookManager } from './core/hooks.js';
import { run, type RunResult } from './core/runner.js';
import { createSecretsMonitor } from './monitors/secrets.js';
import { createNetworkMonitor } from './monitors/network.js';
import { installNetworkHooks, removeNetworkHooks } from './monitors/network-hooks.js';
import {
    installModuleHooks,
    removeModuleHooks,
    generateSBOM,
    generateSPDX,
    getLoadedModules,
    getModuleStats,
} from './monitors/module-hooks.js';
import { detectAxion, updateAxionIntegration, getAxionInfo } from './integrations/axion.js';

const program = new Command();

/**
 * Formats output with colors for better readability
 */
const colors = {
    green: (text: string) => `\x1b[32m${text}\x1b[0m`,
    yellow: (text: string) => `\x1b[33m${text}\x1b[0m`,
    red: (text: string) => `\x1b[31m${text}\x1b[0m`,
    cyan: (text: string) => `\x1b[36m${text}\x1b[0m`,
    magenta: (text: string) => `\x1b[35m${text}\x1b[0m`,
    dim: (text: string) => `\x1b[2m${text}\x1b[0m`,
    bold: (text: string) => `\x1b[1m${text}\x1b[0m`,
};

/**
 * Prints a success message
 */
function success(message: string): void {
    console.log(colors.green('✓'), message);
}

/**
 * Prints an error message and exits
 */
function error(message: string): never {
    console.error(colors.red('✗'), message);
    process.exit(1);
}

/**
 * Prints an info message
 */
function info(message: string): void {
    console.log(colors.cyan('ℹ'), message);
}

/**
 * Prints a warning message
 */
function warn(message: string): void {
    console.log(colors.yellow('⚠'), message);
}

program
    .name('gln')
    .description('Runtime Security Telemetry for Modern Applications')
    .version('1.0.0')
    .option('-q, --quiet', 'Suppress Gluon output')
    .option('-v, --verbose', 'Show detailed output');

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
                error('Project already initialized. Delete .gluon/ to reinitialize.');
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

            let config = await initConfig(projectName);

            // Check for Axion integration
            const axionDetected = await detectAxion();
            if (axionDetected) {
                config = await updateAxionIntegration(config);
                await saveConfig(config);
            }

            success('Gluon project initialized!');
            console.log();
            info(`Configuration saved to ${colors.cyan('.gluon/config.yaml')}`);
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

            if (axionDetected) {
                console.log();
                console.log(colors.magenta('🔗 Axion Detected!'));
                console.log(`   Gluon will monitor secrets from your Axion manifest.`);
                if (config.tier === 'free') {
                    console.log(colors.dim(`   Upgrade to Pro for full Axion integration.`));
                }
            }
            console.log();

            console.log(colors.bold('📥 Next steps:'));
            console.log(`   1. Run your app with monitoring: ${colors.cyan('gln run -- npm start')}`);
            console.log(`   2. View telemetry: ${colors.cyan('gln status')}`);
            console.log(`   3. Customize settings: ${colors.cyan('gln config')}`);
            console.log();

            console.log(colors.yellow('⚠️  Important:'));
            console.log('   Add .gluon/ to your .gitignore');
        } catch (err) {
            error((err as Error).message);
        }
    });

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
                const { createDefaultConfig } = await import('./core/config.js');
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
        } catch (err) {
            error((err as Error).message);
        }
    });

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
        } catch (err) {
            error((err as Error).message);
        }
    });

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
        } catch (err) {
            error((err as Error).message);
        }
    });


/**
 * SBOM Command
 * Generate Software Bill of Materials
 */
program
    .command('sbom')
    .description('Generate SBOM (Software Bill of Materials)')
    .option('--format <format>', 'Output format (cyclonedx or spdx)', 'cyclonedx')
    .option('-o, --output <file>', 'Output file path')
    .option('--static', 'Generate from package.json instead of runtime')
    .action(async (options: { format: string; output?: string; static?: boolean }) => {
        try {
            const projectName = basename(process.cwd());

            if (options.static) {
                // Static SBOM from package.json
                info('Generating static SBOM from package.json...');

                try {
                    const { readFile } = await import('node:fs/promises');
                    const { join } = await import('node:path');

                    const packageJsonPath = join(process.cwd(), 'package.json');
                    const packageJson = JSON.parse(await readFile(packageJsonPath, 'utf8'));

                    const allDeps = {
                        ...packageJson.dependencies ?? {},
                        ...packageJson.devDependencies ?? {},
                    };

                    // Generate SBOM
                    const components = Object.entries(allDeps).map(([name, version]) => ({
                        type: 'library' as const,
                        name,
                        version: String(version).replace(/^[\^~>=<]/, ''),
                        purl: `pkg:npm/${name.replace(/\//g, '%2F')}@${String(version).replace(/^[\^~>=<]/, '')}`,
                    }));

                    const sbom = options.format === 'spdx' ? {
                        spdxVersion: 'SPDX-2.3',
                        dataLicense: 'CC0-1.0',
                        SPDXID: 'SPDXRef-DOCUMENT',
                        name: projectName,
                        documentNamespace: `https://gluon.dotsetlabs.com/sbom/${projectName}/${Date.now()}`,
                        creationInfo: {
                            created: new Date().toISOString(),
                            creators: ['Tool: gluon-1.0.0'],
                        },
                        packages: components.map((c, i) => ({
                            SPDXID: `SPDXRef-Package-${i + 1}`,
                            name: c.name,
                            versionInfo: c.version,
                            downloadLocation: `https://www.npmjs.com/package/${c.name}`,
                        })),
                    } : {
                        bomFormat: 'CycloneDX',
                        specVersion: '1.5',
                        version: 1,
                        metadata: {
                            timestamp: new Date().toISOString(),
                            tools: [{ vendor: 'dotsetlabs', name: 'gluon', version: '1.0.0' }],
                            component: { type: 'application', name: projectName },
                        },
                        components,
                    };

                    const output = JSON.stringify(sbom, null, 2);

                    if (options.output) {
                        await writeFile(options.output, output, 'utf8');
                        success(`SBOM written to ${options.output}`);
                    } else {
                        console.log(output);
                    }

                    console.log();
                    info(`Found ${components.length} dependencies in package.json`);

                } catch (err) {
                    error(`Failed to read package.json: ${(err as Error).message}`);
                }
            } else {
                // Runtime SBOM instructions
                info('Runtime SBOM tracks dependencies loaded during execution.');
                console.log();
                console.log('To generate a runtime SBOM:');
                console.log(`  ${colors.cyan('gln run --sbom -- npm start')}`);
                console.log();
                console.log('For static SBOM from package.json:');
                console.log(`  ${colors.cyan('gln sbom --static')}`);
                console.log(`  ${colors.cyan('gln sbom --static --format spdx -o sbom.spdx.json')}`);
            }
        } catch (err) {
            error((err as Error).message);
        }
    });

/**
 * Version command (built-in from Commander)
 * Help command (built-in from Commander)
 */

// Parse and execute
// ============================================
// Cloud Commands
// ============================================

/**
 * login command
 */
program
    .command('login')
    .description('Authenticate with Gluon Cloud')
    .action(async () => {
        try {
            if (await isAuthenticated()) {
                const credentials = await loadCredentials();
                success(`Already logged in as ${credentials?.email}`);
                return;
            }

            info('Authenticating with Gluon Cloud...');

            const { deviceCode, userCode, verificationUri, expiresIn, interval } = await cloudClient.getDeviceCode();

            console.log();
            console.log(colors.bold('  1. Open this URL in your browser:'));
            console.log(`     ${colors.cyan(verificationUri)}`);
            console.log();
            console.log(colors.bold('  2. Enter this code:'));
            console.log(`     ${colors.green(colors.bold(userCode))}`);
            console.log();
            console.log(colors.dim(`  Code expires in ${Math.floor(expiresIn / 60)} minutes.`));
            console.log();

            // Poll for token
            process.stdout.write(colors.dim('  Waiting for authorization'));
            const startTime = Date.now();
            const pollInterval = Math.max(interval, 5) * 1000;

            while (Date.now() - startTime < expiresIn * 1000) {
                await new Promise(resolve => setTimeout(resolve, pollInterval));
                process.stdout.write('.');

                try {
                    const response = await cloudClient.pollDeviceToken(deviceCode);

                    if (response.status === 'complete' && response.user && response.tokens) {
                        console.log(colors.green(' ✓'));
                        console.log();

                        // Save credentials
                        await saveCredentials({
                            accessToken: response.tokens.accessToken,
                            refreshToken: response.tokens.refreshToken,
                            expiresAt: new Date(response.tokens.expiresAt * 1000).toISOString(),
                            email: response.user.email,
                            userId: response.user.id,
                        });

                        success('Logged in successfully!');
                        console.log();
                        console.log('  Email:', colors.cyan(response.user.email));
                        console.log('  Name:', response.user.name || colors.dim('(not set)'));
                        console.log();
                        return;
                    }

                    if (response.status === 'slow_down') {
                        // Increase interval
                        await new Promise(resolve => setTimeout(resolve, 5000));
                    }
                    // status === 'pending' - continue polling
                } catch (err: any) {
                    const message = err.message || '';
                    if (message.includes('expired') || message.includes('denied')) {
                        console.log(colors.red(' ✗'));
                        console.log();
                        error(message);
                    }
                    throw err;
                }
            }

            console.log(colors.red(' ✗'));
            console.log();
            error('Authorization timed out. Please try again.');
        } catch (err: any) {
            error(err.message);
        }
    });

/**
 * logout command
 */
program
    .command('logout')
    .description('Sign out and clear credentials')
    .action(async () => {
        try {
            await clearCredentials();
            success('Logged out successfully.');
        } catch (err: any) {
            error(err.message);
        }
    });

/**
 * whoami command
 */
program
    .command('whoami')
    .description('Show current authenticated user')
    .action(async () => {
        try {
            const credentials = await loadCredentials();
            if (!credentials) {
                info('Not logged in. Run "gln login" to authenticate.');
                return;
            }

            info(`Logged in as: ${colors.cyan(credentials.email)}`);
            info(`User ID: ${colors.dim(credentials.userId)}`);

            if (await isCloudLinked()) {
                const config = await loadCloudConfig();
                info(`Linked Project: ${colors.green(config?.projectId || 'Unknown')}`);
            } else {
                info('Project state: Local only');
            }
        } catch (err: any) {
            error(err.message);
        }
    });

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
            telemetry.setCloudProjectId(cloudConfig.projectId);

            info(`Pushing telemetry to ${colors.cyan(cloudConfig.projectId)}...`);
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
            const { startDashboardServer } = await import('./dashboard/server.js');
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

program.parse();
