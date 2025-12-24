/**
 * Gluon CLI
 *
 * Command-line interface for the Gluon security telemetry platform.
 * Refactored to use modular command structure.
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
import { registerInitCommand } from './commands/init.js';
import { registerRunCommand } from './commands/run.js';
import { registerStatusCommand } from './commands/status.js';
import { registerConfigCommand } from './commands/config.js';
import { registerSbomCommand } from './commands/sbom.js';
import { registerAuthCommands } from './commands/auth.js';
import { registerProjectCommands } from './commands/project.js';
import { registerPushCommand } from './commands/push.js';
import { registerDashboardCommand } from './commands/dashboard.js';

const program = new Command();

program
    .name('gln')
    .description('Runtime Security Telemetry for Modern Applications')
    .version('1.0.0')
    .option('-q, --quiet', 'Suppress Gluon output')
    .option('-v, --verbose', 'Show detailed output');

// Register all command modules
registerInitCommand(program);
registerRunCommand(program);
registerStatusCommand(program);
registerConfigCommand(program);
registerSbomCommand(program);
registerAuthCommands(program);
registerProjectCommands(program);
registerPushCommand(program);
registerDashboardCommand(program);

program.parse();
