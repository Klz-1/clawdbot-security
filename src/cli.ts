#!/usr/bin/env node
/**
 * Clawdbot Security Manager - CLI Entry Point
 *
 * Standalone security management tool for Clawdbot installations.
 * Can be used alongside existing Clawdbot without modification.
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { registerStatusCommand } from './cli/status.js';
import { registerProfileCommand } from './cli/profile.js';
import { registerScoreCommand } from './cli/score.js';
import { registerSetupCommand } from './cli/setup.js';
import { registerHardenCommand } from './cli/harden.js';
import { registerAuditCommand } from './cli/audit.js';
import { registerUpdateCommand } from './cli/update.js';
import { registerCveCommand } from './cli/cve.js';
import { registerLogsCommand } from './cli/logs.js';
import { registerDashboardCommand } from './cli/dashboard.js';
import { registerReportCommand } from './cli/report.js';

const program = new Command();

program
  .name('clawdbot-security')
  .description('Comprehensive security management for Clawdbot installations')
  .version('0.1.0')
  .addHelpText('after', `
${chalk.bold('Examples:')}
  $ clawdbot-security status              # Show security overview
  $ clawdbot-security setup               # Run interactive setup wizard
  $ clawdbot-security score               # Calculate security score
  $ clawdbot-security audit               # Run security audit
  $ clawdbot-security harden              # Apply security hardening

${chalk.bold('For more help:')}
  $ clawdbot-security <command> --help

${chalk.dim('Documentation: https://github.com/clawdbot-security/clawdbot-security')}
  `);

// Register all commands
registerStatusCommand(program);
registerProfileCommand(program);
registerScoreCommand(program);
registerSetupCommand(program);
registerHardenCommand(program);
registerAuditCommand(program);
registerUpdateCommand(program);
registerCveCommand(program);
registerLogsCommand(program);
registerDashboardCommand(program);
registerReportCommand(program);

// Error handling
program.exitOverride();

try {
  await program.parseAsync(process.argv);
} catch (err: any) {
  if (err.code === 'commander.help' || err.code === 'commander.version') {
    process.exit(0);
  }

  console.error(chalk.red('Error:'), err.message);
  process.exit(1);
}
