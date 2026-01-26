/**
 * Setup Command - Interactive security setup wizard
 * Phase 2 Implementation
 */

import { Command } from 'commander';
import { runSecuritySetupWizard } from '../wizard/setup.js';

export function registerSetupCommand(program: Command): void {
  program
    .command('setup')
    .description('Run interactive security setup wizard')
    .option('--profile <name>', 'Security profile to apply')
    .option('--non-interactive', 'Skip prompts')
    .option('--nginx', 'Apply nginx hardening')
    .option('--fail2ban', 'Configure fail2ban')
    .action(async (options) => {
      try {
        await runSecuritySetupWizard(options);
      } catch (err: any) {
        console.error('Setup failed:', err.message);
        process.exit(1);
      }
    });
}
