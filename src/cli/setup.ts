/**
 * Setup Command - Interactive security setup wizard
 * Phase 2 - To be implemented
 */

import { Command } from 'commander';
import chalk from 'chalk';

export function registerSetupCommand(program: Command): void {
  program
    .command('setup')
    .description('Run interactive security setup wizard')
    .option('--profile <name>', 'Security profile to apply')
    .option('--non-interactive', 'Skip prompts')
    .action(async (options) => {
      console.log(chalk.yellow('⚠  Setup wizard coming in Phase 2!'));
      console.log();
      console.log('For now, you can manually apply a profile:');
      console.log(
        chalk.cyan('  clawdbot-security profile standard')
      );
    });
}
