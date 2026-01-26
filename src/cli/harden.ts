import { Command } from 'commander';
import chalk from 'chalk';

export function registerHardenCommand(program: Command): void {
  program
    .command('harden')
    .description('Apply security hardening')
    .option('--nginx', 'Harden nginx only')
    .option('--fail2ban', 'Configure fail2ban only')
    .option('--hooks', 'Install security hooks only')
    .action(async () => {
      console.log(chalk.yellow('⚠  Hardening features coming in Phase 3!'));
    });
}
