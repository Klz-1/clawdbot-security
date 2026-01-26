import { Command } from 'commander';
import chalk from 'chalk';

export function registerDashboardCommand(program: Command): void {
  program
    .command('dashboard')
    .description('Launch security dashboard')
    .action(async () => {
      console.log(chalk.yellow('⚠  Dashboard coming in Phase 4!'));
    });
}
