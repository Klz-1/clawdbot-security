import { Command } from 'commander';
import chalk from 'chalk';

export function registerUpdateCommand(program: Command): void {
  program
    .command('update')
    .description('Check for security updates')
    .action(async () => {
      console.log(chalk.yellow('⚠  Update features coming in Phase 5!'));
    });
}
