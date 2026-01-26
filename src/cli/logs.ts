import { Command } from 'commander';
import chalk from 'chalk';

export function registerLogsCommand(program: Command): void {
  program
    .command('logs')
    .description('View security logs')
    .action(async () => {
      console.log(chalk.yellow('⚠  Log viewing coming in Phase 4!'));
    });
}
