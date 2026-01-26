import { Command } from 'commander';
import chalk from 'chalk';

export function registerReportCommand(program: Command): void {
  program
    .command('report')
    .description('Generate security report')
    .action(async () => {
      console.log(chalk.yellow('⚠  Reporting coming in Phase 6!'));
    });
}
