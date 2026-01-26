import { Command } from 'commander';
import chalk from 'chalk';

export function registerCveCommand(program: Command): void {
  program
    .command('cve')
    .description('Check CVE status')
    .action(async () => {
      console.log(chalk.yellow('⚠  CVE tracking coming in Phase 5!'));
    });
}
