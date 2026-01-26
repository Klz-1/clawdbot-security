import { Command } from 'commander';
import chalk from 'chalk';

export function registerAuditCommand(program: Command): void {
  program
    .command('audit')
    .description('Run security audit')
    .option('--deep', 'Run deep audit')
    .action(async () => {
      console.log(chalk.yellow('⚠  Audit features coming soon!'));
    });
}
