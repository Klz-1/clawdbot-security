/**
 * CVE Command - Check CVE status
 * Phase 5 Implementation
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { getCVEStatus } from '../monitoring/cve-checker.js';

export function registerCveCommand(program: Command): void {
  program
    .command('cve')
    .description('Check CVE status')
    .option('--json', 'Output as JSON')
    .action(async (options) => {
      try {
        console.log(chalk.bold.cyan('Checking for vulnerabilities...\n'));

        const status = await getCVEStatus();

        if (options.json) {
          console.log(JSON.stringify(status, null, 2));
          return;
        }

        // NPM packages
        console.log(chalk.bold('NPM Packages:'));
        if (status.npm.length === 0) {
          console.log(chalk.green('  ✓ No known vulnerabilities\n'));
        } else {
          status.npm.forEach(cve => {
            const severityColor = cve.severity === 'critical' || cve.severity === 'high' ? 'red' : 'yellow';
            console.log(chalk[severityColor](`  ✗ ${cve.id}: ${cve.package}`));
            console.log(chalk.dim(`    ${cve.title}`));
            console.log(chalk.dim(`    Severity: ${cve.severity.toUpperCase()}`));
            if (cve.fixAvailable) {
              console.log(chalk.green(`    Fix available: npm audit fix`));
            }
          });
          console.log();
        }

        // Python
        console.log(chalk.bold('Python:'));
        if (status.python.length === 0) {
          console.log(chalk.green('  ✓ No known vulnerabilities\n'));
        } else {
          status.python.forEach(cve => {
            console.log(chalk.yellow(`  ⚠ ${cve.id}: ${cve.package}`));
            console.log(chalk.dim(`    ${cve.title}`));
            console.log(chalk.dim(`    Current: ${cve.currentVersion}`));
          });
          console.log();
        }

        // System updates
        console.log(chalk.bold('System Packages:'));
        if (status.system.length === 0) {
          console.log(chalk.green('  ✓ All packages up to date\n'));
        } else {
          console.log(chalk.yellow(`  ⚠ ${status.system.length} packages have updates available`));
          console.log(chalk.dim(`    Run: sudo apt-get upgrade\n`));
        }

        // Summary
        if (status.totalCritical > 0 || status.totalHigh > 0) {
          console.log(chalk.red.bold(`⚠ Action Required: ${status.totalCritical} critical, ${status.totalHigh} high severity`));
          console.log(chalk.dim('Run: clawdbot-security update --apply'));
        } else {
          console.log(chalk.green('✓ Security status: Good'));
        }

      } catch (err: any) {
        console.error(chalk.red('Error:'), err.message);
        process.exit(1);
      }
    });
}
