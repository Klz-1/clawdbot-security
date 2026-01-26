/**
 * Update Command - Check and apply security updates
 * Phase 5 Implementation
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { exec } from 'child_process';
import { promisify } from 'util';
import { getCVEStatus } from '../monitoring/cve-checker.js';

const execAsync = promisify(exec);

export function registerUpdateCommand(program: Command): void {
  program
    .command('update')
    .description('Check and apply security updates')
    .option('--check', 'Check for updates only')
    .option('--apply', 'Apply available updates')
    .option('--dry-run', 'Show what would be updated')
    .action(async (options) => {
      try {
        const status = await getCVEStatus();

        if (options.check || options.dryRun || (!options.apply)) {
          console.log(chalk.bold.cyan('Security Updates Available:\n'));

          // NPM updates
          if (status.npm.length > 0) {
            console.log(chalk.bold('NPM Packages:'));
            status.npm.forEach(cve => {
              const color = cve.severity === 'critical' || cve.severity === 'high' ? 'red' : 'yellow';
              console.log(chalk[color](`  • ${cve.package}: ${cve.severity}`));
            });
            if (status.npm.some(c => c.fixAvailable)) {
              console.log(chalk.dim('  Run: npm audit fix'));
            }
            console.log();
          }

          // Python updates
          if (status.python.length > 0) {
            console.log(chalk.bold('Python:'));
            status.python.forEach(cve => {
              console.log(chalk.yellow(`  • ${cve.id}: ${cve.package}`));
            });
            console.log(chalk.dim('  Check: sudo apt-get update && apt list --upgradable'));
            console.log();
          }

          // System updates
          if (status.system.length > 0) {
            console.log(chalk.bold('System Packages:'));
            console.log(chalk.yellow(`  • ${status.system.length} packages`));
            status.system.slice(0, 5).forEach(pkg => {
              console.log(chalk.dim(`    ${pkg.package}: ${pkg.currentVersion} → ${pkg.availableVersion}`));
            });
            if (status.system.length > 5) {
              console.log(chalk.dim(`    ... and ${status.system.length - 5} more`));
            }
            console.log();
          }

          if (status.npm.length === 0 && status.python.length === 0 && status.system.length === 0) {
            console.log(chalk.green('✓ All packages up to date!'));
          } else if (!options.apply) {
            console.log(chalk.cyan('Run with --apply to install updates'));
          }
          return;
        }

        // Apply updates
        if (options.apply) {
          console.log(chalk.bold.cyan('Applying security updates...\n'));

          // NPM updates
          if (status.npm.length > 0) {
            console.log(chalk.bold('Updating NPM packages...'));
            try {
              await execAsync('npm audit fix --force');
              console.log(chalk.green('✓ NPM packages updated\n'));
            } catch (err) {
              console.log(chalk.yellow('⚠ Some NPM updates failed (may require manual intervention)\n'));
            }
          }

          // System updates
          if (status.system.length > 0) {
            console.log(chalk.bold('Updating system packages...'));
            console.log(chalk.dim('This requires sudo access'));
            try {
              await execAsync('sudo apt-get update && sudo apt-get upgrade -y');
              console.log(chalk.green('✓ System packages updated\n'));
            } catch (err) {
              console.log(chalk.red('✗ System update failed (check sudo access)\n'));
            }
          }

          console.log(chalk.green.bold('✓ Security updates complete!'));
          console.log(chalk.dim('Run: clawdbot-security cve'));
        }

      } catch (err: any) {
        console.error(chalk.red('Error:'), err.message);
        process.exit(1);
      }
    });
}
