/**
 * Harden Command - Apply security hardening to production systems
 * Phase 3 Implementation
 */

import { Command } from 'commander';
import chalk from 'chalk';
import {
  deployNginxConfig,
  deployFail2banConfig,
  deployAll,
  getDeploymentStatus,
} from '../deployment/deployer.js';
import { loadSecurityConfig } from '../core/config.js';

export function registerHardenCommand(program: Command): void {
  program
    .command('harden')
    .description('Apply security hardening to production systems')
    .option('--nginx', 'Harden nginx only')
    .option('--fail2ban', 'Configure fail2ban only')
    .option('--hooks', 'Install security hooks only')
    .option('--dry-run', 'Preview changes without applying')
    .option('--force', 'Force deployment even if validations fail')
    .option('--skip-backup', 'Skip backup creation (not recommended)')
    .option('--profile <name>', 'Security profile to use (basic/standard/paranoid)')
    .action(async (options) => {
      try {
        console.log(chalk.bold.cyan('🔒 Clawdbot Security Hardening\n'));

        // Determine profile
        let profile = options.profile;
        if (!profile) {
          const securityConfig = await loadSecurityConfig();
          profile = securityConfig?.profile || 'standard';
        }

        console.log(chalk.dim(`Profile: ${profile}`));
        console.log(chalk.dim(`Dry run: ${options.dryRun ? 'Yes' : 'No'}\n`));

        // Check deployment status
        const status = await getDeploymentStatus();

        if (!status.sudo && !options.dryRun) {
          console.log(chalk.red('✗ sudo access required'));
          console.log(chalk.dim('  Run with sudo or configure passwordless sudo'));
          process.exit(1);
        }

        // Determine what to deploy
        const deployNginx = options.nginx || (!options.fail2ban && !options.hooks);
        const deployFail2ban = options.fail2ban || (!options.nginx && !options.hooks);
        const deployHooks = options.hooks || (!options.nginx && !options.fail2ban);

        const deployOptions = {
          dryRun: options.dryRun,
          force: options.force,
          skipBackup: options.skipBackup,
        };

        // Deploy nginx
        if (deployNginx) {
          if (!status.nginx.installed) {
            console.log(chalk.yellow('⚠ nginx not installed - skipping'));
          } else {
            console.log(chalk.bold('nginx Hardening:'));

            if (status.nginx.deployed && !options.dryRun) {
              console.log(chalk.yellow('  ⚠ nginx already hardened, will update configuration'));
            }

            const result = await deployNginxConfig(profile, deployOptions);

            if (result.success) {
              console.log(chalk.green(`  ✓ ${result.message}`));
              if (result.backup && !options.dryRun) {
                console.log(chalk.dim(`    Backup: ${result.backup.id}`));
              }
            } else {
              console.log(chalk.red(`  ✗ ${result.error || result.message}`));
              if (!options.force) {
                process.exit(1);
              }
            }
            console.log();
          }
        }

        // Deploy fail2ban
        if (deployFail2ban) {
          if (!status.fail2ban.installed) {
            console.log(chalk.yellow('⚠ fail2ban not installed - skipping'));
            console.log(chalk.dim('  Install: sudo apt-get install fail2ban'));
          } else {
            console.log(chalk.bold('fail2ban Configuration:'));

            if (status.fail2ban.deployed && !options.dryRun) {
              console.log(chalk.yellow('  ⚠ fail2ban already configured, will update'));
            }

            const result = await deployFail2banConfig(profile, deployOptions);

            if (result.success) {
              console.log(chalk.green(`  ✓ ${result.message}`));
              if (result.backup && !options.dryRun) {
                console.log(chalk.dim(`    Backup: ${result.backup.id}`));
              }
            } else {
              console.log(chalk.red(`  ✗ ${result.error || result.message}`));
              if (!options.force) {
                process.exit(1);
              }
            }
            console.log();
          }
        }

        // Deploy security hooks
        if (deployHooks) {
          console.log(chalk.bold('Security Hooks:'));
          console.log(chalk.yellow('  ⚠ Hook installation coming soon (Phase 3)'));
          console.log();
        }

        // Summary
        if (options.dryRun) {
          console.log(chalk.cyan('Dry run complete. No changes were made.'));
          console.log(chalk.dim('Run without --dry-run to apply changes.'));
        } else {
          console.log(chalk.green.bold('✓ Hardening complete!'));
          console.log();
          console.log(chalk.dim('Next steps:'));
          console.log(chalk.cyan('  • Verify services: clawdbot-security status'));
          console.log(chalk.cyan('  • View security score: clawdbot-security score'));
          console.log(chalk.cyan('  • Check deployment: systemctl status nginx fail2ban'));
        }

      } catch (err: any) {
        console.error(chalk.red('Error:'), err.message);
        process.exit(1);
      }
    });
}
