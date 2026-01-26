/**
 * Profile Command - Apply security profile
 */

import { Command } from 'commander';
import chalk from 'chalk';
import {
  loadSecurityConfig,
  saveSecurityConfig,
  getDefaultSecurityConfig,
} from '../core/config.js';

export function registerProfileCommand(program: Command): void {
  program
    .command('profile <name>')
    .description('Apply security profile (basic|standard|paranoid)')
    .option('--dry-run', 'Preview changes without applying')
    .action(async (name: string, options) => {
      try {
        const validProfiles = ['basic', 'standard', 'paranoid'];

        if (!validProfiles.includes(name)) {
          console.error(
            chalk.red('Error:'),
            `Invalid profile "${name}". Choose from: ${validProfiles.join(', ')}`
          );
          process.exit(1);
        }

        let config = await loadSecurityConfig();
        if (!config) {
          config = getDefaultSecurityConfig();
        }

        if (options.dryRun) {
          console.log(chalk.bold(`Profile: ${name}`));
          console.log(
            JSON.stringify(config.profiles?.[name], null, 2)
          );
          return;
        }

        // Apply profile
        config.profile = name as any;
        await saveSecurityConfig(config);

        console.log(chalk.green('✓'), `Applied ${chalk.bold(name)} security profile`);
        console.log();
        console.log(
          chalk.dim('Run'),
          chalk.cyan('clawdbot-security status'),
          chalk.dim('to see the changes')
        );
      } catch (err: any) {
        console.error(chalk.red('Error:'), err.message);
        process.exit(1);
      }
    });
}
