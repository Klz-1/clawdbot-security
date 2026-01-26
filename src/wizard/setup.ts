/**
 * Security Setup Wizard
 * Interactive wizard using @clack/prompts
 */

import * as clack from '@clack/prompts';
import chalk from 'chalk';
import {
  loadClawdbotConfig,
  loadSecurityConfig,
  saveSecurityConfig,
  getDefaultSecurityConfig,
  isClawdbotInstalled,
} from '../core/config.js';
import type { SecurityProfile } from '../core/types.js';
import { calculateSecurityScore } from '../scoring/calculator.js';
import { detectNginx, applyNginxHardening } from '../utils/nginx.js';
import { detectFail2ban, installFail2ban, applyFail2banConfig } from '../utils/fail2ban.js';

export interface SetupOptions {
  profile?: string;
  nonInteractive?: boolean;
  nginx?: boolean;
  fail2ban?: boolean;
}

export async function runSecuritySetupWizard(options: SetupOptions): Promise<void> {
  // Check if Clawdbot is installed
  const installed = await isClawdbotInstalled();
  if (!installed) {
    clack.log.error('Clawdbot installation not found at ~/.clawdbot/');
    clack.log.info('Install Clawdbot first: npm install -g clawdbot');
    process.exit(1);
  }

  // Non-interactive mode
  if (options.nonInteractive) {
    await runNonInteractiveSetup(options);
    return;
  }

  // Interactive mode
  clack.intro(chalk.bold.cyan('🔐 Clawdbot Security Setup'));

  try {
    // Step 1: Profile Selection
    const profile = await clack.select({
      message: 'Choose your security level',
      options: [
        {
          value: 'basic',
          label: 'Basic',
          hint: 'Consumer-friendly, minimal friction',
        },
        {
          value: 'standard',
          label: 'Standard (Recommended)',
          hint: 'Balanced security and usability',
        },
        {
          value: 'paranoid',
          label: 'Paranoid',
          hint: 'Maximum security, some trade-offs',
        },
      ],
      initialValue: 'standard',
    });

    if (clack.isCancel(profile)) {
      clack.cancel('Security setup cancelled');
      process.exit(0);
    }

    // Step 2: Detect nginx
    const spinner = clack.spinner();
    spinner.start('Detecting system services...');

    const hasNginx = await detectNginx();
    const hasFail2ban = await detectFail2ban();

    spinner.stop('System detection complete');

    let applyNginx = false;
    let applyFail2ban = false;

    if (hasNginx) {
      const nginxResponse = await clack.confirm({
        message: 'Apply nginx security hardening?',
        initialValue: true,
      });

      if (clack.isCancel(nginxResponse)) {
        clack.cancel('Setup cancelled');
        process.exit(0);
      }

      applyNginx = nginxResponse as boolean;
    } else {
      clack.log.warn('nginx not detected - skipping nginx hardening');
    }

    // Step 3: fail2ban
    if (hasFail2ban) {
      const fail2banResponse = await clack.confirm({
        message: 'Configure fail2ban for Clawdbot protection?',
        initialValue: true,
      });

      if (clack.isCancel(fail2banResponse)) {
        clack.cancel('Setup cancelled');
        process.exit(0);
      }

      applyFail2ban = fail2banResponse as boolean;
    } else {
      const installResponse = await clack.confirm({
        message: 'fail2ban not detected. Install it now? (requires sudo)',
        initialValue: false,
      });

      if (clack.isCancel(installResponse)) {
        clack.cancel('Setup cancelled');
        process.exit(0);
      }

      if (installResponse) {
        spinner.start('Installing fail2ban...');
        try {
          await installFail2ban();
          spinner.stop('fail2ban installed successfully');
          applyFail2ban = true;
        } catch (err: any) {
          spinner.stop('Failed to install fail2ban');
          clack.log.error(err.message);
          applyFail2ban = false;
        }
      }
    }

    // Step 4: Apply Configuration
    spinner.start('Applying security configuration...');

    try {
      // Apply security profile
      let config = await loadSecurityConfig();
      if (!config) {
        config = getDefaultSecurityConfig();
      }
      config.profile = profile as SecurityProfile;

      try {
        await saveSecurityConfig(config);
        spinner.message('Security profile configured');
      } catch (err: any) {
        if (err.code === 'EACCES') {
          spinner.message('Using standalone security config (main config is read-only)');
        } else {
          throw err;
        }
      }

      // Apply nginx hardening
      if (applyNginx) {
        spinner.message('Applying nginx hardening...');
        await applyNginxHardening(profile as string);
        spinner.message('nginx hardening applied');
      }

      // Apply fail2ban configuration
      if (applyFail2ban) {
        spinner.message('Configuring fail2ban...');
        await applyFail2banConfig(profile as string);
        spinner.message('fail2ban configured');
      }

      spinner.stop('Configuration complete');

      // Step 5: Calculate final score
      const clawdbotConfig = await loadClawdbotConfig();
      const scoreResult = await calculateSecurityScore(clawdbotConfig);

      // Success summary
      clack.outro(
        chalk.green.bold('✓ Security setup complete!') +
          '\n\n' +
          chalk.bold('Security Score: ') +
          chalk.green(`${scoreResult.score}/100\n`) +
          '\n' +
          chalk.dim('Next steps:') +
          '\n' +
          chalk.cyan('  • Run: clawdbot-security status') +
          '\n' +
          chalk.cyan('  • View: clawdbot-security score') +
          '\n' +
          chalk.cyan('  • Audit: clawdbot-security audit')
      );
    } catch (err: any) {
      spinner.stop('Configuration failed');
      throw err;
    }
  } catch (err: any) {
    clack.log.error(err.message);
    clack.outro(chalk.red('Setup failed'));
    process.exit(1);
  }
}

async function runNonInteractiveSetup(options: SetupOptions): Promise<void> {
  const profile = options.profile || 'standard';

  console.log(chalk.bold('Running non-interactive security setup...'));
  console.log(chalk.dim(`Profile: ${profile}`));

  // Apply security profile
  let config = await loadSecurityConfig();
  if (!config) {
    config = getDefaultSecurityConfig();
  }
  config.profile = profile as SecurityProfile;

  try {
    await saveSecurityConfig(config);
    console.log(chalk.green('✓'), 'Security profile applied');
  } catch (err: any) {
    if (err.code === 'EACCES') {
      console.log(chalk.yellow('⚠'), 'Config file is read-only, using standalone security config');
      console.log(chalk.dim('  Security settings saved to ~/.clawdbot/security.json'));
    } else {
      throw err;
    }
  }

  // Apply nginx if requested and available
  if (options.nginx !== false) {
    const hasNginx = await detectNginx();
    if (hasNginx) {
      await applyNginxHardening(profile);
      console.log(chalk.green('✓'), 'nginx hardening applied');
    }
  }

  // Apply fail2ban if requested and available
  if (options.fail2ban !== false) {
    const hasFail2ban = await detectFail2ban();
    if (hasFail2ban) {
      await applyFail2banConfig(profile);
      console.log(chalk.green('✓'), 'fail2ban configured');
    }
  }

  // Calculate final score
  const clawdbotConfig = await loadClawdbotConfig();
  const scoreResult = await calculateSecurityScore(clawdbotConfig);

  console.log();
  console.log(
    chalk.bold('Security Score:'),
    chalk.green(`${scoreResult.score}/100`)
  );
  console.log();
}
