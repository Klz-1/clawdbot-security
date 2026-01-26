/**
 * Production Deployment System
 * Deploys nginx and fail2ban configurations to production with validation
 */

import { readFile, access } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';
import {
  backupNginxConfig,
  backupFail2banConfig,
  restoreNginxBackup,
  restoreFail2banBackup,
  type BackupInfo,
} from './backup.js';

const execAsync = promisify(exec);

export interface DeploymentResult {
  success: boolean;
  component: 'nginx' | 'fail2ban';
  message: string;
  backup?: BackupInfo;
  error?: string;
}

export interface DeploymentOptions {
  dryRun?: boolean;
  force?: boolean;
  skipBackup?: boolean;
  skipValidation?: boolean;
}

const CLAWDBOT_DIR = join(homedir(), '.clawdbot');

/**
 * Check if nginx is installed
 */
async function hasNginx(): Promise<boolean> {
  try {
    await execAsync('which nginx');
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if fail2ban is installed
 */
async function hasFail2ban(): Promise<boolean> {
  try {
    await execAsync('which fail2ban-client');
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if we have sudo access
 */
async function checkSudoAccess(): Promise<boolean> {
  try {
    await execAsync('sudo -n true');
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate nginx configuration
 */
async function validateNginxConfig(): Promise<{ valid: boolean; error?: string }> {
  try {
    const { stderr } = await execAsync('sudo nginx -t');
    // nginx -t outputs to stderr even on success
    if (stderr.includes('syntax is ok') && stderr.includes('test is successful')) {
      return { valid: true };
    }
    return { valid: false, error: stderr };
  } catch (err: any) {
    return { valid: false, error: err.message };
  }
}

/**
 * Validate fail2ban configuration
 */
async function validateFail2banConfig(): Promise<{ valid: boolean; error?: string }> {
  try {
    // Check if fail2ban service is running
    await execAsync('sudo systemctl is-active fail2ban');

    // Test configuration
    const { stdout } = await execAsync('sudo fail2ban-client -t');
    if (stdout.includes('OK') || !stdout.includes('ERROR')) {
      return { valid: true };
    }
    return { valid: false, error: stdout };
  } catch (err: any) {
    // fail2ban might not be running yet, check config syntax only
    try {
      await execAsync('sudo fail2ban-client -t');
      return { valid: true };
    } catch {
      return { valid: false, error: err.message };
    }
  }
}

/**
 * Deploy nginx configuration to production
 */
export async function deployNginxConfig(
  profile: string,
  options: DeploymentOptions = {}
): Promise<DeploymentResult> {
  const result: DeploymentResult = {
    success: false,
    component: 'nginx',
    message: '',
  };

  try {
    // Pre-flight checks
    if (!(await hasNginx())) {
      result.error = 'nginx is not installed';
      result.message = 'Install nginx first: sudo apt-get install nginx';
      return result;
    }

    if (!(await checkSudoAccess())) {
      result.error = 'sudo access required';
      result.message = 'Run with sudo or configure passwordless sudo';
      return result;
    }

    // Check if source config exists
    const sourceConfig = join(CLAWDBOT_DIR, 'nginx', 'clawdbot-security.conf');
    try {
      await access(sourceConfig);
    } catch {
      result.error = 'Configuration not found';
      result.message = `Run setup first: clawdbot-security setup --profile=${profile}`;
      return result;
    }

    if (options.dryRun) {
      const config = await readFile(sourceConfig, 'utf-8');
      result.success = true;
      result.message = `Dry run: Would deploy nginx configuration\n\n${config}`;
      return result;
    }

    // Create backup
    if (!options.skipBackup) {
      try {
        result.backup = await backupNginxConfig();
      } catch (err: any) {
        result.error = `Backup failed: ${err.message}`;
        result.message = 'Cannot proceed without backup';
        return result;
      }
    }

    // Deploy configuration
    try {
      const destPath = '/etc/nginx/conf.d/clawdbot-security.conf';
      await execAsync(`sudo cp ${sourceConfig} ${destPath}`);
      await execAsync(`sudo chmod 644 ${destPath}`);
    } catch (err: any) {
      result.error = `Deployment failed: ${err.message}`;

      // Attempt rollback if we have a backup
      if (result.backup && !options.skipBackup) {
        try {
          await restoreNginxBackup(result.backup);
          result.message = 'Deployment failed, rolled back to previous configuration';
        } catch {
          result.message = 'Deployment failed, rollback also failed';
        }
      }
      return result;
    }

    // Validate configuration
    if (!options.skipValidation) {
      const validation = await validateNginxConfig();
      if (!validation.valid) {
        result.error = `Validation failed: ${validation.error}`;

        // Rollback
        if (result.backup && !options.skipBackup) {
          try {
            await restoreNginxBackup(result.backup);
            result.message = 'Configuration invalid, rolled back';
          } catch {
            result.message = 'Configuration invalid, rollback failed';
          }
        }
        return result;
      }
    }

    // Reload nginx
    try {
      await execAsync('sudo systemctl reload nginx');
    } catch (err: any) {
      result.error = `Reload failed: ${err.message}`;

      // Rollback
      if (result.backup && !options.skipBackup) {
        try {
          await restoreNginxBackup(result.backup);
          result.message = 'Reload failed, rolled back';
        } catch {
          result.message = 'Reload failed, rollback failed';
        }
      }
      return result;
    }

    // Success!
    result.success = true;
    result.message = `nginx hardening deployed successfully (${profile} profile)`;
    return result;

  } catch (err: any) {
    result.error = err.message;
    result.message = 'Unexpected error during deployment';
    return result;
  }
}

/**
 * Deploy fail2ban configuration to production
 */
export async function deployFail2banConfig(
  profile: string,
  options: DeploymentOptions = {}
): Promise<DeploymentResult> {
  const result: DeploymentResult = {
    success: false,
    component: 'fail2ban',
    message: '',
  };

  try {
    // Pre-flight checks
    if (!(await hasFail2ban())) {
      result.error = 'fail2ban is not installed';
      result.message = 'Install fail2ban first: sudo apt-get install fail2ban';
      return result;
    }

    if (!(await checkSudoAccess())) {
      result.error = 'sudo access required';
      result.message = 'Run with sudo or configure passwordless sudo';
      return result;
    }

    // Check if source configs exist
    const jailConfig = join(CLAWDBOT_DIR, 'fail2ban', 'clawdbot.local');
    const filterConfig = join(CLAWDBOT_DIR, 'fail2ban', 'clawdbot-nginx.conf');

    try {
      await access(jailConfig);
      await access(filterConfig);
    } catch {
      result.error = 'Configuration not found';
      result.message = `Run setup first: clawdbot-security setup --profile=${profile}`;
      return result;
    }

    if (options.dryRun) {
      const jail = await readFile(jailConfig, 'utf-8');
      const filter = await readFile(filterConfig, 'utf-8');
      result.success = true;
      result.message = `Dry run: Would deploy fail2ban configuration\n\nJail:\n${jail}\n\nFilters:\n${filter}`;
      return result;
    }

    // Create backup
    if (!options.skipBackup) {
      try {
        result.backup = await backupFail2banConfig();
      } catch (err: any) {
        result.error = `Backup failed: ${err.message}`;
        result.message = 'Cannot proceed without backup';
        return result;
      }
    }

    // Deploy jail configuration
    try {
      const jailDest = '/etc/fail2ban/jail.d/clawdbot.local';
      await execAsync(`sudo cp ${jailConfig} ${jailDest}`);
      await execAsync(`sudo chmod 644 ${jailDest}`);
    } catch (err: any) {
      result.error = `Jail deployment failed: ${err.message}`;
      return result;
    }

    // Deploy filter configuration
    try {
      const filterDest = '/etc/fail2ban/filter.d/clawdbot-nginx.conf';
      await execAsync(`sudo cp ${filterConfig} ${filterDest}`);
      await execAsync(`sudo chmod 644 ${filterDest}`);
    } catch (err: any) {
      result.error = `Filter deployment failed: ${err.message}`;

      // Rollback
      if (result.backup && !options.skipBackup) {
        try {
          await restoreFail2banBackup(result.backup);
          result.message = 'Deployment failed, rolled back';
        } catch {
          result.message = 'Deployment failed, rollback failed';
        }
      }
      return result;
    }

    // Validate configuration (if fail2ban is running)
    if (!options.skipValidation) {
      const validation = await validateFail2banConfig();
      if (!validation.valid) {
        result.error = `Validation failed: ${validation.error}`;

        // Rollback
        if (result.backup && !options.skipBackup) {
          try {
            await restoreFail2banBackup(result.backup);
            result.message = 'Configuration invalid, rolled back';
          } catch {
            result.message = 'Configuration invalid, rollback failed';
          }
        }
        return result;
      }
    }

    // Restart fail2ban
    try {
      await execAsync('sudo systemctl restart fail2ban');

      // Wait a moment for service to start
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Verify it's running
      await execAsync('sudo systemctl is-active fail2ban');
    } catch (err: any) {
      result.error = `Restart failed: ${err.message}`;

      // Rollback
      if (result.backup && !options.skipBackup) {
        try {
          await restoreFail2banBackup(result.backup);
          result.message = 'Restart failed, rolled back';
        } catch {
          result.message = 'Restart failed, rollback failed';
        }
      }
      return result;
    }

    // Success!
    result.success = true;
    result.message = `fail2ban configured successfully (${profile} profile)`;
    return result;

  } catch (err: any) {
    result.error = err.message;
    result.message = 'Unexpected error during deployment';
    return result;
  }
}

/**
 * Deploy all security configurations
 */
export async function deployAll(
  profile: string,
  options: DeploymentOptions = {}
): Promise<DeploymentResult[]> {
  const results: DeploymentResult[] = [];

  // Deploy nginx if installed
  if (await hasNginx()) {
    results.push(await deployNginxConfig(profile, options));
  }

  // Deploy fail2ban if installed
  if (await hasFail2ban()) {
    results.push(await deployFail2banConfig(profile, options));
  }

  return results;
}

/**
 * Get deployment status
 */
export async function getDeploymentStatus(): Promise<{
  nginx: { installed: boolean; deployed: boolean; version?: string };
  fail2ban: { installed: boolean; deployed: boolean; running?: boolean };
  sudo: boolean;
}> {
  const status = {
    nginx: { installed: false, deployed: false, version: undefined as string | undefined },
    fail2ban: { installed: false, deployed: false, running: undefined as boolean | undefined },
    sudo: false,
  };

  // Check nginx
  if (await hasNginx()) {
    status.nginx.installed = true;

    try {
      const { stderr } = await execAsync('nginx -v');
      const match = stderr.match(/nginx\/([0-9.]+)/);
      if (match) {
        status.nginx.version = match[1];
      }
    } catch {
      // Version detection failed
    }

    try {
      await access('/etc/nginx/conf.d/clawdbot-security.conf');
      status.nginx.deployed = true;
    } catch {
      status.nginx.deployed = false;
    }
  }

  // Check fail2ban
  if (await hasFail2ban()) {
    status.fail2ban.installed = true;

    try {
      await access('/etc/fail2ban/jail.d/clawdbot.local');
      status.fail2ban.deployed = true;
    } catch {
      status.fail2ban.deployed = false;
    }

    try {
      await execAsync('sudo systemctl is-active fail2ban');
      status.fail2ban.running = true;
    } catch {
      status.fail2ban.running = false;
    }
  }

  // Check sudo
  status.sudo = await checkSudoAccess();

  return status;
}
