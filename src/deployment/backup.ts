/**
 * Backup and Rollback System
 * Creates timestamped backups before applying configuration changes
 */

import { readFile, writeFile, mkdir, access, copyFile } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export interface BackupInfo {
  id: string;
  timestamp: string;
  type: 'nginx' | 'fail2ban' | 'full';
  files: string[];
  location: string;
}

const BACKUP_DIR = join(homedir(), '.clawdbot', 'backups');

/**
 * Create a backup directory if it doesn't exist
 */
async function ensureBackupDir(): Promise<void> {
  try {
    await mkdir(BACKUP_DIR, { recursive: true });
  } catch {
    // Directory already exists
  }
}

/**
 * Generate backup ID from timestamp
 */
function generateBackupId(): string {
  const now = new Date();
  return now.toISOString().replace(/[:.]/g, '-').split('T')[0] + '-' +
         now.getTime().toString().slice(-6);
}

/**
 * Backup nginx configuration
 */
export async function backupNginxConfig(): Promise<BackupInfo> {
  await ensureBackupDir();

  const backupId = generateBackupId();
  const backupPath = join(BACKUP_DIR, `nginx-${backupId}`);

  await mkdir(backupPath, { recursive: true });

  const files: string[] = [];

  // Backup main nginx config
  try {
    await copyFile('/etc/nginx/nginx.conf', join(backupPath, 'nginx.conf'));
    files.push('/etc/nginx/nginx.conf');
  } catch {
    // File may not exist or no permissions
  }

  // Backup conf.d directory
  try {
    await execAsync(`sudo cp -r /etc/nginx/conf.d ${backupPath}/conf.d`);
    files.push('/etc/nginx/conf.d/');
  } catch {
    // Directory may not exist
  }

  // Backup clawdbot-specific config if it exists
  try {
    await copyFile(
      '/etc/nginx/conf.d/clawdbot-security.conf',
      join(backupPath, 'clawdbot-security.conf')
    );
    files.push('/etc/nginx/conf.d/clawdbot-security.conf');
  } catch {
    // File doesn't exist yet (first deployment)
  }

  return {
    id: backupId,
    timestamp: new Date().toISOString(),
    type: 'nginx',
    files,
    location: backupPath,
  };
}

/**
 * Backup fail2ban configuration
 */
export async function backupFail2banConfig(): Promise<BackupInfo> {
  await ensureBackupDir();

  const backupId = generateBackupId();
  const backupPath = join(BACKUP_DIR, `fail2ban-${backupId}`);

  await mkdir(backupPath, { recursive: true });

  const files: string[] = [];

  // Backup jail.d directory
  try {
    await execAsync(`sudo cp -r /etc/fail2ban/jail.d ${backupPath}/jail.d`);
    files.push('/etc/fail2ban/jail.d/');
  } catch {
    // Directory may not exist
  }

  // Backup filter.d directory
  try {
    await execAsync(`sudo cp -r /etc/fail2ban/filter.d ${backupPath}/filter.d`);
    files.push('/etc/fail2ban/filter.d/');
  } catch {
    // Directory may not exist
  }

  // Backup clawdbot-specific files if they exist
  try {
    await copyFile(
      '/etc/fail2ban/jail.d/clawdbot.local',
      join(backupPath, 'clawdbot.local')
    );
    files.push('/etc/fail2ban/jail.d/clawdbot.local');
  } catch {
    // File doesn't exist yet
  }

  return {
    id: backupId,
    timestamp: new Date().toISOString(),
    type: 'fail2ban',
    files,
    location: backupPath,
  };
}

/**
 * Create full system backup (nginx + fail2ban)
 */
export async function createFullBackup(): Promise<BackupInfo> {
  const nginxBackup = await backupNginxConfig();
  const fail2banBackup = await backupFail2banConfig();

  return {
    id: generateBackupId(),
    timestamp: new Date().toISOString(),
    type: 'full',
    files: [...nginxBackup.files, ...fail2banBackup.files],
    location: BACKUP_DIR,
  };
}

/**
 * Restore nginx configuration from backup
 */
export async function restoreNginxBackup(backupInfo: BackupInfo): Promise<void> {
  if (backupInfo.type !== 'nginx' && backupInfo.type !== 'full') {
    throw new Error('Invalid backup type for nginx restore');
  }

  try {
    // Restore main config if it was backed up
    const mainConfig = join(backupInfo.location, 'nginx.conf');
    try {
      await access(mainConfig);
      await execAsync(`sudo cp ${mainConfig} /etc/nginx/nginx.conf`);
    } catch {
      // Main config wasn't backed up
    }

    // Restore conf.d directory if it was backed up
    const confDir = join(backupInfo.location, 'conf.d');
    try {
      await access(confDir);
      await execAsync(`sudo cp -r ${confDir}/* /etc/nginx/conf.d/`);
    } catch {
      // conf.d wasn't backed up
    }

    // Restore clawdbot-specific config
    const clawdbotConfig = join(backupInfo.location, 'clawdbot-security.conf');
    try {
      await access(clawdbotConfig);
      await execAsync(`sudo cp ${clawdbotConfig} /etc/nginx/conf.d/clawdbot-security.conf`);
    } catch {
      // Clawdbot config wasn't backed up, may need to remove it
      try {
        await execAsync('sudo rm -f /etc/nginx/conf.d/clawdbot-security.conf');
      } catch {
        // File doesn't exist
      }
    }

    // Validate and reload
    await execAsync('sudo nginx -t');
    await execAsync('sudo systemctl reload nginx');

  } catch (err: any) {
    throw new Error(`Failed to restore nginx backup: ${err.message}`);
  }
}

/**
 * Restore fail2ban configuration from backup
 */
export async function restoreFail2banBackup(backupInfo: BackupInfo): Promise<void> {
  if (backupInfo.type !== 'fail2ban' && backupInfo.type !== 'full') {
    throw new Error('Invalid backup type for fail2ban restore');
  }

  try {
    // Restore jail.d directory
    const jailDir = join(backupInfo.location, 'jail.d');
    try {
      await access(jailDir);
      await execAsync(`sudo cp -r ${jailDir}/* /etc/fail2ban/jail.d/`);
    } catch {
      // jail.d wasn't backed up
    }

    // Restore filter.d directory
    const filterDir = join(backupInfo.location, 'filter.d');
    try {
      await access(filterDir);
      await execAsync(`sudo cp -r ${filterDir}/* /etc/fail2ban/filter.d/`);
    } catch {
      // filter.d wasn't backed up
    }

    // Restart fail2ban
    await execAsync('sudo systemctl restart fail2ban');

  } catch (err: any) {
    throw new Error(`Failed to restore fail2ban backup: ${err.message}`);
  }
}

/**
 * List all available backups
 */
export async function listBackups(): Promise<BackupInfo[]> {
  try {
    const { stdout } = await execAsync(`ls -1 ${BACKUP_DIR}`);
    const backupDirs = stdout.trim().split('\n').filter(Boolean);

    const backups: BackupInfo[] = [];

    for (const dir of backupDirs) {
      const match = dir.match(/^(nginx|fail2ban)-(.+)$/);
      if (match) {
        const [, type, id] = match;
        backups.push({
          id,
          timestamp: '', // Would need to parse from directory metadata
          type: type as 'nginx' | 'fail2ban',
          files: [],
          location: join(BACKUP_DIR, dir),
        });
      }
    }

    return backups;
  } catch {
    return [];
  }
}

/**
 * Delete old backups (keep last N)
 */
export async function cleanupOldBackups(keepCount: number = 5): Promise<void> {
  const backups = await listBackups();

  if (backups.length <= keepCount) {
    return;
  }

  // Sort by timestamp (newest first)
  backups.sort((a, b) => b.id.localeCompare(a.id));

  // Delete old backups
  const toDelete = backups.slice(keepCount);

  for (const backup of toDelete) {
    try {
      await execAsync(`rm -rf ${backup.location}`);
    } catch {
      // Failed to delete, continue
    }
  }
}
