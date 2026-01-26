/**
 * Configuration management for Clawdbot Security
 *
 * Detects and works with existing Clawdbot installations
 */

import { readFile, writeFile, access } from 'fs/promises';
import { homedir } from 'os';
import { join } from 'path';
import type { ClawdbotConfig, SecurityConfig } from './types.js';

export const CLAWDBOT_CONFIG_DIR = join(homedir(), '.clawdbot');
export const CLAWDBOT_CONFIG_PATH = join(CLAWDBOT_CONFIG_DIR, 'clawdbot.json');
export const SECURITY_CONFIG_PATH = join(CLAWDBOT_CONFIG_DIR, 'security.json');

/**
 * Check if Clawdbot is installed
 */
export async function isClawdbotInstalled(): Promise<boolean> {
  try {
    await access(CLAWDBOT_CONFIG_DIR);
    return true;
  } catch {
    return false;
  }
}

/**
 * Load Clawdbot configuration
 */
export async function loadClawdbotConfig(): Promise<ClawdbotConfig | null> {
  try {
    const content = await readFile(CLAWDBOT_CONFIG_PATH, 'utf-8');
    return JSON.parse(content);
  } catch (err) {
    // Config doesn't exist or can't be read
    return null;
  }
}

/**
 * Load security configuration
 * First checks Clawdbot's config, then standalone security config
 */
export async function loadSecurityConfig(): Promise<SecurityConfig | null> {
  // Try loading from Clawdbot's main config first
  const clawdbotConfig = await loadClawdbotConfig();
  if (clawdbotConfig?.security) {
    return clawdbotConfig.security;
  }

  // Try standalone security config
  try {
    const content = await readFile(SECURITY_CONFIG_PATH, 'utf-8');
    return JSON.parse(content);
  } catch {
    return null;
  }
}

/**
 * Save security configuration
 * Saves to Clawdbot's main config if it exists, otherwise standalone
 */
export async function saveSecurityConfig(
  securityConfig: SecurityConfig
): Promise<void> {
  const clawdbotConfig = await loadClawdbotConfig();

  if (clawdbotConfig) {
    // Update Clawdbot's main config
    clawdbotConfig.security = securityConfig;

    // Create backup
    const backupPath = `${CLAWDBOT_CONFIG_PATH}.backup`;
    try {
      await writeFile(backupPath, JSON.stringify(clawdbotConfig, null, 2));
    } catch {
      // Backup failed, but continue
    }

    // Write updated config
    await writeFile(
      CLAWDBOT_CONFIG_PATH,
      JSON.stringify(clawdbotConfig, null, 2)
    );
  } else {
    // Save as standalone config
    await writeFile(
      SECURITY_CONFIG_PATH,
      JSON.stringify(securityConfig, null, 2)
    );
  }
}

/**
 * Get default security configuration
 */
export function getDefaultSecurityConfig(): SecurityConfig {
  return {
    profile: 'standard',
    profiles: {
      basic: {
        level: 'basic',
        nginx: {
          rateLimiting: 'moderate',
          fail2ban: 'basic',
          securityHeaders: true,
        },
        filesystem: {
          configPerms: '600',
          statePerms: '700',
          credentialsPerms: '600',
        },
        updates: {
          autoCheck: true,
          autoApply: 'security_only',
        },
      },
      standard: {
        level: 'standard',
        nginx: {
          rateLimiting: 'strict',
          fail2ban: 'aggressive',
          securityHeaders: true,
        },
        filesystem: {
          configPerms: '600',
          statePerms: '700',
          credentialsPerms: '600',
        },
        updates: {
          autoCheck: true,
          autoApply: 'all_security',
          applyWindow: {
            startHour: 2,
            endHour: 5,
          },
        },
        monitoring: {
          securityLogs: true,
          alertThreshold: 'medium',
        },
      },
      paranoid: {
        level: 'paranoid',
        nginx: {
          rateLimiting: 'very_strict',
          fail2ban: 'zero_tolerance',
          securityHeaders: true,
        },
        filesystem: {
          configPerms: '600',
          statePerms: '700',
          credentialsPerms: '600',
        },
        updates: {
          autoCheck: true,
          autoApply: 'all_security',
          applyWindow: {
            startHour: 2,
            endHour: 5,
          },
        },
        monitoring: {
          securityLogs: true,
          alertThreshold: 'low',
        },
      },
    },
  };
}

/**
 * Initialize security configuration if it doesn't exist
 */
export async function initializeSecurityConfig(): Promise<SecurityConfig> {
  let config = await loadSecurityConfig();

  if (!config) {
    config = getDefaultSecurityConfig();
    await saveSecurityConfig(config);
  }

  return config;
}
