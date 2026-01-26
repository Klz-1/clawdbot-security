/**
 * fail2ban Detection and Management
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';

const execAsync = promisify(exec);

/**
 * Detect if fail2ban is installed
 */
export async function detectFail2ban(): Promise<boolean> {
  try {
    await execAsync('which fail2ban-client');
    return true;
  } catch {
    return false;
  }
}

/**
 * Get fail2ban version
 */
export async function getFail2banVersion(): Promise<string | null> {
  try {
    const { stdout } = await execAsync('fail2ban-client version');
    const match = stdout.match(/Fail2Ban v([0-9.]+)/);
    return match ? match[1] : null;
  } catch {
    return null;
  }
}

/**
 * Install fail2ban
 */
export async function installFail2ban(): Promise<void> {
  // Detect package manager
  const hasApt = await hasCommand('apt-get');
  const hasYum = await hasCommand('yum');

  if (hasApt) {
    await execAsync('sudo apt-get update && sudo apt-get install -y fail2ban');
  } else if (hasYum) {
    await execAsync('sudo yum install -y fail2ban');
  } else {
    throw new Error('Unsupported package manager. Please install fail2ban manually.');
  }
}

/**
 * Check if a command exists
 */
async function hasCommand(command: string): Promise<boolean> {
  try {
    await execAsync(`which ${command}`);
    return true;
  } catch {
    return false;
  }
}

/**
 * Apply fail2ban configuration based on profile
 */
export async function applyFail2banConfig(profile: string): Promise<void> {
  // For now, create template files in user's home directory
  // In production, this would write to /etc/fail2ban/jail.d/
  const configDir = join(homedir(), '.clawdbot', 'fail2ban');

  try {
    await mkdir(configDir, { recursive: true });
  } catch {
    // Directory already exists
  }

  const jailConfig = getFail2banJailTemplate(profile);
  const filterConfig = getFail2banFilterTemplate();

  await writeFile(join(configDir, 'clawdbot.local'), jailConfig);
  await writeFile(join(configDir, 'clawdbot-nginx.conf'), filterConfig);

  // Note: In production, would also:
  // 1. Copy to /etc/fail2ban/jail.d/
  // 2. Copy filters to /etc/fail2ban/filter.d/
  // 3. Restart fail2ban
  // For now, just save templates for user to review
}

/**
 * Get fail2ban jail configuration template
 */
function getFail2banJailTemplate(profile: string): string {
  const templates = {
    basic: `[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[nginx-rate-limit]
enabled = true
port = http,https
filter = clawdbot-nginx-rate-limit
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 3600

[nginx-path-traversal]
enabled = true
port = http,https
filter = clawdbot-nginx-path-traversal
logpath = /var/log/nginx/access.log
maxretry = 3
bantime = 7200
`,
    standard: `[DEFAULT]
bantime = 86400
findtime = 600
maxretry = 2

[nginx-rate-limit]
enabled = true
port = http,https
filter = clawdbot-nginx-rate-limit
logpath = /var/log/nginx/error.log
maxretry = 2
bantime = 3600

[nginx-path-traversal]
enabled = true
port = http,https
filter = clawdbot-nginx-path-traversal
logpath = /var/log/nginx/access.log
maxretry = 1
bantime = 86400

[nginx-suspicious-ua]
enabled = true
port = http,https
filter = clawdbot-nginx-suspicious-ua
logpath = /var/log/nginx/access.log
maxretry = 1
bantime = 604800
`,
    paranoid: `[DEFAULT]
bantime = -1
findtime = 600
maxretry = 1

[nginx-rate-limit]
enabled = true
port = http,https
filter = clawdbot-nginx-rate-limit
logpath = /var/log/nginx/error.log
maxretry = 1
bantime = -1

[nginx-path-traversal]
enabled = true
port = http,https
filter = clawdbot-nginx-path-traversal
logpath = /var/log/nginx/access.log
maxretry = 1
bantime = -1

[nginx-suspicious-ua]
enabled = true
port = http,https
filter = clawdbot-nginx-suspicious-ua
logpath = /var/log/nginx/access.log
maxretry = 1
bantime = -1

[nginx-attack-pattern]
enabled = true
port = http,https
filter = clawdbot-nginx-attack-pattern
logpath = /var/log/nginx/access.log
maxretry = 1
bantime = -1
`,
  };

  return templates[profile as keyof typeof templates] || templates.standard;
}

/**
 * Get fail2ban filter templates
 */
function getFail2banFilterTemplate(): string {
  return `# Clawdbot nginx rate limit filter
[Definition]
failregex = limiting requests, excess:.* by zone.*client: <HOST>
ignoreregex =

# Clawdbot nginx path traversal filter
[Definition]
failregex = .*"\\.\\./.*" .* 403 .*
            .*"etc/passwd" .* 403 .*
ignoreregex =

# Clawdbot nginx suspicious user agent filter
[Definition]
failregex = .* "(nikto|sqlmap|nmap|metasploit|burp)" .*
ignoreregex =

# Clawdbot nginx attack pattern filter
[Definition]
failregex = .* "(eval\\(|base64_|exec\\(|system\\()" .* 403 .*
ignoreregex =
`;
}

/**
 * Get fail2ban status
 */
export async function getFail2banStatus(): Promise<string> {
  try {
    const { stdout } = await execAsync('sudo fail2ban-client status');
    return stdout;
  } catch (err: any) {
    return err.message;
  }
}

/**
 * Check if fail2ban is running
 */
export async function isFail2banRunning(): Promise<boolean> {
  try {
    await execAsync('sudo systemctl is-active fail2ban');
    return true;
  } catch {
    return false;
  }
}
