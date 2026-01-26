/**
 * nginx Detection and Management
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { access, readFile, writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';

const execAsync = promisify(exec);

/**
 * Detect if nginx is installed
 */
export async function detectNginx(): Promise<boolean> {
  try {
    await execAsync('which nginx');
    return true;
  } catch {
    return false;
  }
}

/**
 * Get nginx version
 */
export async function getNginxVersion(): Promise<string | null> {
  try {
    const { stderr } = await execAsync('nginx -v');
    // nginx version is in stderr: nginx version: nginx/1.24.0
    const match = stderr.match(/nginx\/([0-9.]+)/);
    return match ? match[1] : null;
  } catch {
    return null;
  }
}

/**
 * Check if nginx config directory exists
 */
export async function hasNginxConfigDir(): Promise<boolean> {
  try {
    await access('/etc/nginx');
    return true;
  } catch {
    return false;
  }
}

/**
 * Apply nginx hardening based on profile
 */
export async function applyNginxHardening(profile: string): Promise<void> {
  // For now, create a template file in user's home directory
  // In production, this would write to /etc/nginx/conf.d/
  const configDir = join(homedir(), '.clawdbot', 'nginx');

  try {
    await mkdir(configDir, { recursive: true });
  } catch {
    // Directory already exists
  }

  const template = getNginxTemplate(profile);
  const configPath = join(configDir, 'clawdbot-security.conf');

  await writeFile(configPath, template);

  // Note: In production, would also:
  // 1. Copy to /etc/nginx/conf.d/
  // 2. Run nginx -t to validate
  // 3. Reload nginx
  // For now, just save the template for user to review
}

/**
 * Get nginx configuration template based on profile
 */
function getNginxTemplate(profile: string): string {
  const templates = {
    basic: `# Clawdbot Security - Basic Profile
# Rate limiting zones
limit_req_zone $binary_remote_addr zone=general:10m rate=20r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;

# Hide nginx version
server_tokens off;

# Clawdbot Gateway
location /v1/ {
    limit_req zone=api burst=20 nodelay;

    proxy_pass http://127.0.0.1:18789;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
`,
    standard: `# Clawdbot Security - Standard Profile
# Rate limiting zones
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;

# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

# Hide nginx version
server_tokens off;

# Path traversal protection
location ~ \\.\\. {
    return 403;
}

# Clawdbot Gateway
location /v1/ {
    limit_req zone=api burst=10 nodelay;

    # Block common attack patterns
    if ($request_uri ~* "(\\.\\./|\\.\\.\\\\|etc/passwd|eval\\(|base64_)") {
        return 403;
    }

    proxy_pass http://127.0.0.1:18789;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Host $host;
}
`,
    paranoid: `# Clawdbot Security - Paranoid Profile
# Rate limiting zones (strict)
limit_req_zone $binary_remote_addr zone=general:10m rate=5r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=2r/s;

# Security headers (maximum)
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=()" always;
add_header Content-Security-Policy "default-src 'self'" always;

# Hide nginx version
server_tokens off;

# Path traversal protection (strict)
location ~ \\.\\. {
    return 403;
}

# Block sensitive files
location ~ /(\\.|wp-config|readme|license|changelog) {
    return 403;
}

# Clawdbot Gateway (strict limits)
location /v1/ {
    limit_req zone=api burst=5 nodelay;

    # Strict method filtering
    if ($request_method !~ ^(GET|POST|HEAD)$) {
        return 405;
    }

    # Block all attack patterns
    if ($request_uri ~* "(\\.\\./|\\.\\.\\\\|etc/passwd|proc/|eval\\(|base64_|exec\\(|system\\()") {
        return 403;
    }

    # Block suspicious user agents
    if ($http_user_agent ~* (nikto|sqlmap|nmap|metasploit|burp)) {
        return 403;
    }

    proxy_pass http://127.0.0.1:18789;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Host $host;
}
`,
  };

  return templates[profile as keyof typeof templates] || templates.standard;
}

/**
 * Validate nginx configuration
 */
export async function validateNginxConfig(): Promise<boolean> {
  try {
    await execAsync('nginx -t');
    return true;
  } catch {
    return false;
  }
}

/**
 * Reload nginx
 */
export async function reloadNginx(): Promise<void> {
  await execAsync('sudo systemctl reload nginx');
}
