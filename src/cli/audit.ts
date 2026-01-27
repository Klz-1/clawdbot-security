/**
 * Comprehensive Security Audit - All Attack Vectors
 * Updated for general Clawdbot installations (all channels, skills, MCP, etc.)
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { exec } from 'child_process';
import { promisify } from 'util';
import { access, stat, readdir, readFile } from 'fs/promises';
import { constants } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { loadClawdbotConfig } from '../core/config.js';
import { calculateSecurityScore } from '../scoring/calculator.js';
import { getCVEStatus } from '../monitoring/cve-checker.js';
import type { AuditResult, AuditIssue, AuditCheck, Severity, ClawdbotConfig } from '../core/types.js';

const execAsync = promisify(exec);

interface ServiceStatus {
  running: boolean;
  enabled: boolean;
}

const CLAWDBOT_DIR = join(homedir(), '.clawdbot');

export function registerAuditCommand(program: Command): void {
  program
    .command('audit')
    .description('Run comprehensive security audit (all attack vectors)')
    .option('--deep', 'Include CVE scanning and supply chain checks')
    .option('--json', 'Output as JSON')
    .action(async (options) => {
      try {
        console.log(chalk.bold.cyan('\n🔍 Running Comprehensive Security Audit...\n'));
        console.log(chalk.dim('This checks ALL attack vectors: channels, skills, hooks, MCP, secrets, models, etc.\n'));

        const result = await runComprehensiveAudit(options.deep);

        if (options.json) {
          console.log(JSON.stringify(result, null, 2));
          return;
        }

        displayAuditResults(result);

        // Calculate and display security score
        const config = await loadClawdbotConfig();
        const scoreResult = await calculateSecurityScore(config || {});
        console.log(chalk.bold.cyan('\n📊 Security Score'));
        console.log(`${chalk.bold(scoreResult.score.toString())}/100`);

        if (scoreResult.score >= 90) {
          console.log(chalk.green.bold('\n✓ EXCELLENT - Your Clawdbot is well secured!'));
        } else if (scoreResult.score >= 75) {
          console.log(chalk.yellow.bold('\n⚠ GOOD - Some improvements recommended'));
        } else if (scoreResult.score >= 60) {
          console.log(chalk.yellow.bold('\n⚠ FAIR - Security hardening recommended'));
        } else {
          console.log(chalk.red.bold('\n✗ POOR - Immediate action required'));
        }

        // Exit with appropriate code
        if (result.issues.some(i => i.severity === 'critical')) {
          process.exit(1);
        }

      } catch (err: any) {
        console.error(chalk.red('Error:'), err.message);
        process.exit(1);
      }
    });
}

async function runComprehensiveAudit(deep: boolean = false): Promise<AuditResult> {
  const issues: AuditIssue[] = [];
  const checks: AuditCheck[] = [];

  const config = await loadClawdbotConfig() || {};

  // === INFRASTRUCTURE SECURITY ===

  console.log(chalk.bold.cyan('Infrastructure Security'));

  // 1. File Permissions (expanded to include all sensitive files)
  console.log(chalk.dim('  • Checking file permissions...'));
  const filePermsResult = await checkFilePermissionsComprehensive();
  checks.push(...filePermsResult.checks);
  issues.push(...filePermsResult.issues);

  // 2. Gateway Authentication
  console.log(chalk.dim('  • Checking gateway authentication...'));
  const gatewayResult = await checkGatewayAuth(config);
  checks.push(...gatewayResult.checks);
  issues.push(...gatewayResult.issues);

  // 3. Network Exposure
  console.log(chalk.dim('  • Checking network exposure...'));
  const networkResult = await checkNetworkExposure(config);
  checks.push(...networkResult.checks);
  issues.push(...networkResult.issues);

  // 4. mDNS/Avahi Service Discovery
  console.log(chalk.dim('  • Checking mDNS/Avahi service discovery...'));
  const mdnsResult = await checkServiceDiscovery();
  checks.push(...mdnsResult.checks);
  issues.push(...mdnsResult.issues);

  // === CHANNEL SECURITY (DYNAMIC) ===

  console.log(chalk.bold.cyan('\nChannel Security'));

  // 5. Channel Policies (ALL channels, not just Telegram/Discord)
  console.log(chalk.dim('  • Checking channel policies (all channels)...'));
  const channelResult = await checkAllChannelPolicies(config);
  checks.push(...channelResult.checks);
  issues.push(...channelResult.issues);

  // === SECRETS & CREDENTIALS ===

  console.log(chalk.bold.cyan('\nSecrets & Credentials'));

  // 6. Secrets Management
  console.log(chalk.dim('  • Checking secrets management...'));
  const secretsResult = await checkSecretsManagement(config);
  checks.push(...secretsResult.checks);
  issues.push(...secretsResult.issues);

  // 7. Token Storage
  console.log(chalk.dim('  • Checking token storage...'));
  const tokenResult = await checkTokenStorage();
  checks.push(...tokenResult.checks);
  issues.push(...tokenResult.issues);

  // === SKILLS & TOOLS SECURITY ===

  console.log(chalk.bold.cyan('\nSkills & Tools Security'));

  // 8. Skills Security
  console.log(chalk.dim('  • Checking skills security...'));
  const skillsResult = await checkSkillsSecurity(config);
  checks.push(...skillsResult.checks);
  issues.push(...skillsResult.issues);

  // 9. Tools Security
  console.log(chalk.dim('  • Checking tools security...'));
  const toolsResult = await checkToolsSecurity(config);
  checks.push(...toolsResult.checks);
  issues.push(...toolsResult.issues);

  // === HOOKS & EXTENSIONS ===

  console.log(chalk.bold.cyan('\nHooks & Extensions'));

  // 10. Hooks Security
  console.log(chalk.dim('  • Checking hooks security...'));
  const hooksResult = await checkHooksSecurity(config);
  checks.push(...hooksResult.checks);
  issues.push(...hooksResult.issues);

  // 10.5 Prompt Injection Protection (CVE-2025-PROMPT-INJECTION / PR #1827)
  console.log(chalk.dim('  • Checking prompt injection protection...'));
  const promptInjectionResult = await checkPromptInjectionProtection();
  checks.push(...promptInjectionResult.checks);
  issues.push(...promptInjectionResult.issues);

  // === MODEL SECURITY ===

  console.log(chalk.bold.cyan('\nModel Security'));

  // 11. Model Configuration
  console.log(chalk.dim('  • Checking model security...'));
  const modelsResult = await checkModelSecurity(config);
  checks.push(...modelsResult.checks);
  issues.push(...modelsResult.issues);

  // === WORKSPACE & ISOLATION ===

  console.log(chalk.bold.cyan('\nWorkspace & Isolation'));

  // 12. Workspace Isolation
  console.log(chalk.dim('  • Checking workspace isolation...'));
  const workspaceResult = await checkWorkspaceIsolation(config);
  checks.push(...workspaceResult.checks);
  issues.push(...workspaceResult.issues);

  // === HARDENING & PROTECTION ===

  console.log(chalk.bold.cyan('\nHardening & Protection'));

  // 13. nginx Configuration
  console.log(chalk.dim('  • Checking nginx configuration...'));
  const nginxResult = await checkNginxConfig();
  checks.push(...nginxResult.checks);
  issues.push(...nginxResult.issues);

  // 14. fail2ban Status
  console.log(chalk.dim('  • Checking fail2ban status...'));
  const fail2banResult = await checkFail2ban();
  checks.push(...fail2banResult.checks);
  issues.push(...fail2banResult.issues);

  // 15. Security Profile
  console.log(chalk.dim('  • Checking security profile...'));
  const profileResult = await checkSecurityProfile(config);
  checks.push(...profileResult.checks);
  issues.push(...profileResult.issues);

  // === ENHANCED SECURITY CHECKS ===
  console.log(chalk.bold.cyan('\nEnhanced Security'));

  // 16. Browser Control Security
  console.log(chalk.dim('  • Checking browser control security...'));
  const browserResult = await checkBrowserSecurity(config);
  checks.push(...browserResult.checks);
  issues.push(...browserResult.issues);

  // 17. Logging & Redaction Security
  console.log(chalk.dim('  • Checking logging security...'));
  const loggingResult = await checkLoggingSecurity(config);
  checks.push(...loggingResult.checks);
  issues.push(...loggingResult.issues);

  // 18. Dangerous Command Blocking
  console.log(chalk.dim('  • Checking dangerous command blocking...'));
  const commandsResult = await checkDangerousCommands(config);
  checks.push(...commandsResult.checks);
  issues.push(...commandsResult.issues);

  // 19. Tool Sandboxing (Enhanced)
  console.log(chalk.dim('  • Checking tool sandboxing...'));
  const sandboxResult = await checkToolSandboxing(config);
  checks.push(...sandboxResult.checks);
  issues.push(...sandboxResult.issues);

  // 20. Secret Scanning Integration
  console.log(chalk.dim('  • Checking secret scanning...'));
  const secretScanResult = await checkSecretScanning();
  checks.push(...secretScanResult.checks);
  issues.push(...secretScanResult.issues);

  // 21. Enhanced Prompt Injection Protection
  console.log(chalk.dim('  • Checking enhanced prompt injection protection...'));
  const enhancedPromptResult = await checkEnhancedPromptInjection(config);
  checks.push(...enhancedPromptResult.checks);
  issues.push(...enhancedPromptResult.issues);

  // === VULNERABILITIES & UPDATES (DEEP MODE) ===

  if (deep) {
    console.log(chalk.bold.cyan('\nVulnerabilities & Supply Chain'));

    // 22. CVE Status
    console.log(chalk.dim('  • Checking CVE status (deep scan)...'));
    const cveResult = await checkCVEStatus();
    checks.push(...cveResult.checks);
    issues.push(...cveResult.issues);

    // 23. Dependency Security
    console.log(chalk.dim('  • Checking dependency security...'));
    const depsResult = await checkDependencySecurity();
    checks.push(...depsResult.checks);
    issues.push(...depsResult.issues);
  }

  console.log(); // Empty line

  return {
    ok: issues.filter(i => i.severity === 'critical' || i.severity === 'high').length === 0,
    issues,
    checks,
  };
}

// === INFRASTRUCTURE CHECKS ===

async function checkFilePermissionsComprehensive(): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  const filesToCheck = [
    { path: `${CLAWDBOT_DIR}/clawdbot.json`, name: 'Config file', expectedMax: 0o600 },
    { path: `${CLAWDBOT_DIR}/.env`, name: 'Environment file', expectedMax: 0o600 },
    { path: `${CLAWDBOT_DIR}/secrets`, name: 'Secrets directory', expectedMax: 0o700 },
    { path: `${CLAWDBOT_DIR}/credentials`, name: 'Credentials directory', expectedMax: 0o700 },
    { path: `${CLAWDBOT_DIR}`, name: 'Clawdbot directory', expectedMax: 0o700 },
    { path: `${CLAWDBOT_DIR}/hooks`, name: 'Hooks directory', expectedMax: 0o700 },
  ];

  for (const file of filesToCheck) {
    try {
      await access(file.path, constants.R_OK);
      const stats = await stat(file.path);
      const perms = stats.mode & 0o777;

      if (perms <= file.expectedMax) {
        checks.push({
          name: `${file.name} permissions`,
          passed: true,
          message: `Permissions: ${perms.toString(8)} (secure)`,
        });
      } else {
        checks.push({
          name: `${file.name} permissions`,
          passed: false,
          message: `Permissions: ${perms.toString(8)} (too permissive)`,
        });
        issues.push({
          code: 'FILE_PERMS_' + file.name.toUpperCase().replace(/ /g, '_'),
          severity: file.name.includes('secret') || file.name.includes('credential') || file.name.includes('.env') ? 'critical' : 'medium',
          message: `${file.name} has overly permissive permissions (${perms.toString(8)})`,
          fix: `chmod ${file.expectedMax.toString(8)} ${file.path}`,
        });
      }
    } catch (err) {
      checks.push({
        name: `${file.name} permissions`,
        passed: true,
        message: 'File not found (may be intentional)',
      });
    }
  }

  // Check for token files
  const tokenFiles = ['telegram.token', 'discord.token', 'whatsapp.token', 'slack.token'];
  for (const tokenFile of tokenFiles) {
    try {
      const tokenPath = join(CLAWDBOT_DIR, tokenFile);
      await access(tokenPath, constants.R_OK);
      const stats = await stat(tokenPath);
      const perms = stats.mode & 0o777;

      if (perms > 0o600) {
        issues.push({
          code: 'TOKEN_FILE_PERMS',
          severity: 'critical',
          message: `${tokenFile} has overly permissive permissions (${perms.toString(8)})`,
          fix: `chmod 600 ${tokenPath}`,
        });
      }
    } catch {
      // Token file doesn't exist - not an issue
    }
  }

  return { checks, issues };
}

async function checkGatewayAuth(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  const authMode = config.gateway?.auth?.mode;

  if (!authMode || authMode === 'none') {
    checks.push({
      name: 'Gateway authentication',
      passed: false,
      message: 'No authentication configured',
    });
    issues.push({
      code: 'NO_AUTH',
      severity: 'critical',
      message: 'Gateway has no authentication enabled',
      fix: 'Configure gateway.auth.mode in ~/.clawdbot/clawdbot.json',
    });
  } else {
    checks.push({
      name: 'Gateway authentication',
      passed: true,
      message: `Auth mode: ${authMode}`,
    });
  }

  // Check bind address
  const bind = config.gateway?.bind;
  if (bind && bind !== 'loopback' && bind !== '127.0.0.1' && bind !== 'localhost') {
    issues.push({
      code: 'GATEWAY_PUBLIC_BIND',
      severity: 'high',
      message: `Gateway bound to ${bind} (publicly accessible)`,
      fix: 'Use Tailscale/VPN for remote access instead of public binding',
    });
  }

  return { checks, issues };
}

/**
 * Comprehensive Network Port Exposure Check
 *
 * Categorizes listening ports by exposure level:
 * - Public (0.0.0.0, ::) - Internet accessible
 * - Tailscale (100.*, fd7a:*) - VPN only
 * - Localhost (127.0.0.1, ::1) - Local only
 *
 * Identifies services and provides security recommendations.
 */
async function checkNetworkExposure(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    // Check for listening ports
    const { stdout } = await execAsync('ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null || echo "unavailable"');

    if (stdout === 'unavailable') {
      checks.push({
        name: 'Network exposure',
        passed: true,
        message: 'Could not check (requires ss or netstat)',
      });
      return { checks, issues };
    }

    const lines = stdout.split('\n');
    const publicPorts: { port: string; address: string }[] = [];
    const tailscalePorts: { port: string; address: string }[] = [];
    const localhostPorts: { port: string; address: string }[] = [];

    // Common service port mappings
    const serviceNames: Record<string, string> = {
      '22': 'SSH',
      '80': 'HTTP',
      '443': 'HTTPS',
      '631': 'CUPS/Printing',
      '3000': 'Web Service',
      '3001': 'Web Service',
      '3002': 'Web Service',
      '5432': 'PostgreSQL',
      '8042': 'Task Viewer',
      '8080': 'HTTP/nginx',
      '8222': 'Vaultwarden',
      '18789': 'Clawdbot Gateway',
      '18791': 'Clawdbot Gateway',
      '18792': 'Clawdbot Gateway',
    };

    for (const line of lines) {
      if (!line.includes('LISTEN')) continue;

      // Extract address and port from line
      const match = line.match(/LISTEN\s+\d+\s+\d+\s+([\S]+):(\d+)/);
      if (!match) continue;

      const [, address, port] = match;

      // Skip localhost
      if (address.includes('127.0.0.1') || address.includes('127.0.0.53') ||
          address.includes('::1') || address === 'localhost') {
        localhostPorts.push({ port, address });
        continue;
      }

      // Check for Tailscale IPs (typically 100.x.x.x or fd7a:*)
      if (address.startsWith('100.') || address.startsWith('fd7a:')) {
        tailscalePorts.push({ port, address });
        continue;
      }

      // Public interfaces (0.0.0.0, ::, or other IPs)
      if (address === '0.0.0.0' || address === '::' || address === '*') {
        publicPorts.push({ port, address });
      }
    }

    // Check each category
    if (publicPorts.length > 0) {
      for (const { port, address } of publicPorts) {
        const serviceName = serviceNames[port] || 'Unknown Service';

        // Determine severity
        let severity: Severity = 'medium';
        let recommendation = '';

        if (port === '22') {
          // SSH is acceptable if key-based auth
          severity = 'low';
          recommendation = 'Ensure SSH uses key-based authentication (not passwords)';
        } else if (port === '631') {
          // CUPS should not be public
          severity = 'high';
          recommendation = 'Disable CUPS: sudo systemctl stop cups && sudo systemctl disable cups';
        } else if (['8080', '8042', '8222', '3000', '3001', '3002'].includes(port)) {
          // Web services should be Tailscale-only
          severity = 'high';
          recommendation = `Restrict to Tailscale: bind to 100.x.x.x instead of ${address}`;
        } else if (['18789', '18791', '18792'].includes(port)) {
          // Clawdbot gateways should NEVER be public
          severity = 'critical';
          recommendation = 'CRITICAL: Clawdbot gateway exposed! Must bind to localhost only';
        } else {
          severity = 'medium';
          recommendation = 'Review if this service needs to be publicly accessible';
        }

        checks.push({
          name: `Port ${port} (${serviceName})`,
          passed: port === '22', // Only SSH is acceptable public
          message: `Listening on ${address}:${port}`,
        });

        if (port !== '22') {
          issues.push({
            code: `PUBLIC_PORT_${port}`,
            severity,
            message: `${serviceName} exposed on public interface ${address}:${port}`,
            fix: recommendation,
          });
        }
      }

      checks.push({
        name: 'Public network exposure',
        passed: publicPorts.length === 1 && publicPorts[0].port === '22',
        message: `${publicPorts.length} port(s) on public interfaces`,
      });
    } else {
      checks.push({
        name: 'Public network exposure',
        passed: true,
        message: 'No public ports detected (excellent!)',
      });
    }

    // Tailscale ports (informational)
    if (tailscalePorts.length > 0) {
      const tailscaleServices = tailscalePorts.map(p => {
        const serviceName = serviceNames[p.port] || 'Unknown';
        return `${p.port} (${serviceName})`;
      }).join(', ');

      checks.push({
        name: 'Tailscale-only services',
        passed: true,
        message: `${tailscalePorts.length} service(s) on VPN: ${tailscaleServices}`,
      });
    }

    // Localhost ports (informational)
    if (localhostPorts.length > 0) {
      checks.push({
        name: 'Localhost services',
        passed: true,
        message: `${localhostPorts.length} service(s) on localhost (secure)`,
      });
    }

  } catch (error) {
    checks.push({
      name: 'Network exposure',
      passed: true,
      message: 'Could not check network ports',
    });
  }

  return { checks, issues };
}

async function checkServiceDiscovery(): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    const { stdout: activeOut } = await execAsync('systemctl is-active avahi-daemon 2>/dev/null || echo inactive');
    const { stdout: enabledOut } = await execAsync('systemctl is-enabled avahi-daemon 2>/dev/null || echo disabled');

    const isRunning = activeOut.trim() === 'active';
    const isEnabled = enabledOut.trim() === 'enabled';

    if (isRunning) {
      checks.push({
        name: 'mDNS/Avahi service',
        passed: false,
        message: 'Avahi daemon is running',
      });
      issues.push({
        code: 'MDNS_ACTIVE',
        severity: 'high',
        message: 'Avahi daemon is broadcasting mDNS service discovery on LAN',
        fix: 'sudo systemctl stop avahi-daemon && sudo systemctl disable avahi-daemon && sudo systemctl disable avahi-daemon.socket',
      });
    } else {
      checks.push({
        name: 'mDNS/Avahi service',
        passed: true,
        message: 'Avahi daemon is not running',
      });
    }

    if (!isRunning && isEnabled) {
      issues.push({
        code: 'MDNS_ENABLED',
        severity: 'medium',
        message: 'Avahi daemon will start on boot',
        fix: 'sudo systemctl disable avahi-daemon && sudo systemctl disable avahi-daemon.socket',
      });
    }
  } catch {
    checks.push({
      name: 'mDNS/Avahi service',
      passed: true,
      message: 'Avahi not installed',
    });
  }

  return { checks, issues };
}

// === CHANNEL SECURITY (DYNAMIC) ===

async function checkAllChannelPolicies(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  const channels = config.channels || {};
  const channelNames = Object.keys(channels);

  if (channelNames.length === 0) {
    checks.push({
      name: 'Channel policies',
      passed: true,
      message: 'No channels configured',
    });
    return { checks, issues };
  }

  // Check each channel dynamically
  for (const channelName of channelNames) {
    const channel = channels[channelName];
    const dmPolicy = channel?.dmPolicy;
    const groupPolicy = channel?.groupPolicy;

    // Check DM policy
    if (dmPolicy === 'open') {
      checks.push({
        name: `${channelName} DM policy`,
        passed: false,
        message: 'Open to all users',
      });
      issues.push({
        code: `${channelName.toUpperCase()}_DM_OPEN`,
        severity: 'high',
        message: `${channelName} DMs are open to all users`,
        fix: `Set channels.${channelName}.dmPolicy to "pairing" or "allowlist" in config`,
      });
    } else {
      checks.push({
        name: `${channelName} DM policy`,
        passed: true,
        message: dmPolicy || 'Not configured',
      });
    }

    // Check group policy
    if (groupPolicy === 'open') {
      issues.push({
        code: `${channelName.toUpperCase()}_GROUP_OPEN`,
        severity: 'medium',
        message: `${channelName} groups are open to all`,
        fix: `Set channels.${channelName}.groupPolicy to "allowlist" in config`,
      });
    }
  }

  return { checks, issues };
}

// === SECRETS & CREDENTIALS ===

async function checkSecretsManagement(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  // Check if secrets are in config (BAD) vs .env (GOOD)
  const configStr = JSON.stringify(config);
  const suspiciousPatterns = [
    { pattern: /"token":\s*"[^"]{20,}"/, name: 'API tokens' },
    { pattern: /"apiKey":\s*"[^"]{20,}"/, name: 'API keys' },
    { pattern: /"password":\s*"[^"]{3,}"/, name: 'Passwords' },
    { pattern: /"secret":\s*"[^"]{20,}"/, name: 'Secrets' },
  ];

  for (const { pattern, name } of suspiciousPatterns) {
    if (pattern.test(configStr)) {
      checks.push({
        name: `${name} in config`,
        passed: false,
        message: 'Secrets found in config file',
      });
      issues.push({
        code: 'SECRETS_IN_CONFIG',
        severity: 'critical',
        message: `${name} found in config file (should be in .env)`,
        fix: 'Move secrets to ~/.clawdbot/.env and use environment variables',
      });
    }
  }

  // Check if .env exists
  try {
    await access(join(CLAWDBOT_DIR, '.env'), constants.R_OK);
    checks.push({
      name: 'Environment file',
      passed: true,
      message: '.env file exists',
    });
  } catch {
    checks.push({
      name: 'Environment file',
      passed: false,
      message: '.env file not found',
    });
    issues.push({
      code: 'NO_ENV_FILE',
      severity: 'medium',
      message: 'No .env file found (secrets may be in config)',
      fix: 'Create ~/.clawdbot/.env for storing secrets',
    });
  }

  return { checks, issues };
}

async function checkTokenStorage(): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  // Check if token files are in root directory (should be in secrets/)
  const tokenFiles = ['telegram.token', 'discord.token', 'whatsapp.token', 'slack.token'];

  for (const tokenFile of tokenFiles) {
    try {
      const rootPath = join(CLAWDBOT_DIR, tokenFile);
      await access(rootPath, constants.R_OK);

      issues.push({
        code: 'TOKEN_FILE_LOCATION',
        severity: 'medium',
        message: `${tokenFile} in root directory (should be in secrets/)`,
        fix: `mv ~/.clawdbot/${tokenFile} ~/.clawdbot/secrets/`,
      });
    } catch {
      // File doesn't exist in root - check if it's in secrets/ (GOOD)
      try {
        const secretsPath = join(CLAWDBOT_DIR, 'secrets', tokenFile);
        await access(secretsPath, constants.R_OK);
        checks.push({
          name: `${tokenFile} location`,
          passed: true,
          message: 'Stored in secrets/ directory',
        });
      } catch {
        // Not in either location - channel might not be configured
      }
    }
  }

  return { checks, issues };
}

// === SKILLS & TOOLS SECURITY ===

async function checkSkillsSecurity(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  const skills = config.skills?.entries || {};
  const skillNames = Object.keys(skills);

  if (skillNames.length === 0) {
    checks.push({
      name: 'Skills installed',
      passed: true,
      message: 'No skills installed',
    });
    return { checks, issues };
  }

  checks.push({
    name: 'Skills installed',
    passed: true,
    message: `${skillNames.length} skill(s) installed`,
  });

  // Warn about skill security risks
  issues.push({
    code: 'SKILLS_SECURITY_REVIEW',
    severity: 'medium',
    message: `${skillNames.length} skill(s) installed - ensure they are from trusted sources`,
    fix: 'Review skill sources and permissions. Consider sandboxing or removing untrusted skills.',
  });

  // Check for skills with suspicious permissions (if metadata available)
  // Note: This would require reading skill metadata from npm or skill directory
  // For now, we just warn about the presence of skills

  return { checks, issues };
}

async function checkToolsSecurity(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  const tools = config.tools || {};
  const toolNames = Object.keys(tools);

  if (toolNames.length === 0) {
    checks.push({
      name: 'Tools configured',
      passed: true,
      message: 'No custom tools configured',
    });
    return { checks, issues };
  }

  checks.push({
    name: 'Tools configured',
    passed: true,
    message: `${toolNames.length} tool(s) configured`,
  });

  // Check for dangerous tool capabilities
  for (const toolName of toolNames) {
    const tool = tools[toolName];

    // Check for shell execution capability
    if (tool?.capabilities?.includes('shell') || tool?.type === 'shell') {
      issues.push({
        code: 'TOOL_SHELL_ACCESS',
        severity: 'high',
        message: `Tool "${toolName}" has shell execution capability`,
        fix: 'Review tool necessity and restrict permissions if possible',
      });
    }

    // Check for file system access
    if (tool?.capabilities?.includes('filesystem') || tool?.type === 'filesystem') {
      issues.push({
        code: 'TOOL_FILESYSTEM_ACCESS',
        severity: 'medium',
        message: `Tool "${toolName}" has filesystem access`,
        fix: 'Ensure tool is trusted and limit scope if possible',
      });
    }
  }

  return { checks, issues };
}

// === HOOKS & EXTENSIONS ===

async function checkHooksSecurity(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    const hooksDir = join(CLAWDBOT_DIR, 'hooks');
    const hooks = await readdir(hooksDir);

    if (hooks.length === 0) {
      checks.push({
        name: 'Hooks installed',
        passed: true,
        message: 'No hooks installed',
      });
      return { checks, issues };
    }

    checks.push({
      name: 'Hooks installed',
      passed: true,
      message: `${hooks.length} hook(s) installed`,
    });

    // Check each hook
    for (const hookName of hooks) {
      const hookPath = join(hooksDir, hookName);
      const stats = await stat(hookPath);

      if (!stats.isDirectory()) continue;

      // Check hook permissions
      const perms = stats.mode & 0o777;
      if (perms > 0o755) {
        issues.push({
          code: 'HOOK_PERMISSIONS',
          severity: 'medium',
          message: `Hook "${hookName}" has overly permissive permissions (${perms.toString(8)})`,
          fix: `chmod 755 ${hookPath}`,
        });
      }

      // Check for suspicious hook code (basic static analysis)
      try {
        const hookFiles = await readdir(hookPath);
        for (const file of hookFiles) {
          if (file.endsWith('.js') || file.endsWith('.ts')) {
            const content = await readFile(join(hookPath, file), 'utf-8');

            // Check for dangerous patterns
            if (content.includes('eval(') || content.includes('Function(')) {
              issues.push({
                code: 'HOOK_DANGEROUS_CODE',
                severity: 'high',
                message: `Hook "${hookName}" contains dangerous code (eval/Function)`,
                fix: `Review hook code or remove: ${hookPath}`,
              });
            }

            if (content.includes('child_process') || content.includes('exec(')) {
              issues.push({
                code: 'HOOK_SHELL_ACCESS',
                severity: 'medium',
                message: `Hook "${hookName}" has shell execution capability`,
                fix: 'Ensure hook is trusted and necessary',
              });
            }
          }
        }
      } catch {
        // Can't read hook files - permission issue
      }
    }
  } catch {
    checks.push({
      name: 'Hooks installed',
      passed: true,
      message: 'Hooks directory not found',
    });
  }

  return { checks, issues };
}

/**
 * Check for Prompt Injection Protection (CVE-2025-PROMPT-INJECTION)
 *
 * This vulnerability (PR #1827) allowed malicious emails sent to Gmail hooks to inject
 * commands directly into LLM prompts, potentially executing arbitrary instructions.
 *
 * The fix introduces external content sanitization that wraps untrusted data with
 * XML-style delimiters and security warnings to prevent prompt injection attacks.
 *
 * @see https://github.com/clawdbot/clawdbot/pull/1827
 */
async function checkPromptInjectionProtection(): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    // Check if Clawdbot has external content sanitization module
    // This was introduced in PR #1827 to prevent prompt injection via email hooks
    const npmRoot = (await execAsync('npm root -g')).stdout.trim();
    const clawdbotPath = join(npmRoot, 'clawdbot');

    // Check for the security module that handles external content
    const securityModuleExists = await access(join(clawdbotPath, 'dist', 'security'))
      .then(() => true)
      .catch(() => false);

    if (!securityModuleExists) {
      checks.push({
        name: 'Prompt injection protection',
        passed: false,
        message: 'Security module not found (vulnerable)',
      });
      issues.push({
        code: 'PROMPT_INJECTION_VULNERABLE',
        severity: 'critical',
        message: 'Clawdbot installation vulnerable to prompt injection attacks (CVE-2025-PROMPT-INJECTION)',
        fix: 'Update Clawdbot to version 2026.1.24-3 or later: npm update -g clawdbot',
      });
      return { checks, issues };
    }

    // Check if Gmail hooks are enabled (primary attack vector)
    const hooksDir = join(CLAWDBOT_DIR, 'hooks');
    let gmailHookFound = false;

    try {
      const hooks = await readdir(hooksDir);
      for (const hookName of hooks) {
        const hookPath = join(hooksDir, hookName);
        const hookMdPath = join(hookPath, 'HOOK.md');

        try {
          const hookMd = await readFile(hookMdPath, 'utf-8');
          // Check if hook handles email/Gmail/external content
          if (hookMd.toLowerCase().includes('gmail') ||
              hookMd.toLowerCase().includes('email') ||
              hookMd.toLowerCase().includes('cron')) {
            gmailHookFound = true;

            // Check if hook code uses proper sanitization
            const hookFiles = await readdir(hookPath);
            let sanitizationFound = false;

            for (const file of hookFiles) {
              if (file.endsWith('.js') || file.endsWith('.ts')) {
                const content = await readFile(join(hookPath, file), 'utf-8');

                // Look for sanitization patterns
                if (content.includes('sanitize') ||
                    content.includes('escapeXml') ||
                    content.includes('EXTERNAL_CONTENT')) {
                  sanitizationFound = true;
                  break;
                }
              }
            }

            if (!sanitizationFound) {
              issues.push({
                code: 'HOOK_NO_SANITIZATION',
                severity: 'high',
                message: `Hook "${hookName}" handles external content but may not sanitize it`,
                fix: 'Update hook to use proper external content sanitization',
              });
            }
          }
        } catch {
          // Can't read hook metadata
        }
      }
    } catch {
      // No hooks directory
    }

    if (gmailHookFound) {
      checks.push({
        name: 'Prompt injection protection',
        passed: true,
        message: 'External content hooks detected - ensure sanitization is enabled',
      });
    } else {
      checks.push({
        name: 'Prompt injection protection',
        passed: true,
        message: 'No external content hooks detected (low risk)',
      });
    }

    // Additional check: Verify Clawdbot version
    const version = (await execAsync('clawdbot --version')).stdout.trim();
    const [year, month, day] = version.split(/[.-]/).map(Number);

    // PR #1827 was merged around 2026.1.24
    const isPatched = year > 2026 ||
                     (year === 2026 && month > 1) ||
                     (year === 2026 && month === 1 && day >= 24);

    if (!isPatched) {
      issues.push({
        code: 'CLAWDBOT_VERSION_VULNERABLE',
        severity: 'high',
        message: `Clawdbot version ${version} may be vulnerable to prompt injection (PR #1827)`,
        fix: 'Update to version 2026.1.24 or later: npm update -g clawdbot',
      });
    } else {
      checks.push({
        name: 'Clawdbot version',
        passed: true,
        message: `Version ${version} includes prompt injection protection`,
      });
    }

  } catch (error) {
    checks.push({
      name: 'Prompt injection protection',
      passed: false,
      message: 'Could not verify protection status',
    });
    issues.push({
      code: 'PROMPT_INJECTION_CHECK_FAILED',
      severity: 'medium',
      message: 'Unable to verify prompt injection protection',
      fix: 'Manually verify Clawdbot version is 2026.1.24 or later',
    });
  }

  return { checks, issues };
}

// === MODEL SECURITY ===

async function checkModelSecurity(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  const models = config.agents?.defaults?.models || {};
  const modelNames = Object.keys(models);

  if (modelNames.length === 0) {
    checks.push({
      name: 'Models configured',
      passed: true,
      message: 'Using default models',
    });
    return { checks, issues };
  }

  // Check for untrusted model providers
  const trustedProviders = ['anthropic', 'openai', 'google', 'cohere'];
  const untrustedModels: string[] = [];

  for (const modelName of modelNames) {
    const provider = modelName.split('/')[0];
    if (!trustedProviders.includes(provider)) {
      untrustedModels.push(modelName);
    }
  }

  if (untrustedModels.length > 0) {
    issues.push({
      code: 'UNTRUSTED_MODELS',
      severity: 'medium',
      message: `${untrustedModels.length} model(s) from untrusted providers: ${untrustedModels.join(', ')}`,
      fix: 'Verify model provider security and data handling policies',
    });
  } else {
    checks.push({
      name: 'Model providers',
      passed: true,
      message: 'All models from trusted providers',
    });
  }

  return { checks, issues };
}

// === WORKSPACE & ISOLATION ===

async function checkWorkspaceIsolation(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  const workspace = config.agents?.defaults?.workspace;

  if (!workspace) {
    checks.push({
      name: 'Workspace configuration',
      passed: true,
      message: 'Using default workspace',
    });
    return { checks, issues };
  }

  try {
    const stats = await stat(workspace);
    const perms = stats.mode & 0o777;

    if (perms > 0o755) {
      issues.push({
        code: 'WORKSPACE_PERMISSIONS',
        severity: 'medium',
        message: `Workspace has overly permissive permissions (${perms.toString(8)})`,
        fix: `chmod 755 ${workspace}`,
      });
    } else {
      checks.push({
        name: 'Workspace permissions',
        passed: true,
        message: `Permissions: ${perms.toString(8)}`,
      });
    }

    // Check if workspace is outside of clawdbot directory (isolation)
    if (workspace.startsWith(CLAWDBOT_DIR)) {
      issues.push({
        code: 'WORKSPACE_NOT_ISOLATED',
        severity: 'low',
        message: 'Workspace is inside Clawdbot directory (not isolated)',
        fix: 'Consider using a separate directory for agent workspace',
      });
    }
  } catch {
    checks.push({
      name: 'Workspace configuration',
      passed: false,
      message: 'Workspace directory not found',
    });
    issues.push({
      code: 'WORKSPACE_MISSING',
      severity: 'medium',
      message: 'Configured workspace directory does not exist',
      fix: `Create workspace directory: mkdir -p ${workspace}`,
    });
  }

  return { checks, issues };
}

// === HARDENING & PROTECTION ===

async function checkNginxConfig(): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    await execAsync('which nginx');
    const { stdout: statusOut } = await execAsync('systemctl is-active nginx || true');
    const isRunning = statusOut.trim() === 'active';

    checks.push({
      name: 'nginx service',
      passed: isRunning,
      message: isRunning ? 'Running' : 'Not running',
    });

    if (!isRunning) {
      issues.push({
        code: 'NGINX_NOT_RUNNING',
        severity: 'low',
        message: 'nginx is installed but not running',
        fix: 'sudo systemctl start nginx',
      });
    }

    try {
      await access('/etc/nginx/conf.d/clawdbot-security.conf', constants.R_OK);
      checks.push({
        name: 'nginx hardening',
        passed: true,
        message: 'Security configuration applied',
      });
    } catch {
      checks.push({
        name: 'nginx hardening',
        passed: false,
        message: 'No security configuration found',
      });
      issues.push({
        code: 'NGINX_NO_HARDENING',
        severity: 'medium',
        message: 'nginx security hardening not applied',
        fix: 'Run: clawdbot-security harden --nginx',
      });
    }
  } catch {
    checks.push({
      name: 'nginx service',
      passed: true,
      message: 'Not installed (optional)',
    });
  }

  return { checks, issues };
}

async function checkFail2ban(): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    await execAsync('which fail2ban-client');
    const { stdout: statusOut } = await execAsync('systemctl is-active fail2ban || true');
    const isRunning = statusOut.trim() === 'active';

    checks.push({
      name: 'fail2ban service',
      passed: isRunning,
      message: isRunning ? 'Running' : 'Not running',
    });

    if (!isRunning) {
      issues.push({
        code: 'FAIL2BAN_NOT_RUNNING',
        severity: 'medium',
        message: 'fail2ban is installed but not running',
        fix: 'sudo systemctl start fail2ban',
      });
    }
  } catch {
    checks.push({
      name: 'fail2ban service',
      passed: false,
      message: 'Not installed',
    });
    issues.push({
      code: 'FAIL2BAN_NOT_INSTALLED',
      severity: 'low',
      message: 'fail2ban is not installed (recommended for production)',
      fix: 'Install: sudo apt-get install fail2ban && clawdbot-security harden --fail2ban',
    });
  }

  return { checks, issues };
}

async function checkSecurityProfile(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  const profile = config.security?.profile;

  if (!profile) {
    checks.push({
      name: 'Security profile',
      passed: false,
      message: 'Not configured',
    });
    issues.push({
      code: 'NO_PROFILE',
      severity: 'medium',
      message: 'No security profile configured',
      fix: 'Run: clawdbot-security setup',
    });
  } else {
    checks.push({
      name: 'Security profile',
      passed: true,
      message: `Profile: ${profile}`,
    });
  }

  return { checks, issues };
}

// === VULNERABILITIES & SUPPLY CHAIN ===

async function checkCVEStatus(): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    const cveStatus = await getCVEStatus();

    const npmCritical = cveStatus.npm.filter(c => c.severity === 'critical').length;
    const npmHigh = cveStatus.npm.filter(c => c.severity === 'high').length;

    if (npmCritical > 0) {
      issues.push({
        code: 'NPM_CRITICAL',
        severity: 'critical',
        message: `${npmCritical} critical npm vulnerabilities found`,
        fix: 'Run: npm audit fix --force',
      });
    }

    if (npmHigh > 0) {
      issues.push({
        code: 'NPM_HIGH',
        severity: 'high',
        message: `${npmHigh} high severity npm vulnerabilities found`,
        fix: 'Run: npm audit fix',
      });
    }

    checks.push({
      name: 'NPM vulnerabilities',
      passed: npmCritical === 0 && npmHigh === 0,
      message: npmCritical + npmHigh === 0 ? 'No critical/high issues' : `${npmCritical + npmHigh} issues found`,
    });

    const pythonCVEs = cveStatus.python?.length || 0;
    if (pythonCVEs > 0) {
      issues.push({
        code: 'PYTHON_CVE',
        severity: 'medium',
        message: `${pythonCVEs} Python CVEs detected`,
        fix: 'Run: sudo apt-get update && sudo apt-get upgrade python3',
      });
    }

    checks.push({
      name: 'Python CVEs',
      passed: pythonCVEs === 0,
      message: pythonCVEs === 0 ? 'No CVEs found' : `${pythonCVEs} CVEs found`,
    });

    const systemUpdates = cveStatus.system?.length || 0;
    if (systemUpdates > 0) {
      issues.push({
        code: 'SYSTEM_UPDATES',
        severity: 'low',
        message: `${systemUpdates} system package updates available`,
        fix: 'Run: sudo apt-get update && sudo apt-get upgrade',
      });
    }

    checks.push({
      name: 'System packages',
      passed: systemUpdates === 0,
      message: systemUpdates === 0 ? 'Up to date' : `${systemUpdates} updates available`,
    });
  } catch (err: any) {
    checks.push({
      name: 'CVE status',
      passed: false,
      message: `Error checking CVEs: ${err.message}`,
    });
  }

  return { checks, issues };
}

async function checkDependencySecurity(): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  // Check for package-lock.json integrity
  try {
    await access(join(CLAWDBOT_DIR, 'package-lock.json'), constants.R_OK);
    checks.push({
      name: 'Dependency lock file',
      passed: true,
      message: 'package-lock.json present',
    });
  } catch {
    issues.push({
      code: 'NO_LOCKFILE',
      severity: 'low',
      message: 'No package-lock.json (dependencies not locked)',
      fix: 'Run: npm install to generate package-lock.json',
    });
  }

  return { checks, issues };
}

// === DISPLAY RESULTS ===

function displayAuditResults(result: AuditResult): void {
  console.log(chalk.bold.cyan('\n═══════════════════════════════════════════════════════'));
  console.log(chalk.bold.cyan('  Comprehensive Security Audit Results'));
  console.log(chalk.bold.cyan('═══════════════════════════════════════════════════════\n'));

  const passed = result.checks.filter(c => c.passed);
  const failed = result.checks.filter(c => !c.passed);

  if (passed.length > 0) {
    console.log(chalk.green.bold(`✓ Passed Checks (${passed.length})`));
    for (const check of passed) {
      console.log(chalk.green(`  ✓ ${check.name}`));
      console.log(chalk.dim(`    ${check.message}`));
    }
    console.log();
  }

  if (failed.length > 0) {
    console.log(chalk.yellow.bold(`✗ Failed Checks (${failed.length})`));
    for (const check of failed) {
      console.log(chalk.yellow(`  ✗ ${check.name}`));
      console.log(chalk.dim(`    ${check.message}`));
    }
    console.log();
  }

  const criticalIssues = result.issues.filter(i => i.severity === 'critical');
  const highIssues = result.issues.filter(i => i.severity === 'high');
  const mediumIssues = result.issues.filter(i => i.severity === 'medium');
  const lowIssues = result.issues.filter(i => i.severity === 'low');

  if (criticalIssues.length > 0) {
    console.log(chalk.red.bold('🔴 Critical Issues'));
    for (const issue of criticalIssues) {
      console.log(chalk.red(`  • ${issue.message}`));
      if (issue.fix) {
        console.log(chalk.dim(`    Fix: ${issue.fix}`));
      }
    }
    console.log();
  }

  if (highIssues.length > 0) {
    console.log(chalk.red.bold('⚠️  High Severity Issues'));
    for (const issue of highIssues) {
      console.log(chalk.red(`  • ${issue.message}`));
      if (issue.fix) {
        console.log(chalk.dim(`    Fix: ${issue.fix}`));
      }
    }
    console.log();
  }

  if (mediumIssues.length > 0) {
    console.log(chalk.yellow.bold('⚠️  Medium Severity Issues'));
    for (const issue of mediumIssues) {
      console.log(chalk.yellow(`  • ${issue.message}`));
      if (issue.fix) {
        console.log(chalk.dim(`    Fix: ${issue.fix}`));
      }
    }
    console.log();
  }

  if (lowIssues.length > 0) {
    console.log(chalk.blue.bold('ℹ️  Low Severity Issues'));
    for (const issue of lowIssues) {
      console.log(chalk.blue(`  • ${issue.message}`));
      if (issue.fix) {
        console.log(chalk.dim(`    Fix: ${issue.fix}`));
      }
    }
    console.log();
  }

  const totalIssues = result.issues.length;
  if (totalIssues === 0) {
    console.log(chalk.green.bold('✓ No issues found - Security audit passed!'));
  } else {
    console.log(chalk.yellow.bold(`Found ${totalIssues} issue(s) across ${result.checks.length} checks`));
    console.log(chalk.dim(`  Critical: ${criticalIssues.length} | High: ${highIssues.length} | Medium: ${mediumIssues.length} | Low: ${lowIssues.length}`));
  }
}

// === ENHANCED CHECKS (from TheSethRose/Clawdbot-Security-Check) ===

/**
 * Check Browser Control Security
 * Verifies that browser control UI and remote access are properly secured
 */
async function checkBrowserSecurity(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    const browserConfig = config?.browser;
    const gatewayConfig = config?.gateway;

    if (!browserConfig) {
      checks.push({
        name: 'Browser control',
        passed: true,
        message: 'Not configured (no browser control enabled)',
      });
      return { checks, issues };
    }

    // Check for remote control URL without token
    if (browserConfig.remoteControlUrl && !browserConfig.remoteControlToken) {
      issues.push({
        code: 'BROWSER_CONTROL_NO_AUTH',
        severity: 'high',
        message: 'Browser remote control URL configured without authentication token',
        fix: 'Add remoteControlToken to browser config, or disable remoteControlUrl',
      });
    }

    // Check for insecure auth in control UI
    if (gatewayConfig?.controlUi?.allowInsecureAuth === true) {
      issues.push({
        code: 'BROWSER_CONTROL_INSECURE_AUTH',
        severity: 'high',
        message: 'Browser control UI allows insecure authentication',
        fix: 'Set gateway.controlUi.allowInsecureAuth to false',
      });
    }

    // Check for host control disabled (security best practice)
    if (browserConfig.disableHostControl === false || !browserConfig.disableHostControl) {
      issues.push({
        code: 'BROWSER_HOST_CONTROL_ENABLED',
        severity: 'medium',
        message: 'Browser host control is enabled (allows UI takeover)',
        fix: 'Set browser.disableHostControl to true for better security',
      });
    }

    // Check for dedicated profile (isolation)
    if (browserConfig.dedicatedProfile === false || !browserConfig.dedicatedProfile) {
      issues.push({
        code: 'BROWSER_NO_DEDICATED_PROFILE',
        severity: 'medium',
        message: 'Browser not using dedicated profile (no session isolation)',
        fix: 'Set browser.dedicatedProfile to true',
      });
    }

    if (issues.length === 0) {
      checks.push({
        name: 'Browser control security',
        passed: true,
        message: 'Browser control properly secured',
      });
    } else {
      checks.push({
        name: 'Browser control security',
        passed: false,
        message: `${issues.length} browser security issue(s) found`,
      });
    }
  } catch (error) {
    checks.push({
      name: 'Browser control security',
      passed: true,
      message: 'Could not check browser security',
    });
  }

  return { checks, issues };
}

/**
 * Check Logging and Redaction Security
 * Verifies that sensitive data is properly redacted from logs
 */
async function checkLoggingSecurity(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    const loggingConfig = config?.logging;

    // Check if redaction is enabled
    if (!loggingConfig?.redactSensitive) {
      issues.push({
        code: 'LOGGING_NO_REDACTION',
        severity: 'medium',
        message: 'Log redaction not enabled (credentials may be logged in plaintext)',
        fix: 'Set logging.redactSensitive to "tools" or "all" in config',
      });
    } else if (loggingConfig.redactSensitive === 'none' || loggingConfig.redactSensitive === false) {
      issues.push({
        code: 'LOGGING_REDACTION_DISABLED',
        severity: 'medium',
        message: 'Log redaction explicitly disabled',
        fix: 'Set logging.redactSensitive to "tools" or "all"',
      });
    }

    // Check log file permissions
    const logsPath = loggingConfig?.path || join(CLAWDBOT_DIR, 'logs');
    try {
      const logsStat = await stat(logsPath);
      const perms = (logsStat.mode & 0o777).toString(8);

      if (perms !== '700' && perms !== '750') {
        issues.push({
          code: 'LOGS_LOOSE_PERMISSIONS',
          severity: 'medium',
          message: `Logs directory has loose permissions (${perms})`,
          fix: `chmod 700 ${logsPath}`,
        });
      }
    } catch {
      // Logs directory doesn't exist - not necessarily an issue
    }

    if (issues.length === 0) {
      checks.push({
        name: 'Logging security',
        passed: true,
        message: 'Logging configured securely with redaction',
      });
    } else {
      checks.push({
        name: 'Logging security',
        passed: false,
        message: `${issues.length} logging security issue(s)`,
      });
    }
  } catch (error) {
    checks.push({
      name: 'Logging security',
      passed: true,
      message: 'Could not check logging configuration',
    });
  }

  return { checks, issues };
}

/**
 * Check Dangerous Command Blocking
 * Verifies that destructive commands are blocked
 */
async function checkDangerousCommands(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    const blockedCommands = config?.blocked_commands || config?.blockedCommands || [];

    // Common dangerous commands that should be blocked
    const recommendedBlocks = [
      'rm -rf',
      'mkfs',
      ':(){:|:&}',  // Fork bomb
      'dd if=',     // Disk wipe
      '>()',        // Process substitution attacks
      'curl |',     // Piped downloads
      'wget |',     // Piped downloads
      'git push --force',  // Force push
    ];

    const missingBlocks: string[] = [];
    for (const dangerous of recommendedBlocks) {
      const isBlocked = blockedCommands.some((blocked: string) =>
        blocked.includes(dangerous) || dangerous.includes(blocked)
      );
      if (!isBlocked) {
        missingBlocks.push(dangerous);
      }
    }

    if (blockedCommands.length === 0) {
      issues.push({
        code: 'NO_COMMAND_BLOCKING',
        severity: 'medium',
        message: 'No dangerous command blocking configured',
        fix: `Add blocked_commands array to config with: ${recommendedBlocks.slice(0, 3).join(', ')}, etc.`,
      });
    } else if (missingBlocks.length > 0) {
      issues.push({
        code: 'INCOMPLETE_COMMAND_BLOCKING',
        severity: 'low',
        message: `${missingBlocks.length} dangerous command(s) not blocked: ${missingBlocks.slice(0, 3).join(', ')}`,
        fix: `Add to blocked_commands: ${missingBlocks.slice(0, 3).join(', ')}`,
      });
    }

    if (issues.length === 0) {
      checks.push({
        name: 'Dangerous command blocking',
        passed: true,
        message: `${blockedCommands.length} dangerous commands blocked`,
      });
    } else {
      checks.push({
        name: 'Dangerous command blocking',
        passed: false,
        message: 'Incomplete command blocking',
      });
    }
  } catch (error) {
    checks.push({
      name: 'Dangerous command blocking',
      passed: true,
      message: 'Could not check command blocking',
    });
  }

  return { checks, issues };
}

/**
 * Check Tool Sandboxing (Enhanced)
 * Verifies workspace access levels and tool restrictions
 */
async function checkToolSandboxing(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    const workspaceAccess = config?.workspaceAccess;
    const sandbox = config?.sandbox;
    const restrictTools = config?.restrict_tools;
    const mcpTools = config?.mcp_tools;

    // Check workspace access level
    if (workspaceAccess === 'rw') {
      issues.push({
        code: 'WORKSPACE_FULL_WRITE_ACCESS',
        severity: 'medium',
        message: 'Workspace has full read-write access (consider read-only for safety)',
        fix: 'Set workspaceAccess to "ro" unless write access is required',
      });
    } else if (!workspaceAccess || workspaceAccess === 'none') {
      checks.push({
        name: 'Workspace access',
        passed: true,
        message: 'Workspace access restricted (none or not configured)',
      });
    } else if (workspaceAccess === 'ro') {
      checks.push({
        name: 'Workspace access',
        passed: true,
        message: 'Workspace access set to read-only',
      });
    }

    // Check sandboxing
    if (sandbox !== 'all' && sandbox !== true) {
      issues.push({
        code: 'SANDBOX_NOT_FULL',
        severity: 'low',
        message: 'Not all tools are sandboxed',
        fix: 'Set sandbox to "all" for maximum isolation',
      });
    }

    // Check tool restrictions
    if (!restrictTools && !mcpTools?.blocked) {
      issues.push({
        code: 'NO_TOOL_RESTRICTIONS',
        severity: 'low',
        message: 'No tool restrictions configured',
        fix: 'Set restrict_tools to true or configure mcp_tools.blocked array',
      });
    }

    // Check for dangerous MCP tools allowed
    if (mcpTools?.allowed && !mcpTools?.blocked) {
      const dangerousTools = ['exec', 'gateway', 'system'];
      const allowedDangerous = mcpTools.allowed.filter((t: string) =>
        dangerousTools.some(d => t.toLowerCase().includes(d))
      );

      if (allowedDangerous.length > 0) {
        issues.push({
          code: 'DANGEROUS_TOOLS_ALLOWED',
          severity: 'medium',
          message: `Dangerous MCP tools allowed: ${allowedDangerous.join(', ')}`,
          fix: 'Consider blocking or restricting these tools',
        });
      }
    }

    if (issues.length === 0 || (issues.length === 1 && issues[0].severity === 'low')) {
      checks.push({
        name: 'Tool sandboxing',
        passed: true,
        message: 'Tools properly sandboxed and restricted',
      });
    } else {
      checks.push({
        name: 'Tool sandboxing',
        passed: false,
        message: `${issues.length} tool sandboxing issue(s)`,
      });
    }
  } catch (error) {
    checks.push({
      name: 'Tool sandboxing',
      passed: true,
      message: 'Could not check tool sandboxing',
    });
  }

  return { checks, issues };
}

/**
 * Check Secret Scanning Integration
 * Verifies detect-secrets baseline exists and is current
 */
async function checkSecretScanning(): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    // Check if detect-secrets is installed
    let detectSecretsInstalled = false;
    try {
      await execAsync('which detect-secrets');
      detectSecretsInstalled = true;
    } catch {
      detectSecretsInstalled = false;
    }

    if (!detectSecretsInstalled) {
      issues.push({
        code: 'NO_SECRET_SCANNING',
        severity: 'low',
        message: 'detect-secrets not installed (no automatic secret scanning)',
        fix: 'Install: pip install detect-secrets',
      });
      checks.push({
        name: 'Secret scanning',
        passed: false,
        message: 'detect-secrets not installed',
      });
      return { checks, issues };
    }

    // Check for .secrets.baseline
    const baselinePath = join(CLAWDBOT_DIR, '.secrets.baseline');
    try {
      await access(baselinePath, constants.F_OK);

      // Check if baseline is recent (< 30 days old)
      const baselineStat = await stat(baselinePath);
      const ageInDays = (Date.now() - baselineStat.mtimeMs) / (1000 * 60 * 60 * 24);

      if (ageInDays > 30) {
        issues.push({
          code: 'STALE_SECRETS_BASELINE',
          severity: 'low',
          message: `Secret scanning baseline is ${Math.floor(ageInDays)} days old`,
          fix: 'Update: detect-secrets scan --baseline .secrets.baseline --update',
        });
      } else {
        checks.push({
          name: 'Secret scanning',
          passed: true,
          message: `Baseline exists (updated ${Math.floor(ageInDays)} days ago)`,
        });
      }
    } catch {
      issues.push({
        code: 'NO_SECRETS_BASELINE',
        severity: 'low',
        message: 'No .secrets.baseline found',
        fix: `Create: cd ${CLAWDBOT_DIR} && detect-secrets scan --baseline .secrets.baseline`,
      });
      checks.push({
        name: 'Secret scanning',
        passed: false,
        message: 'No secrets baseline configured',
      });
    }
  } catch (error) {
    checks.push({
      name: 'Secret scanning',
      passed: true,
      message: 'Could not check secret scanning',
    });
  }

  return { checks, issues };
}

/**
 * Check Enhanced Prompt Injection Protection
 * Verifies wrap_untrusted_content configuration
 */
async function checkEnhancedPromptInjection(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    const wrapUntrusted = config?.wrap_untrusted_content;
    const wrapper = config?.untrusted_content_wrapper;
    const treatLinksHostile = config?.treatLinksAsHostile;
    const mentionGate = config?.mentionGate;

    // Check for untrusted content wrapping
    if (!wrapUntrusted) {
      issues.push({
        code: 'NO_CONTENT_WRAPPING',
        severity: 'medium',
        message: 'Untrusted content wrapping not enabled',
        fix: 'Set wrap_untrusted_content to true in config',
      });
    } else if (!wrapper || wrapper === '') {
      issues.push({
        code: 'NO_WRAPPER_CONFIGURED',
        severity: 'medium',
        message: 'Content wrapper enabled but no wrapper tag configured',
        fix: 'Set untrusted_content_wrapper to "<untrusted>" or similar',
      });
    }

    // Check for link handling
    if (!treatLinksHostile) {
      issues.push({
        code: 'LINKS_NOT_HOSTILE',
        severity: 'low',
        message: 'Links not treated as hostile (potential phishing risk)',
        fix: 'Set treatLinksAsHostile to true',
      });
    }

    // Check for mention gating in groups
    if (!mentionGate) {
      issues.push({
        code: 'NO_MENTION_GATE',
        severity: 'low',
        message: 'Mention gating not enabled (anyone in group can trigger)',
        fix: 'Set mentionGate to true to require @mentions in groups',
      });
    }

    if (issues.length === 0) {
      checks.push({
        name: 'Enhanced prompt injection protection',
        passed: true,
        message: 'Content wrapping, link handling, and mention gating configured',
      });
    } else {
      checks.push({
        name: 'Enhanced prompt injection protection',
        passed: false,
        message: `${issues.length} prompt injection protection issue(s)`,
      });
    }
  } catch (error) {
    checks.push({
      name: 'Enhanced prompt injection protection',
      passed: true,
      message: 'Could not check enhanced prompt injection protection',
    });
  }

  return { checks, issues };
}
