/**
 * Audit Command - Comprehensive security audit
 * Includes mDNS/Avahi detection (CVE-2025-MDNS)
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { exec } from 'child_process';
import { promisify } from 'util';
import { access, stat } from 'fs/promises';
import { constants } from 'fs';
import { loadClawdbotConfig } from '../core/config.js';
import { calculateSecurityScore } from '../scoring/calculator.js';
import { getCVEStatus } from '../monitoring/cve-checker.js';
import type { AuditResult, AuditIssue, AuditCheck, Severity, ClawdbotConfig } from '../core/types.js';

const execAsync = promisify(exec);

interface ServiceStatus {
  running: boolean;
  enabled: boolean;
}

export function registerAuditCommand(program: Command): void {
  program
    .command('audit')
    .description('Run comprehensive security audit')
    .option('--deep', 'Run deep audit with CVE checks')
    .option('--json', 'Output as JSON')
    .action(async (options) => {
      try {
        console.log(chalk.bold.cyan('\n🔍 Running Security Audit...\n'));

        const result = await runSecurityAudit(options.deep);

        if (options.json) {
          console.log(JSON.stringify(result, null, 2));
          return;
        }

        // Display results
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

async function runSecurityAudit(deep: boolean = false): Promise<AuditResult> {
  const issues: AuditIssue[] = [];
  const checks: AuditCheck[] = [];

  // Load configuration
  const config = await loadClawdbotConfig() || {};

  // 1. File Permissions Check
  console.log(chalk.dim('  • Checking file permissions...'));
  const filePermsResult = await checkFilePermissions();
  checks.push(...filePermsResult.checks);
  issues.push(...filePermsResult.issues);

  // 2. Gateway Authentication Check
  console.log(chalk.dim('  • Checking gateway authentication...'));
  const gatewayResult = await checkGatewayAuth(config);
  checks.push(...gatewayResult.checks);
  issues.push(...gatewayResult.issues);

  // 3. Channel Policies Check
  console.log(chalk.dim('  • Checking channel policies...'));
  const channelResult = await checkChannelPolicies(config);
  checks.push(...channelResult.checks);
  issues.push(...channelResult.issues);

  // 4. mDNS/Avahi Service Discovery Check (NEW - from security audit)
  console.log(chalk.dim('  • Checking mDNS/Avahi service discovery...'));
  const mdnsResult = await checkServiceDiscovery();
  checks.push(...mdnsResult.checks);
  issues.push(...mdnsResult.issues);

  // 5. nginx Configuration Check
  console.log(chalk.dim('  • Checking nginx configuration...'));
  const nginxResult = await checkNginxConfig();
  checks.push(...nginxResult.checks);
  issues.push(...nginxResult.issues);

  // 6. fail2ban Status Check
  console.log(chalk.dim('  • Checking fail2ban status...'));
  const fail2banResult = await checkFail2ban();
  checks.push(...fail2banResult.checks);
  issues.push(...fail2banResult.issues);

  // 7. Security Profile Check
  console.log(chalk.dim('  • Checking security profile...'));
  const profileResult = await checkSecurityProfile(config);
  checks.push(...profileResult.checks);
  issues.push(...profileResult.issues);

  // 8. CVE Status (only in deep mode)
  if (deep) {
    console.log(chalk.dim('  • Checking CVE status (deep scan)...'));
    const cveResult = await checkCVEStatus();
    checks.push(...cveResult.checks);
    issues.push(...cveResult.issues);
  }

  return {
    ok: issues.filter(i => i.severity === 'critical' || i.severity === 'high').length === 0,
    issues,
    checks,
  };
}

async function checkFilePermissions(): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  const filesToCheck = [
    { path: `${process.env.HOME}/.clawdbot/clawdbot.json`, name: 'Config file', expectedMax: 0o600 },
    { path: `${process.env.HOME}/.clawdbot`, name: 'State directory', expectedMax: 0o700 },
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
          code: 'FILE_PERMS',
          severity: 'medium',
          message: `${file.name} has overly permissive permissions (${perms.toString(8)})`,
          fix: `chmod ${file.expectedMax.toString(8)} ${file.path}`,
        });
      }
    } catch (err) {
      // File doesn't exist - not necessarily an issue
      checks.push({
        name: `${file.name} permissions`,
        passed: true,
        message: 'File not found (may be intentional)',
      });
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
  if (bind && bind !== 'loopback' && bind !== '127.0.0.1') {
    issues.push({
      code: 'GATEWAY_BIND',
      severity: 'medium',
      message: `Gateway bound to ${bind} (not localhost)`,
      fix: 'Consider using Tailscale serve instead of exposing gateway publicly',
    });
  }

  return { checks, issues };
}

async function checkChannelPolicies(config: any): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  // Telegram DM policy
  const telegramDM = config.channels?.telegram?.dmPolicy;
  if (telegramDM === 'open') {
    checks.push({
      name: 'Telegram DM policy',
      passed: false,
      message: 'Open to all users',
    });
    issues.push({
      code: 'TELEGRAM_DM_OPEN',
      severity: 'high',
      message: 'Telegram DMs are open to all users',
      fix: 'Set channels.telegram.dmPolicy to "pairing" or "allowlist"',
    });
  } else {
    checks.push({
      name: 'Telegram DM policy',
      passed: true,
      message: telegramDM || 'Not configured',
    });
  }

  // Discord DM policy
  const discordDM = config.channels?.discord?.dmPolicy;
  if (discordDM === 'open') {
    checks.push({
      name: 'Discord DM policy',
      passed: false,
      message: 'Open to all users',
    });
    issues.push({
      code: 'DISCORD_DM_OPEN',
      severity: 'high',
      message: 'Discord DMs are open to all users',
      fix: 'Set channels.discord.dmPolicy to "pairing" or "allowlist"',
    });
  } else {
    checks.push({
      name: 'Discord DM policy',
      passed: true,
      message: discordDM || 'Not configured',
    });
  }

  return { checks, issues };
}

/**
 * Check for mDNS/Avahi service discovery exposure
 * Based on security audit report CVE-2025-MDNS
 */
async function checkServiceDiscovery(): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    // Check if Avahi daemon is running
    const avahiStatus = await checkService('avahi-daemon');

    if (avahiStatus.running) {
      checks.push({
        name: 'mDNS/Avahi service',
        passed: false,
        message: 'Avahi daemon is running',
      });
      issues.push({
        code: 'MDNS_ACTIVE',
        severity: 'high',
        message: 'Avahi daemon is broadcasting mDNS service discovery on LAN',
        fix: 'Disable Avahi: sudo systemctl stop avahi-daemon && sudo systemctl disable avahi-daemon && sudo systemctl disable avahi-daemon.socket',
      });
    } else {
      checks.push({
        name: 'mDNS/Avahi service',
        passed: true,
        message: 'Avahi daemon is not running',
      });
    }

    // Check if Avahi is enabled (will start on boot)
    if (!avahiStatus.running && avahiStatus.enabled) {
      issues.push({
        code: 'MDNS_ENABLED',
        severity: 'medium',
        message: 'Avahi daemon is disabled but will start on boot',
        fix: 'Disable Avahi permanently: sudo systemctl disable avahi-daemon && sudo systemctl disable avahi-daemon.socket',
      });
    }

    // Check for mDNS broadcasts using avahi-browse (if available)
    try {
      const { stdout } = await execAsync('timeout 2 avahi-browse -a -t 2>&1 || true');
      if (stdout.includes('_clawdbot') || stdout.includes('clawdbot-gw')) {
        checks.push({
          name: 'mDNS broadcasts',
          passed: false,
          message: 'Clawdbot services detected in mDNS broadcasts',
        });
        issues.push({
          code: 'MDNS_BROADCAST',
          severity: 'high',
          message: 'Clawdbot services are being broadcast via mDNS (visible to LAN)',
          fix: 'Stop Avahi: sudo systemctl stop avahi-daemon',
        });
      }
    } catch (err) {
      // avahi-browse not available or timeout - not a problem
    }

  } catch (err) {
    // Avahi not installed - this is actually good
    checks.push({
      name: 'mDNS/Avahi service',
      passed: true,
      message: 'Avahi not installed',
    });
  }

  return { checks, issues };
}

async function checkNginxConfig(): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    // Check if nginx is installed
    await execAsync('which nginx');

    // Check if nginx is running
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

    // Check if clawdbot security config exists
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

  } catch (err) {
    // nginx not installed
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
    // Check if fail2ban is installed
    await execAsync('which fail2ban-client');

    // Check if fail2ban is running
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

    // Check for clawdbot jails
    if (isRunning) {
      try {
        const { stdout } = await execAsync('sudo fail2ban-client status 2>/dev/null || true');
        if (stdout.includes('nginx-rate-limit') || stdout.includes('clawdbot')) {
          checks.push({
            name: 'fail2ban jails',
            passed: true,
            message: 'Clawdbot jails configured',
          });
        } else {
          checks.push({
            name: 'fail2ban jails',
            passed: false,
            message: 'No Clawdbot jails found',
          });
          issues.push({
            code: 'FAIL2BAN_NO_JAILS',
            severity: 'medium',
            message: 'fail2ban has no Clawdbot-specific jails',
            fix: 'Run: clawdbot-security harden --fail2ban',
          });
        }
      } catch {
        // Can't check jails (probably permissions)
      }
    }

  } catch (err) {
    // fail2ban not installed
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

async function checkCVEStatus(): Promise<{ checks: AuditCheck[]; issues: AuditIssue[] }> {
  const checks: AuditCheck[] = [];
  const issues: AuditIssue[] = [];

  try {
    const cveStatus = await getCVEStatus();

    // Check npm vulnerabilities (filter by severity)
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

    // Check Python CVEs
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

    // Check system updates (system is an array of packages)
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

async function checkService(serviceName: string): Promise<ServiceStatus> {
  try {
    const { stdout: activeOut } = await execAsync(`systemctl is-active ${serviceName} 2>/dev/null || true`);
    const { stdout: enabledOut } = await execAsync(`systemctl is-enabled ${serviceName} 2>/dev/null || true`);

    return {
      running: activeOut.trim() === 'active',
      enabled: enabledOut.trim() === 'enabled',
    };
  } catch {
    return { running: false, enabled: false };
  }
}

function displayAuditResults(result: AuditResult): void {
  console.log(chalk.bold.cyan('Audit Results\n'));

  // Group checks by status
  const passed = result.checks.filter(c => c.passed);
  const failed = result.checks.filter(c => !c.passed);

  // Display passed checks
  if (passed.length > 0) {
    console.log(chalk.green.bold('✓ Passed Checks'));
    for (const check of passed) {
      console.log(chalk.green(`  ✓ ${check.name}`));
      console.log(chalk.dim(`    ${check.message}`));
    }
    console.log();
  }

  // Display failed checks
  if (failed.length > 0) {
    console.log(chalk.yellow.bold('✗ Failed Checks'));
    for (const check of failed) {
      console.log(chalk.yellow(`  ✗ ${check.name}`));
      console.log(chalk.dim(`    ${check.message}`));
    }
    console.log();
  }

  // Display issues by severity
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

  // Summary
  const totalIssues = result.issues.length;
  if (totalIssues === 0) {
    console.log(chalk.green.bold('✓ No issues found - Security audit passed!'));
  } else {
    console.log(chalk.yellow.bold(`Found ${totalIssues} issue(s) across ${result.checks.length} checks`));
  }
}
