/**
 * Dashboard Command - Security dashboard
 * Phase 4 Implementation (CLI version)
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { loadClawdbotConfig, loadSecurityConfig } from '../core/config.js';
import { calculateSecurityScore } from '../scoring/calculator.js';
import { getSecurityMetrics } from '../hooks/event-collector.js';
import { getDeploymentStatus } from '../deployment/deployer.js';

export function registerDashboardCommand(program: Command): void {
  program
    .command('dashboard')
    .description('Show security dashboard')
    .option('--refresh <seconds>', 'Auto-refresh interval (0 = no refresh)', '0')
    .action(async (options) => {
      const refreshInterval = parseInt(options.refresh);

      async function display() {
        console.clear();
        console.log(chalk.bold.cyan('╔═══════════════════════════════════════════════════════╗'));
        console.log(chalk.bold.cyan('║       Clawdbot Security Dashboard                     ║'));
        console.log(chalk.bold.cyan('╚═══════════════════════════════════════════════════════╝\n'));

        // Security Score
        const config = await loadClawdbotConfig();
        const secConfig = await loadSecurityConfig();
        const score = await calculateSecurityScore(config);
        const scoreColor = score.score >= 90 ? 'green' : score.score >= 70 ? 'yellow' : 'red';

        console.log(chalk.bold('Security Score:'), chalk[scoreColor](`${score.score}/100`));
        console.log(chalk.dim(`Profile: ${secConfig?.profile || 'Not configured'}\n`));

        // Deployment Status
        const deployment = await getDeploymentStatus();
        console.log(chalk.bold('Deployment Status:'));
        console.log(`  nginx:    ${deployment.nginx.installed ? chalk.green('✓ Installed') : chalk.gray('✗ Not installed')} ${deployment.nginx.deployed ? chalk.green('(deployed)') : ''}`);
        console.log(`  fail2ban: ${deployment.fail2ban.installed ? chalk.green('✓ Installed') : chalk.gray('✗ Not installed')} ${deployment.fail2ban.deployed ? chalk.green('(deployed)') : ''}`);
        console.log(`  sudo:     ${deployment.sudo ? chalk.green('✓ Available') : chalk.yellow('✗ Not available')}\n`);

        // Recent Events
        const metrics = await getSecurityMetrics(24);
        console.log(chalk.bold('Recent Events (24h):'));
        console.log(`  Total: ${metrics.total}`);
        console.log(`  By Severity:`);
        for (const [severity, count] of Object.entries(metrics.bySeverity)) {
          const color = severity === 'critical' || severity === 'high' ? 'red' : severity === 'medium' ? 'yellow' : 'blue';
          console.log(`    ${chalk[color](severity)}: ${count}`);
        }
        console.log(`  Unique IPs: ${metrics.uniqueIPs}\n`);

        // Recommendations
        if (score.recommendations.length > 0) {
          console.log(chalk.bold('Recommendations:'));
          score.recommendations.slice(0, 3).forEach(rec => {
            console.log(chalk.yellow(`  • ${rec}`));
          });
        }

        console.log(chalk.dim('\nPress Ctrl+C to exit'));
      }

      await display();

      if (refreshInterval > 0) {
        setInterval(display, refreshInterval * 1000);
      }
    });
}
