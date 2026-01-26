/**
 * Status Command - Show security overview
 */

import { Command } from 'commander';
import chalk from 'chalk';
import {
  loadClawdbotConfig,
  loadSecurityConfig,
  isClawdbotInstalled,
} from '../core/config.js';
import { calculateSecurityScore, getScoreRating } from '../scoring/calculator.js';

export function registerStatusCommand(program: Command): void {
  program
    .command('status')
    .description('Show overall security status')
    .option('--json', 'Output as JSON')
    .action(async (options) => {
      try {
        // Check if Clawdbot is installed
        const installed = await isClawdbotInstalled();
        if (!installed) {
          console.error(
            chalk.red('Error:'),
            'Clawdbot installation not found at ~/.clawdbot/'
          );
          console.log(
            chalk.dim('\nInstall Clawdbot first:'),
            'npm install -g clawdbot'
          );
          process.exit(1);
        }

        // Load configurations
        const config = await loadClawdbotConfig();
        const securityConfig = await loadSecurityConfig();

        // Calculate security score
        const scoreResult = await calculateSecurityScore(config);

        if (options.json) {
          console.log(
            JSON.stringify(
              {
                installed: true,
                profile: securityConfig?.profile || 'none',
                score: scoreResult.score,
                rating: getScoreRating(scoreResult.score),
                deductions: scoreResult.deductions,
                recommendations: scoreResult.recommendations,
                lastAudit: securityConfig?.lastAudit,
              },
              null,
              2
            )
          );
          return;
        }

        // Display formatted status
        console.log();
        console.log(chalk.bold.cyan('┌─────────────────────────────────────────┐'));
        console.log(chalk.bold.cyan('│  Clawdbot Security Status               │'));
        console.log(chalk.bold.cyan('├─────────────────────────────────────────┤'));
        console.log(chalk.bold.cyan('│                                         │'));

        // Profile
        const profile = securityConfig?.profile || chalk.red('NOT CONFIGURED');
        console.log(
          chalk.bold.cyan('│  ') +
            chalk.bold('Profile:') +
            ` ${profile}`.padEnd(32) +
            chalk.bold.cyan('│')
        );

        // Security Score
        const scoreColor = getScoreColor(scoreResult.score);
        const scoreText = `${scoreResult.score}/100`;
        console.log(
          chalk.bold.cyan('│  ') +
            chalk.bold('Security Score:') +
            ` ${chalk[scoreColor](scoreText)}`.padEnd(32) +
            chalk.bold.cyan('│')
        );

        // Rating
        const rating = getScoreRating(scoreResult.score);
        console.log(
          chalk.bold.cyan('│  ') +
            chalk.bold('Rating:') +
            ` ${chalk[scoreColor](rating)}`.padEnd(32) +
            chalk.bold.cyan('│')
        );

        console.log(chalk.bold.cyan('│                                         │'));
        console.log(chalk.bold.cyan('└─────────────────────────────────────────┘'));

        // Show deductions if any
        if (scoreResult.deductions.length > 0) {
          console.log();
          console.log(chalk.bold('Security Issues:'));
          for (const deduction of scoreResult.deductions) {
            console.log(
              `  ${chalk.red('●')} ${deduction.reason} ${chalk.dim(`(-${deduction.penalty} points)`)}`
            );
          }
        }

        // Show recommendations
        if (scoreResult.recommendations.length > 0) {
          console.log();
          console.log(chalk.bold('Recommendations:'));
          for (const rec of scoreResult.recommendations) {
            console.log(`  ${chalk.yellow('→')} ${rec}`);
          }
        }

        console.log();

        // Suggest next steps based on score
        if (scoreResult.score < 70) {
          console.log(
            chalk.yellow('⚠  ') +
              chalk.bold('Action required:') +
              ' Run ' +
              chalk.cyan('clawdbot-security setup') +
              ' to improve security'
          );
        } else if (scoreResult.score < 90) {
          console.log(
            chalk.blue('ℹ  ') +
              'Run ' +
              chalk.cyan('clawdbot-security harden') +
              ' to achieve excellent security'
          );
        } else {
          console.log(
            chalk.green('✓  ') +
              chalk.bold('Security configuration is excellent!')
          );
        }

        console.log();
      } catch (err: any) {
        console.error(chalk.red('Error:'), err.message);
        process.exit(1);
      }
    });
}

function getScoreColor(score: number): 'green' | 'yellow' | 'red' {
  if (score >= 90) return 'green';
  if (score >= 70) return 'yellow';
  return 'red';
}
