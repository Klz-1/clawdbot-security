/**
 * Score Command - Calculate security score
 */

import { Command } from 'commander';
import chalk from 'chalk';
import {
  loadClawdbotConfig,
  isClawdbotInstalled,
} from '../core/config.js';
import { calculateSecurityScore, getScoreRating } from '../scoring/calculator.js';

export function registerScoreCommand(program: Command): void {
  program
    .command('score')
    .description('Calculate security score (0-100)')
    .option('--json', 'Output as JSON')
    .action(async (options) => {
      try {
        const installed = await isClawdbotInstalled();
        if (!installed) {
          console.error(
            chalk.red('Error:'),
            'Clawdbot installation not found'
          );
          process.exit(1);
        }

        const config = await loadClawdbotConfig();
        const scoreResult = await calculateSecurityScore(config);

        if (options.json) {
          console.log(JSON.stringify(scoreResult, null, 2));
          return;
        }

        // Display score
        const scoreColor = getScoreColor(scoreResult.score);
        const rating = getScoreRating(scoreResult.score);

        console.log();
        console.log(
          chalk.bold('Security Score: ') +
            chalk.bold[scoreColor](`${scoreResult.score}/100`) +
            chalk.dim(` (${rating})`)
        );

        if (scoreResult.deductions.length > 0) {
          console.log();
          console.log(chalk.bold('Score Breakdown:'));

          // Group deductions by category
          const byCategory = scoreResult.deductions.reduce((acc, d) => {
            if (!acc[d.category]) acc[d.category] = [];
            acc[d.category].push(d);
            return acc;
          }, {} as Record<string, typeof scoreResult.deductions>);

          for (const [category, deductions] of Object.entries(byCategory)) {
            const totalPenalty = deductions.reduce((sum, d) => sum + d.penalty, 0);
            console.log(
              `  ${chalk.yellow(category)}: ${chalk.red(`-${totalPenalty}`)} points`
            );
            for (const d of deductions) {
              console.log(`    ${chalk.dim(d.reason)}`);
            }
          }
        }

        if (scoreResult.recommendations.length > 0) {
          console.log();
          console.log(chalk.bold('Recommendations:'));
          for (const rec of scoreResult.recommendations) {
            console.log(`  ${chalk.cyan('•')} ${rec}`);
          }
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
