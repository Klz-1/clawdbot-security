/**
 * Logs Command - View security audit logs
 * Phase 4 Implementation
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { readAuditLog } from '../hooks/event-collector.js';

export function registerLogsCommand(program: Command): void {
  program
    .command('logs')
    .description('View security audit logs')
    .option('--since <period>', 'Show logs since period (e.g., 1h, 24h, 7d)', '24h')
    .option('--severity <level>', 'Filter by severity (low, medium, high, critical)')
    .option('--type <type>', 'Filter by event type')
    .option('--limit <n>', 'Limit number of results', '50')
    .option('--json', 'Output as JSON')
    .action(async (options) => {
      try {
        const since = parseTimePeriod(options.since);
        const events = await readAuditLog({
          since,
          severity: options.severity,
          type: options.type,
          limit: parseInt(options.limit),
        });

        if (events.length === 0) {
          console.log(chalk.dim('No security events found'));
          return;
        }

        if (options.json) {
          console.log(JSON.stringify(events, null, 2));
          return;
        }

        console.log(chalk.bold.cyan(`Security Audit Log (${events.length} events)\n`));

        for (const event of events.reverse()) {
          const time = new Date(event.timestamp).toLocaleString();
          const severityColor = getSeverityColor(event.severity);
          const severityBadge = chalk[severityColor](event.severity.toUpperCase().padEnd(8));

          console.log(`${chalk.dim(time)} ${severityBadge} ${event.type}`);
          if (event.ip) console.log(chalk.dim(`  IP: ${event.ip}`));
          if (event.user) console.log(chalk.dim(`  User: ${event.user}`));
          if (event.metadata && Object.keys(event.metadata).length > 0) {
            console.log(chalk.dim(`  ${JSON.stringify(event.metadata)}`));
          }
          console.log();
        }
      } catch (err: any) {
        console.error(chalk.red('Error:'), err.message);
        process.exit(1);
      }
    });
}

function parseTimePeriod(period: string): Date {
  const match = period.match(/^(\d+)([hdwm])$/);
  if (!match) return new Date(Date.now() - 24 * 60 * 60 * 1000);
  const [, value, unit] = match;
  const multipliers: Record<string, number> = {
    h: 60 * 60 * 1000, d: 24 * 60 * 60 * 1000,
    w: 7 * 24 * 60 * 60 * 1000, m: 30 * 24 * 60 * 60 * 1000,
  };
  return new Date(Date.now() - parseInt(value) * multipliers[unit]);
}

function getSeverityColor(severity: string): 'red' | 'yellow' | 'blue' | 'gray' {
  return severity === 'critical' || severity === 'high' ? 'red' :
         severity === 'medium' ? 'yellow' : severity === 'low' ? 'blue' : 'gray';
}
