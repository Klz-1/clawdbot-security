/**
 * Security Event Collector Hook
 * Logs all security events to JSONL audit log
 */

import { appendFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import type { SecurityEvent, HookContext } from './types.js';

const LOG_DIR = join(homedir(), '.clawdbot', 'logs');
const AUDIT_LOG = join(LOG_DIR, 'security-audit.jsonl');

/**
 * Ensure log directory exists
 */
async function ensureLogDir(): Promise<void> {
  try {
    await mkdir(LOG_DIR, { recursive: true });
  } catch {
    // Directory already exists
  }
}

/**
 * Log security event to JSONL file
 */
async function logEvent(event: SecurityEvent): Promise<void> {
  await ensureLogDir();

  const logEntry = {
    timestamp: event.timestamp,
    type: event.type,
    severity: event.severity,
    source: event.source,
    ip: event.ip,
    user: event.user,
    metadata: event.metadata,
  };

  const line = JSON.stringify(logEntry) + '\n';
  await appendFile(AUDIT_LOG, line);
}

/**
 * Event collector hook handler
 */
export async function collectSecurityEvent(context: HookContext): Promise<void> {
  const { event } = context;

  try {
    await logEvent(event);

    // Also log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.log(`[Security Event] ${event.type} (${event.severity})`);
    }
  } catch (err) {
    // Don't fail on logging errors
    console.error('Failed to log security event:', err);
  }
}

/**
 * Read audit log entries
 */
export async function readAuditLog(options: {
  since?: Date;
  severity?: string;
  type?: string;
  limit?: number;
} = {}): Promise<SecurityEvent[]> {
  const { readFile } = await import('fs/promises');

  try {
    const content = await readFile(AUDIT_LOG, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);
    let events = lines.map(line => JSON.parse(line) as SecurityEvent);

    // Apply filters
    if (options.since) {
      events = events.filter(e => new Date(e.timestamp) >= options.since!);
    }

    if (options.severity) {
      events = events.filter(e => e.severity === options.severity);
    }

    if (options.type) {
      events = events.filter(e => e.type === options.type);
    }

    // Apply limit
    if (options.limit) {
      events = events.slice(-options.limit);
    }

    return events;
  } catch {
    return [];
  }
}

/**
 * Get security event metrics
 */
export async function getSecurityMetrics(periodHours: number = 24): Promise<{
  total: number;
  bySeverity: Record<string, number>;
  byType: Record<string, number>;
  uniqueIPs: number;
}> {
  const since = new Date(Date.now() - periodHours * 60 * 60 * 1000);
  const events = await readAuditLog({ since });

  const bySeverity: Record<string, number> = {};
  const byType: Record<string, number> = {};
  const ips = new Set<string>();

  for (const event of events) {
    bySeverity[event.severity] = (bySeverity[event.severity] || 0) + 1;
    byType[event.type] = (byType[event.type] || 0) + 1;
    if (event.ip) {
      ips.add(event.ip);
    }
  }

  return {
    total: events.length,
    bySeverity,
    byType,
    uniqueIPs: ips.size,
  };
}

/**
 * Emit a security event (for testing and integration)
 */
export async function emitSecurityEvent(event: Omit<SecurityEvent, 'timestamp'>): Promise<void> {
  const fullEvent: SecurityEvent = {
    ...event,
    timestamp: new Date().toISOString(),
  };

  await collectSecurityEvent({ event: fullEvent, config: {} });
}
