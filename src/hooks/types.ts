/**
 * Security Hooks Type Definitions
 */

export type SecurityEventType =
  | 'security:rate-limit'
  | 'security:path-traversal'
  | 'security:auth-failure'
  | 'security:config-change'
  | 'security:ip-banned'
  | 'security:suspicious-activity'
  | 'security:cve-discovered';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface SecurityEvent {
  type: SecurityEventType;
  severity: Severity;
  timestamp: string;
  source: string;
  ip?: string;
  user?: string;
  metadata: Record<string, any>;
}

export interface HookContext {
  event: SecurityEvent;
  config: any;
}

export type HookHandler = (context: HookContext) => Promise<void>;
