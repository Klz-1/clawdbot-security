/**
 * Core types for Clawdbot Security Manager
 */

export type SecurityProfile = 'basic' | 'standard' | 'paranoid' | 'custom';

export type SecurityLevel = 'basic' | 'standard' | 'paranoid';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface SecurityConfig {
  profile: SecurityProfile;
  profiles?: Record<string, ProfileDefinition>;
  lastAudit?: {
    timestamp: string;
    score: number;
  };
}

export interface ProfileDefinition {
  level: SecurityLevel;
  nginx?: NginxConfig;
  filesystem?: FilesystemConfig;
  updates?: UpdatesConfig;
  monitoring?: MonitoringConfig;
}

export interface NginxConfig {
  rateLimiting?: 'moderate' | 'strict' | 'very_strict';
  fail2ban?: 'basic' | 'aggressive' | 'zero_tolerance';
  securityHeaders?: boolean;
}

export interface FilesystemConfig {
  configPerms?: string;
  statePerms?: string;
  credentialsPerms?: string;
}

export interface UpdatesConfig {
  autoCheck?: boolean;
  autoApply?: 'none' | 'security_only' | 'all_security';
  applyWindow?: {
    startHour: number;
    endHour: number;
  };
  notify?: {
    telegram?: boolean;
    email?: string;
  };
}

export interface MonitoringConfig {
  securityLogs?: boolean;
  alertThreshold?: 'low' | 'medium' | 'high';
}

export interface SecurityScore {
  score: number;
  deductions: ScoreDeduction[];
  recommendations: string[];
}

export interface ScoreDeduction {
  category: string;
  penalty: number;
  reason: string;
}

export interface AuditResult {
  ok: boolean;
  issues: AuditIssue[];
  checks: AuditCheck[];
}

export interface AuditIssue {
  code: string;
  severity: Severity;
  message: string;
  fix?: string;
}

export interface AuditCheck {
  name: string;
  passed: boolean;
  message: string;
}

export interface SecurityEvent {
  type: string;
  severity: Severity;
  source: string;
  metadata: Record<string, any>;
  timestamp: string;
  ip?: string;
  user?: string;
}

export interface CVEStatus {
  npm: CVECategory;
  python: CVE[];
  system: SystemUpdates;
}

export interface CVECategory {
  critical: CVE[];
  high: CVE[];
  medium: CVE[];
  low: CVE[];
}

export interface CVE {
  id: string;
  package: string;
  severity: string;
  title: string;
  url: string;
  fixAvailable?: boolean;
  status?: string;
}

export interface SystemUpdates {
  updates: number;
  packages: Array<{
    package: string;
    version: string;
    type: string;
  }>;
}

export interface ClawdbotConfig {
  security?: SecurityConfig;
  gateway?: {
    auth?: {
      mode?: string;
    };
    bind?: string;
  };
  channels?: {
    telegram?: {
      dmPolicy?: string;
      groupPolicy?: string;
    };
    discord?: {
      dmPolicy?: string;
    };
  };
  [key: string]: any;
}
