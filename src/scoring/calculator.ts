/**
 * Security Score Calculator
 *
 * Calculates a security score (0-100) based on various security factors
 */

import type {
  SecurityScore,
  ScoreDeduction,
  ClawdbotConfig,
  AuditResult,
} from '../core/types.js';

export async function calculateSecurityScore(
  config: ClawdbotConfig | null,
  auditResults?: AuditResult
): Promise<SecurityScore> {
  let score = 100;
  const deductions: ScoreDeduction[] = [];
  const recommendations: string[] = [];

  // If no config exists, major deduction
  if (!config) {
    deductions.push({
      category: 'configuration',
      penalty: 50,
      reason: 'Clawdbot configuration not found',
    });
    recommendations.push('Install and configure Clawdbot');
    return {
      score: 50,
      deductions,
      recommendations,
    };
  }

  // Check gateway authentication
  if (!config.gateway?.auth?.mode || config.gateway.auth.mode === 'none') {
    const penalty = 20;
    score -= penalty;
    deductions.push({
      category: 'gateway_auth',
      penalty,
      reason: 'Gateway has no authentication configured',
    });
    recommendations.push(
      'Enable gateway authentication: set gateway.auth.mode to "token" or "oauth"'
    );
  }

  // Check gateway binding
  if (config.gateway?.bind && config.gateway.bind !== 'loopback') {
    const penalty = 10;
    score -= penalty;
    deductions.push({
      category: 'gateway_bind',
      penalty,
      reason: 'Gateway exposed on network interface',
    });
    recommendations.push(
      'Bind gateway to loopback only: set gateway.bind to "loopback"'
    );
  }

  // Check channel DM policies
  if (config.channels?.telegram?.dmPolicy === 'open') {
    const penalty = 15;
    score -= penalty;
    deductions.push({
      category: 'telegram_dm',
      penalty,
      reason: 'Telegram DM policy is open',
    });
    recommendations.push(
      'Restrict Telegram DM access: set channels.telegram.dmPolicy to "pairing"'
    );
  }

  if (config.channels?.discord?.dmPolicy === 'open') {
    const penalty = 15;
    score -= penalty;
    deductions.push({
      category: 'discord_dm',
      penalty,
      reason: 'Discord DM policy is open',
    });
    recommendations.push(
      'Restrict Discord DM access: set channels.discord.dmPolicy to "pairing"'
    );
  }

  // Check if security profile is configured
  if (!config.security?.profile) {
    const penalty = 10;
    score -= penalty;
    deductions.push({
      category: 'security_profile',
      penalty,
      reason: 'No security profile configured',
    });
    recommendations.push('Run: clawdbot-security setup');
  }

  // Process audit results if provided
  if (auditResults) {
    for (const issue of auditResults.issues) {
      let penalty = 0;
      switch (issue.severity) {
        case 'critical':
          penalty = 15;
          break;
        case 'high':
          penalty = 10;
          break;
        case 'medium':
          penalty = 5;
          break;
        case 'low':
          penalty = 2;
          break;
      }

      if (penalty > 0) {
        score -= penalty;
        deductions.push({
          category: issue.code,
          penalty,
          reason: issue.message,
        });

        if (issue.fix) {
          recommendations.push(issue.fix);
        }
      }
    }
  }

  // Ensure score doesn't go below 0
  score = Math.max(0, score);

  return {
    score,
    deductions,
    recommendations: Array.from(new Set(recommendations)), // Deduplicate
  };
}

/**
 * Get security score color based on value
 */
export function getScoreColor(score: number): string {
  if (score >= 90) return 'green';
  if (score >= 70) return 'yellow';
  return 'red';
}

/**
 * Get security score rating
 */
export function getScoreRating(score: number): string {
  if (score >= 95) return 'EXCELLENT';
  if (score >= 85) return 'GOOD';
  if (score >= 70) return 'FAIR';
  if (score >= 50) return 'POOR';
  return 'CRITICAL';
}
