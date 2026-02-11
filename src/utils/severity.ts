/**
 * Severity classification utilities
 */

import * as core from '@actions/core';
import { Vulnerability, SeverityCounts } from '../api/types';

/**
 * Normalize severity from various formats to standard levels
 */
export function normalizeSeverity(severity: string): string {
  const normalized = severity.toUpperCase().trim();

  if (normalized === 'CRITICAL') return 'CRITICAL';
  if (normalized === 'HIGH') return 'HIGH';
  if (normalized === 'MEDIUM' || normalized === 'MODERATE') return 'MEDIUM';
  if (normalized === 'LOW') return 'LOW';

  return 'UNKNOWN';
}

/**
 * Get severity from CVSS score
 */
export function getSeverityFromCvss(score: number): string {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'UNKNOWN';
}

/**
 * Extract highest severity from vulnerability data
 */
export function getVulnerabilitySeverity(vuln: Vulnerability): string {
  // Use CVSS score if available
  if (vuln.cvss_score != null) {
    return getSeverityFromCvss(vuln.cvss_score);
  }

  // Parse severity array — try all entries for a numeric score
  if (vuln.severity && vuln.severity.length > 0) {
    for (const entry of vuln.severity) {
      const score = parseFloat(entry.score);
      if (!isNaN(score)) {
        return getSeverityFromCvss(score);
      }
    }

    // No numeric score found — check if vector strings were present
    const hasVectorString = vuln.severity.some(s => s.score.startsWith('CVSS:'));
    if (hasVectorString) {
      core.warning(
        `Vulnerability ${vuln.id}: CVSS vector string found but no numeric score available. Severity classified as UNKNOWN.`
      );
    }
  }

  return 'UNKNOWN';
}

/**
 * Count vulnerabilities by severity
 */
export function countBySeverity(vulnerabilities: Vulnerability[]): SeverityCounts {
  const counts: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };

  for (const vuln of vulnerabilities) {
    const severity = getVulnerabilitySeverity(vuln);
    switch (severity) {
      case 'CRITICAL':
        counts.critical++;
        break;
      case 'HIGH':
        counts.high++;
        break;
      case 'MEDIUM':
        counts.medium++;
        break;
      case 'LOW':
        counts.low++;
        break;
      default:
        counts.unknown++;
    }
  }

  return counts;
}
