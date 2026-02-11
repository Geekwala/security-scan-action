/**
 * GitHub Actions output management
 */

import * as core from '@actions/core';
import { ApiResponse, ActionInputs } from '../api/types';
import { countBySeverity, getVulnerabilitySeverity } from '../utils/severity';
import { pluralizeVulnerabilities } from '../utils/format';
import { recomputeSummary } from '../utils/summary';

export type ScanStatus = 'PASS' | 'FAIL' | 'ERROR';

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
};

/**
 * Set GitHub Action outputs
 */
export function setActionOutputs(response: ApiResponse): void {
  if (!response.success || !response.data) {
    core.setOutput('scan-status', 'ERROR');
    core.setOutput('has-vulnerabilities', 'false');
    return;
  }

  const { results } = response.data;

  // Recompute summary to account for ignored vulnerabilities
  const correctedSummary = recomputeSummary(results);

  // Summary outputs (corrected for ignores)
  core.setOutput('total-packages', correctedSummary.total_packages.toString());
  core.setOutput('vulnerable-packages', correctedSummary.vulnerable_packages.toString());
  core.setOutput('safe-packages', correctedSummary.safe_packages.toString());

  // Collect active (non-ignored) vulnerabilities for counts
  const allVulnerabilities = results.flatMap(r => r.vulnerabilities || []);
  const activeVulns = allVulnerabilities.filter(v => !v._ignored);

  // Count by severity (only active vulnerabilities)
  const counts = countBySeverity(activeVulns);
  core.setOutput('critical-count', counts.critical.toString());
  core.setOutput('high-count', counts.high.toString());
  core.setOutput('medium-count', counts.medium.toString());
  core.setOutput('low-count', counts.low.toString());

  // Boolean flag (corrected for ignores)
  const hasVulns = correctedSummary.vulnerable_packages > 0;
  core.setOutput('has-vulnerabilities', hasVulns.toString());

  // Status will be set by checkFailureThresholds
}

/**
 * Check if workflow should fail based on severity thresholds.
 * Collects ALL fail reasons rather than short-circuiting on first match.
 */
export function checkFailureThresholds(
  response: ApiResponse,
  inputs: ActionInputs
): { shouldFail: boolean; reason?: string; reasons: string[]; status: ScanStatus } {
  if (!response.success || !response.data) {
    return { shouldFail: true, reason: 'Scan failed', reasons: ['Scan failed'], status: 'ERROR' };
  }

  const { results } = response.data;
  const allVulnerabilities = results.flatMap(r => r.vulnerabilities || []);

  // Filter out ignored vulnerabilities
  const activeVulns = allVulnerabilities.filter(v => !v._ignored);

  // If only-fixed, filter to vulns with known fixes
  const gatedVulns = inputs.onlyFixed
    ? activeVulns.filter(v => v.fix_version != null)
    : activeVulns;

  const reasons: string[] = [];

  // Check severity threshold
  if (inputs.severityThreshold !== 'none') {
    const thresholdLevel = SEVERITY_ORDER[inputs.severityThreshold.toUpperCase()] ?? 0;
    const exceedingVulns = gatedVulns.filter(v => {
      const severity = getVulnerabilitySeverity(v);
      return (SEVERITY_ORDER[severity] ?? 0) >= thresholdLevel;
    });

    if (exceedingVulns.length > 0) {
      reasons.push(
        `Found ${exceedingVulns.length} ${pluralizeVulnerabilities(exceedingVulns.length)} at or above ${inputs.severityThreshold} severity`
      );
    }
  }

  // Check KEV gate
  if (inputs.failOnKev) {
    const kevVulns = gatedVulns.filter(v => v.is_kev === true);
    if (kevVulns.length > 0) {
      reasons.push(
        `Found ${kevVulns.length} CISA Known Exploited ${pluralizeVulnerabilities(kevVulns.length)}`
      );
    }
  }

  // Check EPSS threshold
  if (inputs.epssThreshold !== undefined) {
    const epssVulns = gatedVulns.filter(
      v => v.epss_score != null && v.epss_score >= inputs.epssThreshold!
    );
    if (epssVulns.length > 0) {
      reasons.push(
        `Found ${epssVulns.length} ${pluralizeVulnerabilities(epssVulns.length)} with EPSS score at or above ${inputs.epssThreshold}`
      );
    }
  }

  if (reasons.length > 0) {
    return {
      shouldFail: true,
      reason: reasons.join('; '),
      reasons,
      status: 'FAIL',
    };
  }

  return { shouldFail: false, reasons: [], status: 'PASS' };
}
