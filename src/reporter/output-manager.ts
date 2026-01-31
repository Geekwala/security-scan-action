/**
 * GitHub Actions output management
 */

import * as core from '@actions/core';
import { ApiResponse, ActionInputs } from '../api/types';
import { countBySeverity } from '../utils/severity';

export type ScanStatus = 'PASS' | 'FAIL' | 'ERROR';

/**
 * Set GitHub Action outputs
 */
export function setActionOutputs(response: ApiResponse): void {
  if (!response.success || !response.data) {
    core.setOutput('scan-status', 'ERROR');
    core.setOutput('has-vulnerabilities', 'false');
    return;
  }

  const { summary, results } = response.data;

  // Summary outputs
  core.setOutput('total-packages', summary.total_packages.toString());
  core.setOutput('vulnerable-packages', summary.vulnerable_packages.toString());
  core.setOutput('safe-packages', summary.safe_packages.toString());

  // Collect all vulnerabilities
  const allVulnerabilities = results.flatMap(r => r.vulnerabilities || []);

  // Count by severity
  const counts = countBySeverity(allVulnerabilities);
  core.setOutput('critical-count', counts.critical.toString());
  core.setOutput('high-count', counts.high.toString());
  core.setOutput('medium-count', counts.medium.toString());
  core.setOutput('low-count', counts.low.toString());

  // Boolean flag
  const hasVulns = summary.vulnerable_packages > 0;
  core.setOutput('has-vulnerabilities', hasVulns.toString());

  // Status will be set by checkFailureThresholds
}

/**
 * Check if workflow should fail based on severity thresholds
 */
export function checkFailureThresholds(
  response: ApiResponse,
  inputs: ActionInputs
): { shouldFail: boolean; reason?: string; status: ScanStatus } {
  if (!response.success || !response.data) {
    return { shouldFail: true, reason: 'Scan failed', status: 'ERROR' };
  }

  const { results } = response.data;
  const allVulnerabilities = results.flatMap(r => r.vulnerabilities || []);
  const counts = countBySeverity(allVulnerabilities);

  // Check critical threshold
  if (inputs.failOnCritical && counts.critical > 0) {
    return {
      shouldFail: true,
      reason: `Found ${counts.critical} critical vulnerabilit${counts.critical === 1 ? 'y' : 'ies'}`,
      status: 'FAIL',
    };
  }

  // Check high threshold
  if (inputs.failOnHigh && counts.high > 0) {
    return {
      shouldFail: true,
      reason: `Found ${counts.high} high severity vulnerabilit${counts.high === 1 ? 'y' : 'ies'}`,
      status: 'FAIL',
    };
  }

  return { shouldFail: false, status: 'PASS' };
}
