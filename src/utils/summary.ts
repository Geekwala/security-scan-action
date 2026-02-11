/**
 * Summary recomputation utilities
 */

import { ScanResult, ScanSummary } from '../api/types';

/**
 * Recompute summary counts from results, accounting for ignored vulnerabilities.
 * A package is "vulnerable" only if it has at least one active (non-ignored) vulnerability.
 */
export function recomputeSummary(results: ScanResult[]): ScanSummary {
  const totalPackages = results.length;
  let vulnerablePackages = 0;

  for (const result of results) {
    if (!result.affected || !result.vulnerabilities?.length) continue;
    const hasActiveVuln = result.vulnerabilities.some(v => !v._ignored);
    if (hasActiveVuln) vulnerablePackages++;
  }

  return {
    total_packages: totalPackages,
    vulnerable_packages: vulnerablePackages,
    safe_packages: totalPackages - vulnerablePackages,
  };
}
