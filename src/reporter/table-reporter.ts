/**
 * Console table output reporter
 */

import * as core from '@actions/core';
import { ApiResponse, Vulnerability } from '../api/types';
import { getVulnerabilitySeverity } from '../utils/severity';

/**
 * Sort vulnerabilities by risk: KEV first, then EPSS desc, then CVSS desc
 */
function sortByRisk(vulns: Array<{ vuln: Vulnerability; pkg: string; version: string; ecosystem: string }>): typeof vulns {
  return [...vulns].sort((a, b) => {
    // KEV first
    const aKev = a.vuln.is_known_exploited ? 1 : 0;
    const bKev = b.vuln.is_known_exploited ? 1 : 0;
    if (bKev !== aKev) return bKev - aKev;

    // EPSS desc
    const aEpss = a.vuln.epss_score ?? 0;
    const bEpss = b.vuln.epss_score ?? 0;
    if (bEpss !== aEpss) return bEpss - aEpss;

    // CVSS desc
    const aCvss = a.vuln.cvss_score ?? 0;
    const bCvss = b.vuln.cvss_score ?? 0;
    return bCvss - aCvss;
  });
}

/**
 * Generate ASCII table output via core.info()
 */
export function generateTableOutput(response: ApiResponse): void {
  if (!response.success || !response.data) return;

  const allVulns: Array<{ vuln: Vulnerability; pkg: string; version: string; ecosystem: string }> = [];

  for (const result of response.data.results) {
    if (!result.affected || !result.vulnerabilities?.length) continue;
    for (const vuln of result.vulnerabilities) {
      if (vuln._ignored) continue;
      allVulns.push({
        vuln,
        pkg: result.package,
        version: result.version,
        ecosystem: result.ecosystem,
      });
    }
  }

  if (allVulns.length === 0) {
    core.info('No active vulnerabilities found.');
    return;
  }

  const sorted = sortByRisk(allVulns);

  // Column widths
  const cols = {
    pkg: Math.max(7, ...sorted.map(v => v.pkg.length)),
    ver: Math.max(7, ...sorted.map(v => v.version.length)),
    id: Math.max(15, ...sorted.map(v => v.vuln.id.length)),
    sev: 8,
    epss: 7,
    kev: 3,
    fix: Math.max(3, ...sorted.map(v => (v.vuln.fix_version || '-').length)),
  };

  const header =
    'Package'.padEnd(cols.pkg) + '  ' +
    'Version'.padEnd(cols.ver) + '  ' +
    'Vulnerability'.padEnd(cols.id) + '  ' +
    'Severity'.padEnd(cols.sev) + '  ' +
    'EPSS'.padEnd(cols.epss) + '  ' +
    'KEV'.padEnd(cols.kev) + '  ' +
    'Fix';

  const separator = '\u2500'.repeat(header.length);

  core.info('');
  core.info(header);
  core.info(separator);

  for (const entry of sorted) {
    const severity = getVulnerabilitySeverity(entry.vuln);
    const epss = entry.vuln.epss_score != null
      ? `${(entry.vuln.epss_score * 100).toFixed(1)}%`
      : '-';
    const kev = entry.vuln.is_known_exploited ? 'YES' : '-';
    const fix = entry.vuln.fix_version || '-';

    const line =
      entry.pkg.padEnd(cols.pkg) + '  ' +
      entry.version.padEnd(cols.ver) + '  ' +
      entry.vuln.id.padEnd(cols.id) + '  ' +
      severity.padEnd(cols.sev) + '  ' +
      epss.padEnd(cols.epss) + '  ' +
      kev.padEnd(cols.kev) + '  ' +
      fix;

    core.info(line);
  }

  core.info('');
}
