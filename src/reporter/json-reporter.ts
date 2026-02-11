/**
 * JSON report generator
 */

import { ApiResponse } from '../api/types';
import { VERSION } from '../version';
import { recomputeSummary } from '../utils/summary';
import { getVulnerabilitySeverity } from '../utils/severity';

export interface JsonReport {
  version: string;
  generatedAt: string;
  scanDurationMs?: number;
  tool: string;
  fileScanned: string;
  summary: {
    total_packages: number;
    vulnerable_packages: number;
    safe_packages: number;
  };
  vulnerabilities: Array<{
    id: string;
    package: string;
    version: string;
    ecosystem: string;
    severity: string;
    summary?: string;
    cvss_score?: number | null;
    epss_score?: number | null;
    is_known_exploited?: boolean;
    fix_version?: string | null;
    ignored: boolean;
    ignoreReason?: string;
  }>;
  ignoredCount: number;
}

/**
 * Generate structured JSON report from scan results
 */
export function generateJsonReport(
  response: ApiResponse,
  fileName: string,
  scanDurationMs?: number
): JsonReport {
  const vulnerabilities: JsonReport['vulnerabilities'] = [];
  let ignoredCount = 0;

  if (response.success && response.data) {
    for (const result of response.data.results) {
      if (!result.affected || !result.vulnerabilities?.length) continue;

      for (const vuln of result.vulnerabilities) {
        if (vuln._ignored) ignoredCount++;

        vulnerabilities.push({
          id: vuln.id,
          package: result.package,
          version: result.version,
          ecosystem: result.ecosystem,
          severity: getVulnerabilitySeverity(vuln),
          summary: vuln.summary,
          cvss_score: vuln.cvss_score,
          epss_score: vuln.epss_score,
          is_known_exploited: vuln.is_known_exploited,
          fix_version: vuln.fix_version,
          ignored: vuln._ignored || false,
          ignoreReason: vuln._ignoreReason,
        });
      }
    }
  }

  return {
    version: VERSION,
    generatedAt: new Date().toISOString(),
    ...(scanDurationMs != null ? { scanDurationMs } : {}),
    tool: 'geekwala-security-scan-action',
    fileScanned: fileName,
    summary: response.data
      ? recomputeSummary(response.data.results)
      : { total_packages: 0, vulnerable_packages: 0, safe_packages: 0 },
    vulnerabilities,
    ignoredCount,
  };
}
