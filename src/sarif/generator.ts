/**
 * SARIF 2.1.0 report generator
 * Pure data transformation — no @actions/core dependency for testability.
 */

import * as crypto from 'crypto';
import { ApiResponse, Vulnerability } from '../api/types';
import { getVulnerabilitySeverity } from '../utils/severity';
import { VERSION } from '../version';
import { SarifLog, SarifRule, SarifResult } from './types';

/**
 * Map vulnerability severity to SARIF result level
 */
function severityToLevel(severity: string): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    default:
      return 'note';
  }
}

/**
 * Map vulnerability severity to security-severity CVSS-like score string
 */
function severityToScore(vuln: Vulnerability): string {
  if (vuln.cvss_score != null) return vuln.cvss_score.toFixed(1);
  const severity = getVulnerabilitySeverity(vuln);
  switch (severity) {
    case 'CRITICAL':
      return '9.0';
    case 'HIGH':
      return '7.0';
    case 'MEDIUM':
      return '4.0';
    case 'LOW':
      return '1.0';
    default:
      return '0.0';
  }
}

/**
 * Generate stable fingerprint for dedup across runs
 */
function generateFingerprint(pkg: string, vulnVersion: string, vulnId: string): string {
  return crypto
    .createHash('sha256')
    .update(`${pkg}:${vulnVersion}:${vulnId}`)
    .digest('hex')
    .substring(0, 32);
}

/**
 * Generate a SARIF 2.1.0 log from scan results
 */
export function generateSarif(response: ApiResponse, fileName: string): SarifLog {
  const rules: SarifRule[] = [];
  const results: SarifResult[] = [];
  const seenRuleIds = new Set<string>();

  if (response.success && response.data) {
    for (const result of response.data.results) {
      if (!result.affected || !result.vulnerabilities?.length) continue;

      for (const vuln of result.vulnerabilities) {
        if (vuln._ignored) continue;

        const severity = getVulnerabilitySeverity(vuln);

        // Add rule if not already seen
        if (!seenRuleIds.has(vuln.id)) {
          seenRuleIds.add(vuln.id);

          const rule: SarifRule = {
            id: vuln.id,
            shortDescription: { text: vuln.summary || `Vulnerability ${vuln.id}` },
            properties: {
              'security-severity': severityToScore(vuln),
              tags: ['security', 'vulnerability'],
            },
          };

          if (vuln.details) {
            rule.fullDescription = { text: vuln.details };
          }

          const ref = vuln.references?.find(r => r.type === 'WEB' || r.type === 'ADVISORY');
          if (ref) {
            rule.helpUri = ref.url;
          }

          rules.push(rule);
        }

        // Build properties bag with enrichment data
        const properties: Record<string, unknown> = {};
        if (vuln.epss_score != null) properties['geekwala/epss-score'] = vuln.epss_score;
        // Keep 'geekwala/is-kev' property name for backward compatibility with existing SARIF consumers
        if (vuln.is_known_exploited != null)
          properties['geekwala/is-kev'] = vuln.is_known_exploited;
        if (vuln.fix_version != null) properties['geekwala/fix-version'] = vuln.fix_version;

        results.push({
          ruleId: vuln.id,
          level: severityToLevel(severity),
          message: {
            text: `${result.package}@${result.version} is affected by ${vuln.id}: ${vuln.summary || 'No description available'}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: fileName },
                region: { startLine: 1 },
              },
            },
          ],
          partialFingerprints: {
            primaryLocationLineHash: generateFingerprint(result.package, result.version, vuln.id),
          },
          ...(Object.keys(properties).length > 0 ? { properties } : {}),
        });
      }
    }
  }

  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'GeekWala Security Scan',
            version: VERSION,
            informationUri: 'https://geekwala.com',
            rules,
          },
        },
        results,
      },
    ],
  };
}
