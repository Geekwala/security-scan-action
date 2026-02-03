/**
 * GitHub Workflow Summary Reporter
 */

import * as core from '@actions/core';
import { ApiResponse } from '../api/types';
import { countBySeverity, getVulnerabilitySeverity } from '../utils/severity';

/**
 * Generate GitHub workflow summary
 */
export async function generateSummary(response: ApiResponse, fileName: string): Promise<void> {
  if (!response.success || !response.data) {
    await core.summary
      .addHeading('🛡️ GeekWala Security Scan - Error', 1)
      .addRaw(`**Error:** ${response.error || 'Unknown error occurred'}`)
      .addBreak()
      .addRaw('Check the action logs for more details.')
      .write();
    return;
  }

  const { summary, results } = response.data;
  const allVulnerabilities = results.flatMap(r => r.vulnerabilities || []);
  const counts = countBySeverity(allVulnerabilities);

  // Start summary
  await core.summary.addHeading('🛡️ GeekWala Security Scan Results', 1);

  // File scanned
  core.summary.addRaw(`**File scanned:** \`${fileName}\``).addBreak();

  // Overall summary
  const hasVulns = summary.vulnerable_packages > 0;
  const emoji = hasVulns ? '⚠️' : '✅';
  core.summary
    .addRaw(
      `${emoji} **${summary.vulnerable_packages}** of **${summary.total_packages}** packages have known vulnerabilities`
    )
    .addBreak()
    .addBreak();

  // Severity breakdown table
  core.summary.addHeading('Severity Breakdown', 2);
  core.summary.addTable([
    [
      { data: 'Severity', header: true },
      { data: 'Count', header: true },
    ],
    ['🔴 Critical', counts.critical.toString()],
    ['🟠 High', counts.high.toString()],
    ['🟡 Medium', counts.medium.toString()],
    ['🟢 Low', counts.low.toString()],
  ]);

  core.summary.addBreak();

  // Vulnerable packages details
  if (hasVulns) {
    core.summary.addHeading('Vulnerable Packages', 2);

    const vulnerableResults = results.filter(r => r.affected && r.vulnerabilities?.length > 0);

    for (const result of vulnerableResults) {
      const severityEmoji = getSeverityEmoji(result.severity);
      core.summary.addHeading(`${severityEmoji} ${result.package}@${result.version}`, 3);

      core.summary.addRaw(`**Ecosystem:** ${result.ecosystem}`).addBreak();
      core.summary.addRaw(`**Vulnerabilities:** ${result.vulnerabilities.length}`).addBreak();
      core.summary.addBreak();

      // List vulnerabilities
      for (const vuln of result.vulnerabilities) {
        const vulnSeverity = getVulnerabilitySeverity(vuln);
        const vulnEmoji = getSeverityEmoji(vulnSeverity);

        core.summary.addRaw(`**${vulnEmoji} ${vuln.id}**`).addBreak();

        if (vuln.summary) {
          core.summary.addRaw(vuln.summary).addBreak();
        }

        // Enrichment data
        const enrichmentData: string[] = [];

        if (vuln.cvss_score !== null && vuln.cvss_score !== undefined) {
          enrichmentData.push(`CVSS: ${vuln.cvss_score.toFixed(1)}`);
        }

        if (vuln.epss_score !== null && vuln.epss_score !== undefined) {
          enrichmentData.push(`EPSS: ${(vuln.epss_score * 100).toFixed(2)}%`);
        }

        if (vuln.is_kev) {
          enrichmentData.push('⚡ CISA KEV');
        }

        if (enrichmentData.length > 0) {
          core.summary.addRaw(`*${enrichmentData.join(' | ')}*`).addBreak();
        }

        core.summary.addBreak();
      }

      core.summary.addBreak();
    }
  } else {
    core.summary.addRaw('✅ No vulnerabilities detected in scanned packages.').addBreak();
  }

  // Footer
  core.summary.addBreak();
  core.summary.addRaw('---').addBreak();
  core.summary.addRaw(
    'Powered by [GeekWala](https://geekwala.com) • Enriched with EPSS & CISA KEV data'
  );

  await core.summary.write();
}

/**
 * Get emoji for severity level
 */
function getSeverityEmoji(severity: string): string {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
      return '🔴';
    case 'HIGH':
      return '🟠';
    case 'MEDIUM':
      return '🟡';
    case 'LOW':
      return '🟢';
    default:
      return '⚪';
  }
}
