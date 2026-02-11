/**
 * Tests for JSON report generator
 */

import { generateJsonReport } from '../../src/reporter/json-reporter';
import type { ApiResponse } from '../../src/api/types';
import * as fixtures from '../fixtures';

// Mock package.json version
jest.mock('../../package.json', () => ({ version: '1.1.0' }));

describe('JSON Report Generator', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2024-01-15T12:00:00.000Z'));
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should generate report with correct metadata', () => {
    const report = generateJsonReport(fixtures.cleanScanResponse, 'package.json');

    expect(report.version).toBe('1.1.0');
    expect(report.generatedAt).toBe('2024-01-15T12:00:00.000Z');
    expect(report.tool).toBe('geekwala-security-scan-action');
    expect(report.fileScanned).toBe('package.json');
  });

  it('should return empty vulnerabilities array for clean scan', () => {
    const report = generateJsonReport(fixtures.cleanScanResponse, 'package.json');

    expect(report.vulnerabilities).toEqual([]);
    expect(report.ignoredCount).toBe(0);
    expect(report.summary).toEqual({
      total_packages: 1,
      vulnerable_packages: 0,
      safe_packages: 1,
    });
  });

  it('should include correct vulnerability data for vulnerable scan', () => {
    const report = generateJsonReport(fixtures.vulnerableScanResponse, 'package.json');

    expect(report.vulnerabilities).toHaveLength(1);
    expect(report.summary).toEqual({
      total_packages: 2,
      vulnerable_packages: 1,
      safe_packages: 1,
    });

    const vuln = report.vulnerabilities[0];
    expect(vuln.id).toBe('CVE-2021-23337');
    expect(vuln.package).toBe('lodash');
    expect(vuln.version).toBe('4.17.20');
    expect(vuln.ecosystem).toBe('npm');
    expect(vuln.severity).toBe('HIGH');
    expect(vuln.summary).toBe('Command injection in lodash');
    expect(vuln.cvss_score).toBe(7.2);
    expect(vuln.epss_score).toBe(0.00234);
    expect(vuln.is_kev).toBe(false);
    expect(vuln.ignored).toBe(false);
    expect(vuln.ignoreReason).toBeUndefined();
  });

  it('should include all vulnerabilities from critical vuln response', () => {
    const report = generateJsonReport(fixtures.criticalVulnResponse, 'package.json');

    expect(report.vulnerabilities).toHaveLength(1);
    expect(report.summary.vulnerable_packages).toBe(1);

    const vuln = report.vulnerabilities[0];
    expect(vuln.id).toBe('CVE-2021-44228');
    expect(vuln.severity).toBe('CRITICAL');
    expect(vuln.cvss_score).toBe(10.0);
    expect(vuln.epss_score).toBe(0.97534);
    expect(vuln.is_kev).toBe(true);
  });

  it('should handle missing enrichment data gracefully', () => {
    const report = generateJsonReport(fixtures.missingEnrichmentResponse, 'package.json');

    expect(report.vulnerabilities).toHaveLength(1);

    const vuln = report.vulnerabilities[0];
    expect(vuln.id).toBe('CVE-2024-9999');
    expect(vuln.cvss_score).toBeNull();
    expect(vuln.epss_score).toBeNull();
    expect(vuln.is_kev).toBe(false);
    expect(vuln.fix_version).toBeUndefined();
  });

  it('should count and flag ignored vulnerabilities', () => {
    const responseWithIgnored: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
        results: [{
          ecosystem: 'npm',
          package: 'test-pkg',
          version: '1.0.0',
          affected: true,
          severity: 'HIGH',
          vulnerabilities: [
            {
              id: 'CVE-2024-0001',
              summary: 'Active vulnerability',
              cvss_score: 8.0,
            },
            {
              id: 'CVE-2024-0002',
              summary: 'Ignored vulnerability',
              cvss_score: 9.0,
              _ignored: true,
              _ignoreReason: 'False positive',
            },
            {
              id: 'CVE-2024-0003',
              summary: 'Another ignored vulnerability',
              cvss_score: 7.5,
              _ignored: true,
              _ignoreReason: 'Not applicable',
            },
          ],
        }],
      },
    };

    const report = generateJsonReport(responseWithIgnored, 'package.json');

    expect(report.vulnerabilities).toHaveLength(3);
    expect(report.ignoredCount).toBe(2);

    // Check active vulnerability
    expect(report.vulnerabilities[0].ignored).toBe(false);
    expect(report.vulnerabilities[0].ignoreReason).toBeUndefined();

    // Check ignored vulnerabilities
    expect(report.vulnerabilities[1].ignored).toBe(true);
    expect(report.vulnerabilities[1].ignoreReason).toBe('False positive');

    expect(report.vulnerabilities[2].ignored).toBe(true);
    expect(report.vulnerabilities[2].ignoreReason).toBe('Not applicable');
  });

  it('should include fix_version when present', () => {
    const responseWithFix: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
        results: [{
          ecosystem: 'npm',
          package: 'fixable-pkg',
          version: '1.0.0',
          affected: true,
          severity: 'HIGH',
          vulnerabilities: [{
            id: 'CVE-2024-1111',
            summary: 'Vulnerability with fix',
            cvss_score: 8.0,
            fix_version: '2.0.0',
          }],
        }],
      },
    };

    const report = generateJsonReport(responseWithFix, 'package.json');

    expect(report.vulnerabilities[0].fix_version).toBe('2.0.0');
  });

  it('should handle error/failed response with zero summary', () => {
    const errorResponse: ApiResponse = {
      success: false,
      error: 'API error',
      type: 'server_error',
    };

    const report = generateJsonReport(errorResponse, 'package.json');

    expect(report.vulnerabilities).toEqual([]);
    expect(report.ignoredCount).toBe(0);
    expect(report.summary).toEqual({
      total_packages: 0,
      vulnerable_packages: 0,
      safe_packages: 0,
    });
  });

  it('should handle multiple packages with mixed vulnerabilities', () => {
    const report = generateJsonReport(fixtures.mixedSeverityResponse, 'package.json');

    expect(report.vulnerabilities).toHaveLength(7);
    expect(report.summary.total_packages).toBe(7);
    expect(report.summary.vulnerable_packages).toBe(7);

    // Verify severity levels are preserved
    const severities = report.vulnerabilities.map(v => v.severity);
    expect(severities).toContain('CRITICAL');
    expect(severities).toContain('HIGH');
    expect(severities).toContain('MEDIUM');
    expect(severities).toContain('LOW');
  });

  it('should handle packages with multiple vulnerabilities', () => {
    const multiVulnResponse: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
        results: [{
          ecosystem: 'npm',
          package: 'multi-vuln-pkg',
          version: '1.0.0',
          affected: true,
          severity: 'HIGH',
          vulnerabilities: [
            { id: 'CVE-2024-0001', summary: 'First vuln', cvss_score: 8.0 },
            { id: 'CVE-2024-0002', summary: 'Second vuln', cvss_score: 7.5 },
            { id: 'CVE-2024-0003', summary: 'Third vuln', cvss_score: 9.0 },
          ],
        }],
      },
    };

    const report = generateJsonReport(multiVulnResponse, 'package.json');

    expect(report.vulnerabilities).toHaveLength(3);
    // All should reference the same package
    expect(report.vulnerabilities.every(v => v.package === 'multi-vuln-pkg')).toBe(true);
    expect(report.vulnerabilities.every(v => v.version === '1.0.0')).toBe(true);
  });

  it('should skip packages with no vulnerabilities', () => {
    const report = generateJsonReport(fixtures.cleanScanResponse, 'package.json');

    expect(report.vulnerabilities).toEqual([]);
    expect(report.summary.safe_packages).toBe(1);
  });

  it('should skip packages not affected', () => {
    const mixedResponse: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 2, vulnerable_packages: 1, safe_packages: 1 },
        results: [
          {
            ecosystem: 'npm',
            package: 'safe-pkg',
            version: '1.0.0',
            affected: false,
            vulnerabilities: [],
            severity: 'NONE',
          },
          {
            ecosystem: 'npm',
            package: 'vuln-pkg',
            version: '2.0.0',
            affected: true,
            severity: 'HIGH',
            vulnerabilities: [
              { id: 'CVE-2024-1111', summary: 'Test vuln', cvss_score: 8.0 },
            ],
          },
        ],
      },
    };

    const report = generateJsonReport(mixedResponse, 'package.json');

    expect(report.vulnerabilities).toHaveLength(1);
    expect(report.vulnerabilities[0].package).toBe('vuln-pkg');
  });

  it('should preserve all ecosystem types', () => {
    const multiEcosystemResponse: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 3, vulnerable_packages: 3, safe_packages: 0 },
        results: [
          {
            ecosystem: 'npm',
            package: 'npm-pkg',
            version: '1.0.0',
            affected: true,
            severity: 'HIGH',
            vulnerabilities: [{ id: 'CVE-1', summary: 'NPM vuln' }],
          },
          {
            ecosystem: 'PyPI',
            package: 'python-pkg',
            version: '2.0.0',
            affected: true,
            severity: 'MEDIUM',
            vulnerabilities: [{ id: 'CVE-2', summary: 'Python vuln' }],
          },
          {
            ecosystem: 'Maven',
            package: 'java-pkg',
            version: '3.0.0',
            affected: true,
            severity: 'LOW',
            vulnerabilities: [{ id: 'CVE-3', summary: 'Java vuln' }],
          },
        ],
      },
    };

    const report = generateJsonReport(multiEcosystemResponse, 'package.json');

    const ecosystems = report.vulnerabilities.map(v => v.ecosystem);
    expect(ecosystems).toContain('npm');
    expect(ecosystems).toContain('PyPI');
    expect(ecosystems).toContain('Maven');
  });

  it('should use custom file name in report', () => {
    const report = generateJsonReport(fixtures.cleanScanResponse, 'requirements.txt');

    expect(report.fileScanned).toBe('requirements.txt');
  });

  it('should handle response with no data field', () => {
    const noDataResponse: ApiResponse = {
      success: false,
      error: 'No data',
      type: 'validation_error',
    };

    const report = generateJsonReport(noDataResponse, 'package.json');

    expect(report.vulnerabilities).toEqual([]);
    expect(report.ignoredCount).toBe(0);
    expect(report.summary).toEqual({
      total_packages: 0,
      vulnerable_packages: 0,
      safe_packages: 0,
    });
  });

  it('should set ignored false when _ignored is not set', () => {
    const report = generateJsonReport(fixtures.vulnerableScanResponse, 'package.json');

    expect(report.vulnerabilities[0].ignored).toBe(false);
  });

  it('should use per-vulnerability severity, not package-level severity', () => {
    const mixedVulnResponse: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
        results: [{
          ecosystem: 'npm',
          package: 'mixed-severity-pkg',
          version: '1.0.0',
          affected: true,
          severity: 'CRITICAL',  // Package-level severity (max of all vulns)
          vulnerabilities: [
            { id: 'CVE-2024-0001', summary: 'Critical vuln', cvss_score: 9.5 },
            { id: 'CVE-2024-0002', summary: 'Low vuln', cvss_score: 2.0 },
          ],
        }],
      },
    };

    const report = generateJsonReport(mixedVulnResponse, 'package.json');

    // Each vulnerability should have its own computed severity
    expect(report.vulnerabilities[0].severity).toBe('CRITICAL');
    expect(report.vulnerabilities[1].severity).toBe('LOW');
  });

  it('should compute corrected summary when all vulns in a package are ignored', () => {
    const responseWithAllIgnored: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
        results: [{
          ecosystem: 'npm',
          package: 'fully-ignored-pkg',
          version: '1.0.0',
          affected: true,
          severity: 'HIGH',
          vulnerabilities: [
            {
              id: 'CVE-2024-0001',
              summary: 'Ignored vuln',
              cvss_score: 8.0,
              _ignored: true,
              _ignoreReason: 'False positive',
            },
          ],
        }],
      },
    };

    const report = generateJsonReport(responseWithAllIgnored, 'package.json');

    // Summary should reflect that no packages are truly vulnerable
    expect(report.summary.vulnerable_packages).toBe(0);
    expect(report.summary.safe_packages).toBe(1);
    expect(report.ignoredCount).toBe(1);
  });
});
