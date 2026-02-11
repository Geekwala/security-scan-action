/**
 * Tests for SARIF 2.1.0 generator
 */

import { generateSarif } from '../../src/sarif/generator';
import type { ApiResponse } from '../../src/api/types';
import * as fixtures from '../fixtures';

describe('SARIF Generator', () => {
  it('should generate valid SARIF 2.1.0 structure', () => {
    const sarif = generateSarif(fixtures.vulnerableScanResponse, 'package.json');

    expect(sarif.$schema).toContain('sarif-schema-2.1.0');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('GeekWala Security Scan');
    expect(sarif.runs[0].tool.driver.rules).toBeDefined();
    expect(sarif.runs[0].results).toBeDefined();
  });

  it('should produce empty results for clean scan', () => {
    const sarif = generateSarif(fixtures.cleanScanResponse, 'package.json');

    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
    expect(sarif.runs[0].results).toHaveLength(0);
  });

  it('should map severity to correct SARIF level', () => {
    const sarif = generateSarif(fixtures.criticalVulnResponse, 'package.json');

    // Critical vuln should be level: error
    expect(sarif.runs[0].results[0].level).toBe('error');
  });

  it('should map HIGH severity to error level', () => {
    const sarif = generateSarif(fixtures.vulnerableScanResponse, 'package.json');

    expect(sarif.runs[0].results[0].level).toBe('error');
  });

  it('should map MEDIUM severity to warning level', () => {
    const mediumResponse: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
        results: [{
          ecosystem: 'npm',
          package: 'pkg',
          version: '1.0.0',
          affected: true,
          severity: 'MEDIUM',
          vulnerabilities: [{ id: 'CVE-1', summary: 'Medium vuln', cvss_score: 5.0 }],
        }],
      },
    };

    const sarif = generateSarif(mediumResponse, 'package.json');
    expect(sarif.runs[0].results[0].level).toBe('warning');
  });

  it('should include EPSS/KEV in result properties', () => {
    const sarif = generateSarif(fixtures.criticalVulnResponse, 'package.json');

    const result = sarif.runs[0].results[0];
    expect(result.properties).toBeDefined();
    expect(result.properties!['geekwala/epss-score']).toBe(0.97534);
    expect(result.properties!['geekwala/is-kev']).toBe(true);
  });

  it('should include fix_version when present', () => {
    const responseWithFix: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
        results: [{
          ecosystem: 'npm',
          package: 'pkg',
          version: '1.0.0',
          affected: true,
          severity: 'HIGH',
          vulnerabilities: [{
            id: 'CVE-1',
            summary: 'Vuln with fix',
            cvss_score: 8.0,
            fix_version: '2.0.0',
          }],
        }],
      },
    };

    const sarif = generateSarif(responseWithFix, 'package.json');
    expect(sarif.runs[0].results[0].properties!['geekwala/fix-version']).toBe('2.0.0');
  });

  it('should generate stable fingerprints', () => {
    const sarif1 = generateSarif(fixtures.vulnerableScanResponse, 'package.json');
    const sarif2 = generateSarif(fixtures.vulnerableScanResponse, 'package.json');

    expect(sarif1.runs[0].results[0].partialFingerprints).toEqual(
      sarif2.runs[0].results[0].partialFingerprints
    );
  });

  it('should handle null enrichment gracefully', () => {
    const sarif = generateSarif(fixtures.missingEnrichmentResponse, 'package.json');

    // Should not throw and should produce a result
    expect(sarif.runs[0].results).toHaveLength(1);
    // Properties should be empty or minimal when enrichment is null
    const props = sarif.runs[0].results[0].properties;
    expect(props?.['geekwala/epss-score']).toBeUndefined();
  });

  it('should create unique rules per vulnerability ID', () => {
    const sarif = generateSarif(fixtures.mixedSeverityResponse, 'package.json');

    const ruleIds = sarif.runs[0].tool.driver.rules.map(r => r.id);
    const uniqueIds = new Set(ruleIds);
    expect(ruleIds.length).toBe(uniqueIds.size);
  });

  it('should include security-severity in rule properties', () => {
    const sarif = generateSarif(fixtures.criticalVulnResponse, 'package.json');

    const rule = sarif.runs[0].tool.driver.rules[0];
    expect(rule.properties).toBeDefined();
    expect(rule.properties!['security-severity']).toBe('10.0');
  });

  it('should skip ignored vulnerabilities', () => {
    const responseWithIgnored: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
        results: [{
          ecosystem: 'npm',
          package: 'pkg',
          version: '1.0.0',
          affected: true,
          severity: 'HIGH',
          vulnerabilities: [
            { id: 'CVE-1', summary: 'Active', cvss_score: 8.0 },
            { id: 'CVE-2', summary: 'Ignored', cvss_score: 9.0, _ignored: true, _ignoreReason: 'test' },
          ],
        }],
      },
    };

    const sarif = generateSarif(responseWithIgnored, 'package.json');
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].ruleId).toBe('CVE-1');
  });

  it('should set artifact location to scanned file', () => {
    const sarif = generateSarif(fixtures.vulnerableScanResponse, 'package.json');

    const location = sarif.runs[0].results[0].locations[0];
    expect(location.physicalLocation.artifactLocation.uri).toBe('package.json');
  });

  describe('severityToScore fallback when cvss_score is null', () => {
    it('should use 9.0 for CRITICAL severity without cvss_score', () => {
      const response: ApiResponse = {
        success: true,
        data: {
          summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
          results: [{
            ecosystem: 'npm',
            package: 'pkg',
            version: '1.0.0',
            affected: true,
            severity: 'CRITICAL',
            vulnerabilities: [{
              id: 'CVE-CRIT',
              summary: 'Critical without CVSS',
              severity: [{ type: 'CVSS_V3', score: '9.5' }],
            }],
          }],
        },
      };

      const sarif = generateSarif(response, 'package.json');
      expect(sarif.runs[0].tool.driver.rules[0].properties!['security-severity']).toBe('9.0');
    });

    it('should use 7.0 for HIGH severity without cvss_score', () => {
      const response: ApiResponse = {
        success: true,
        data: {
          summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
          results: [{
            ecosystem: 'npm',
            package: 'pkg',
            version: '1.0.0',
            affected: true,
            severity: 'HIGH',
            vulnerabilities: [{
              id: 'CVE-HIGH',
              summary: 'High without CVSS',
              severity: [{ type: 'CVSS_V3', score: '7.5' }],
            }],
          }],
        },
      };

      const sarif = generateSarif(response, 'package.json');
      expect(sarif.runs[0].tool.driver.rules[0].properties!['security-severity']).toBe('7.0');
    });

    it('should use 4.0 for MEDIUM severity without cvss_score', () => {
      const response: ApiResponse = {
        success: true,
        data: {
          summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
          results: [{
            ecosystem: 'npm',
            package: 'pkg',
            version: '1.0.0',
            affected: true,
            severity: 'MEDIUM',
            vulnerabilities: [{
              id: 'CVE-MED',
              summary: 'Medium without CVSS',
              severity: [{ type: 'CVSS_V3', score: '5.0' }],
            }],
          }],
        },
      };

      const sarif = generateSarif(response, 'package.json');
      expect(sarif.runs[0].tool.driver.rules[0].properties!['security-severity']).toBe('4.0');
    });

    it('should use 1.0 for LOW severity without cvss_score', () => {
      const response: ApiResponse = {
        success: true,
        data: {
          summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
          results: [{
            ecosystem: 'npm',
            package: 'pkg',
            version: '1.0.0',
            affected: true,
            severity: 'LOW',
            vulnerabilities: [{
              id: 'CVE-LOW',
              summary: 'Low without CVSS',
              severity: [{ type: 'CVSS_V3', score: '2.0' }],
            }],
          }],
        },
      };

      const sarif = generateSarif(response, 'package.json');
      expect(sarif.runs[0].tool.driver.rules[0].properties!['security-severity']).toBe('1.0');
    });
  });

  it('should include fullDescription when vuln.details is present', () => {
    const response: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
        results: [{
          ecosystem: 'npm',
          package: 'pkg',
          version: '1.0.0',
          affected: true,
          severity: 'HIGH',
          vulnerabilities: [{
            id: 'CVE-DETAILS',
            summary: 'Vuln with details',
            details: 'This is a detailed description of the vulnerability.',
            cvss_score: 8.0,
          }],
        }],
      },
    };

    const sarif = generateSarif(response, 'package.json');
    expect(sarif.runs[0].tool.driver.rules[0].fullDescription).toEqual({
      text: 'This is a detailed description of the vulnerability.',
    });
  });

  it('should include helpUri when references contain WEB or ADVISORY type', () => {
    const response: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
        results: [{
          ecosystem: 'npm',
          package: 'pkg',
          version: '1.0.0',
          affected: true,
          severity: 'HIGH',
          vulnerabilities: [{
            id: 'CVE-REF',
            summary: 'Vuln with reference',
            cvss_score: 7.5,
            references: [
              { type: 'ADVISORY', url: 'https://example.com/advisory/CVE-REF' },
            ],
          }],
        }],
      },
    };

    const sarif = generateSarif(response, 'package.json');
    expect(sarif.runs[0].tool.driver.rules[0].helpUri).toBe('https://example.com/advisory/CVE-REF');
  });
});
