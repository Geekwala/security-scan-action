/**
 * Integration tests for output management and summary reporting
 */

import * as core from '@actions/core';
import { setActionOutputs, checkFailureThresholds } from '../../src/reporter/output-manager';
import { generateSummary } from '../../src/reporter/summary-reporter';
import { ActionInputs } from '../../src/api/types';
import * as fixtures from '../fixtures';

// Mock @actions/core
jest.mock('@actions/core');

function makeInputs(overrides: Partial<ActionInputs> = {}): ActionInputs {
  return {
    apiToken: 'test-token',
    failOnCritical: false,
    failOnHigh: false,
    severityThreshold: 'none',
    failOnKev: false,
    onlyFixed: false,
    outputFormat: ['summary'],
    apiBaseUrl: 'https://geekwala.com',
    retryAttempts: 3,
    timeoutSeconds: 300,
    ...overrides,
  };
}

jest.setTimeout(15000);

describe('Reporting Integration', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Output Manager - setActionOutputs', () => {
    it('should set all outputs for clean scan', () => {
      setActionOutputs(fixtures.cleanScanResponse);

      expect(core.setOutput).toHaveBeenCalledWith('total-packages', '1');
      expect(core.setOutput).toHaveBeenCalledWith('vulnerable-packages', '0');
      expect(core.setOutput).toHaveBeenCalledWith('safe-packages', '1');
      expect(core.setOutput).toHaveBeenCalledWith('critical-count', '0');
      expect(core.setOutput).toHaveBeenCalledWith('high-count', '0');
      expect(core.setOutput).toHaveBeenCalledWith('medium-count', '0');
      expect(core.setOutput).toHaveBeenCalledWith('low-count', '0');
      expect(core.setOutput).toHaveBeenCalledWith('has-vulnerabilities', 'false');
    });

    it('should set all outputs for vulnerable scan', () => {
      setActionOutputs(fixtures.vulnerableScanResponse);

      expect(core.setOutput).toHaveBeenCalledWith('total-packages', '2');
      expect(core.setOutput).toHaveBeenCalledWith('vulnerable-packages', '1');
      expect(core.setOutput).toHaveBeenCalledWith('safe-packages', '1');
      expect(core.setOutput).toHaveBeenCalledWith('critical-count', '0');
      expect(core.setOutput).toHaveBeenCalledWith('high-count', '1');
      expect(core.setOutput).toHaveBeenCalledWith('medium-count', '0');
      expect(core.setOutput).toHaveBeenCalledWith('low-count', '0');
      expect(core.setOutput).toHaveBeenCalledWith('has-vulnerabilities', 'true');
    });

    it('should calculate severity counts correctly for mixed severities', () => {
      setActionOutputs(fixtures.mixedSeverityResponse);

      expect(core.setOutput).toHaveBeenCalledWith('critical-count', '1');
      expect(core.setOutput).toHaveBeenCalledWith('high-count', '2');
      expect(core.setOutput).toHaveBeenCalledWith('medium-count', '3');
      expect(core.setOutput).toHaveBeenCalledWith('low-count', '1');
    });

    it('should handle error response gracefully', () => {
      const errorResponse = {
        success: false,
        error: 'API error',
      };

      setActionOutputs(errorResponse);

      expect(core.setOutput).toHaveBeenCalledWith('scan-status', 'ERROR');
      expect(core.setOutput).toHaveBeenCalledWith('has-vulnerabilities', 'false');
    });

    it('should handle large vulnerability counts', () => {
      setActionOutputs(fixtures.largeVulnListResponse);

      expect(core.setOutput).toHaveBeenCalledWith('vulnerable-packages', '1');
      expect(core.setOutput).toHaveBeenCalled();
    });
  });

  describe('Output Manager - checkFailureThresholds', () => {
    it('should return PASS for clean scan', () => {
      const result = checkFailureThresholds(fixtures.cleanScanResponse, makeInputs());

      expect(result.shouldFail).toBe(false);
      expect(result.status).toBe('PASS');
      expect(result.reason).toBeUndefined();
    });

    it('should return PASS when vulnerabilities exist but thresholds not enabled', () => {
      const result = checkFailureThresholds(fixtures.vulnerableScanResponse, makeInputs());

      expect(result.shouldFail).toBe(false);
      expect(result.status).toBe('PASS');
    });

    it('should return FAIL when severity-threshold is critical and critical vulnerabilities exist', () => {
      const result = checkFailureThresholds(
        fixtures.criticalVulnResponse,
        makeInputs({ severityThreshold: 'critical' })
      );

      expect(result.shouldFail).toBe(true);
      expect(result.status).toBe('FAIL');
      expect(result.reason).toContain('critical');
    });

    it('should use correct pluralization for multiple vulnerabilities', () => {
      const multiCriticalResponse = {
        success: true,
        data: {
          summary: { total_packages: 2, vulnerable_packages: 2, safe_packages: 0 },
          results: [
            {
              ecosystem: 'npm',
              package: 'pkg1',
              version: '1.0.0',
              affected: true,
              severity: 'CRITICAL',
              vulnerabilities: [{ id: 'CVE-1', cvss_score: 9.8 }],
            },
            {
              ecosystem: 'npm',
              package: 'pkg2',
              version: '1.0.0',
              affected: true,
              severity: 'CRITICAL',
              vulnerabilities: [{ id: 'CVE-2', cvss_score: 9.5 }],
            },
          ],
        },
      };

      const result = checkFailureThresholds(
        multiCriticalResponse,
        makeInputs({ severityThreshold: 'critical' })
      );

      expect(result.shouldFail).toBe(true);
      expect(result.reason).toContain('2 vulnerabilities');
    });

    it('should return FAIL when severity-threshold is high and high vulnerabilities exist', () => {
      const result = checkFailureThresholds(
        fixtures.vulnerableScanResponse,
        makeInputs({ severityThreshold: 'high' })
      );

      expect(result.shouldFail).toBe(true);
      expect(result.status).toBe('FAIL');
      expect(result.reason).toContain('high');
    });

    it('should fail on both critical and high when severity-threshold is high', () => {
      const result = checkFailureThresholds(
        fixtures.mixedSeverityResponse,
        makeInputs({ severityThreshold: 'high' })
      );

      expect(result.shouldFail).toBe(true);
      expect(result.status).toBe('FAIL');
      // Should count both critical and high
      expect(result.reason).toContain('high');
    });

    it('should return PASS when only medium/low vulnerabilities exist with high threshold', () => {
      const mediumOnlyResponse = {
        success: true,
        data: {
          summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
          results: [
            {
              ecosystem: 'npm',
              package: 'pkg',
              version: '1.0.0',
              affected: true,
              severity: 'MEDIUM',
              vulnerabilities: [{ id: 'CVE-1', cvss_score: 5.0 }],
            },
          ],
        },
      };

      const result = checkFailureThresholds(
        mediumOnlyResponse,
        makeInputs({ severityThreshold: 'high' })
      );

      expect(result.shouldFail).toBe(false);
      expect(result.status).toBe('PASS');
    });

    it('should return ERROR for failed scan', () => {
      const errorResponse = {
        success: false,
        error: 'API error',
      };

      const result = checkFailureThresholds(errorResponse, makeInputs());

      expect(result.shouldFail).toBe(true);
      expect(result.status).toBe('ERROR');
      expect(result.reason).toBe('Scan failed');
    });

    it('should fail on KEV independently of severity threshold', () => {
      const result = checkFailureThresholds(
        fixtures.criticalVulnResponse,
        makeInputs({ failOnKev: true })
      );

      expect(result.shouldFail).toBe(true);
      expect(result.reason).toContain('CISA Known Exploited');
    });

    it('should fail on EPSS threshold', () => {
      const result = checkFailureThresholds(
        fixtures.criticalVulnResponse,
        makeInputs({ epssThreshold: 0.5 })
      );

      expect(result.shouldFail).toBe(true);
      expect(result.reason).toContain('EPSS score at or above 0.5');
    });

    it('should pass when EPSS scores are below threshold', () => {
      const result = checkFailureThresholds(
        fixtures.vulnerableScanResponse,
        makeInputs({ epssThreshold: 0.5 })
      );

      // lodash vuln has epss_score: 0.00234, which is below 0.5
      expect(result.shouldFail).toBe(false);
    });

    it('should exclude ignored vulnerabilities from threshold checks', () => {
      const responseWithIgnored = {
        success: true,
        data: {
          summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
          results: [
            {
              ecosystem: 'npm',
              package: 'pkg',
              version: '1.0.0',
              affected: true,
              severity: 'CRITICAL',
              vulnerabilities: [
                { id: 'CVE-1', cvss_score: 9.8, _ignored: true, _ignoreReason: 'accepted risk' },
              ],
            },
          ],
        },
      };

      const result = checkFailureThresholds(
        responseWithIgnored,
        makeInputs({ severityThreshold: 'critical' })
      );

      expect(result.shouldFail).toBe(false);
      expect(result.status).toBe('PASS');
    });

    it('should filter to only-fixed vulns when enabled', () => {
      const responseWithMixedFixes = {
        success: true,
        data: {
          summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
          results: [
            {
              ecosystem: 'npm',
              package: 'pkg',
              version: '1.0.0',
              affected: true,
              severity: 'CRITICAL',
              vulnerabilities: [
                { id: 'CVE-1', cvss_score: 9.8, fix_version: null },
                { id: 'CVE-2', cvss_score: 9.5, fix_version: '2.0.0' },
              ],
            },
          ],
        },
      };

      // Without only-fixed: both count
      const resultAll = checkFailureThresholds(
        responseWithMixedFixes,
        makeInputs({ severityThreshold: 'critical' })
      );
      expect(resultAll.shouldFail).toBe(true);
      expect(resultAll.reason).toContain('2 vulnerabilities');

      // With only-fixed: only the one with fix_version counts
      const resultFixed = checkFailureThresholds(
        responseWithMixedFixes,
        makeInputs({ severityThreshold: 'critical', onlyFixed: true })
      );
      expect(resultFixed.shouldFail).toBe(true);
      expect(resultFixed.reason).toContain('1 vulnerability');
    });

    it('should accumulate multiple fail reasons', () => {
      const result = checkFailureThresholds(
        fixtures.criticalVulnResponse,
        makeInputs({ severityThreshold: 'critical', failOnKev: true, epssThreshold: 0.5 })
      );

      expect(result.shouldFail).toBe(true);
      expect(result.reasons.length).toBeGreaterThanOrEqual(2);
      expect(result.reason).toContain(';');
    });
  });

  describe('Summary Reporter', () => {
    let mockSummary: any;

    beforeEach(() => {
      // Create a mock summary object with chainable methods
      mockSummary = {
        addHeading: jest.fn().mockReturnThis(),
        addRaw: jest.fn().mockReturnThis(),
        addBreak: jest.fn().mockReturnThis(),
        addTable: jest.fn().mockReturnThis(),
        write: jest.fn().mockResolvedValue(undefined),
      };

      (core.summary as any) = mockSummary;
    });

    it('should generate summary for clean scan', async () => {
      await generateSummary(fixtures.cleanScanResponse, 'package.json');

      expect(mockSummary.addHeading).toHaveBeenCalledWith(
        '🛡️ GeekWala Security Scan Results',
        1
      );
      expect(mockSummary.addRaw).toHaveBeenCalledWith('**File scanned:** `package.json`');
      expect(mockSummary.addRaw).toHaveBeenCalledWith(
        '✅ No vulnerabilities detected in scanned packages.'
      );
      expect(mockSummary.write).toHaveBeenCalled();
    });

    it('should generate summary for vulnerable scan with vulnerability details', async () => {
      await generateSummary(fixtures.vulnerableScanResponse, 'package.json');

      expect(mockSummary.addHeading).toHaveBeenCalledWith(
        '🛡️ GeekWala Security Scan Results',
        1
      );
      expect(mockSummary.addHeading).toHaveBeenCalledWith('Severity Breakdown', 2);
      expect(mockSummary.addHeading).toHaveBeenCalledWith('Vulnerable Packages', 2);
      expect(mockSummary.addTable).toHaveBeenCalled();
      expect(mockSummary.write).toHaveBeenCalled();
    });

    it('should include CVSS scores in summary', async () => {
      await generateSummary(fixtures.vulnerableScanResponse, 'package.json');

      const rawCalls = (mockSummary.addRaw as jest.Mock).mock.calls;
      const hasRawWithCVSS = rawCalls.some((call) =>
        call[0].includes('CVSS:') || call[0].includes('7.2')
      );
      expect(hasRawWithCVSS).toBe(true);
    });

    it('should include EPSS scores in summary', async () => {
      await generateSummary(fixtures.vulnerableScanResponse, 'package.json');

      const rawCalls = (mockSummary.addRaw as jest.Mock).mock.calls;
      const hasRawWithEPSS = rawCalls.some((call) => call[0].includes('EPSS:'));
      expect(hasRawWithEPSS).toBe(true);
    });

    it('should include KEV flags in summary', async () => {
      await generateSummary(fixtures.criticalVulnResponse, 'package.json');

      const rawCalls = (mockSummary.addRaw as jest.Mock).mock.calls;
      const hasKEV = rawCalls.some((call) => call[0].includes('CISA KEV'));
      expect(hasKEV).toBe(true);
    });

    it('should handle missing enrichment data gracefully', async () => {
      await generateSummary(fixtures.missingEnrichmentResponse, 'package.json');

      expect(mockSummary.write).toHaveBeenCalled();
    });

    it('should generate error summary for failed scan', async () => {
      const errorResponse = {
        success: false,
        error: 'Authentication failed',
      };

      await generateSummary(errorResponse, 'package.json');

      expect(mockSummary.addHeading).toHaveBeenCalledWith(
        '🛡️ GeekWala Security Scan - Error',
        1
      );
      expect(mockSummary.addRaw).toHaveBeenCalledWith('**Error:** Authentication failed');
      expect(mockSummary.write).toHaveBeenCalled();
    });

    it('should include severity breakdown table with correct counts', async () => {
      await generateSummary(fixtures.mixedSeverityResponse, 'package.json');

      expect(mockSummary.addTable).toHaveBeenCalledWith([
        [
          { data: 'Severity', header: true },
          { data: 'Count', header: true },
        ],
        ['🔴 Critical', '1'],
        ['🟠 High', '2'],
        ['🟡 Medium', '3'],
        ['🟢 Low', '1'],
      ]);
    });

    it('should include GeekWala branding in footer', async () => {
      await generateSummary(fixtures.cleanScanResponse, 'package.json');

      const rawCalls = (mockSummary.addRaw as jest.Mock).mock.calls;
      const hasGeekWalaBranding = rawCalls.some((call) =>
        call[0].includes('Powered by [GeekWala]')
      );
      expect(hasGeekWalaBranding).toBe(true);
    });
  });
});
