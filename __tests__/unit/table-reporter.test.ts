/**
 * Tests for table reporter
 */

import * as core from '@actions/core';
import { generateTableOutput } from '../../src/reporter/table-reporter';
import {
  cleanScanResponse,
  vulnerableScanResponse,
  criticalVulnResponse,
  missingEnrichmentResponse,
  authErrorResponse,
  serverErrorResponse,
} from '../fixtures/api-responses';
import { ApiResponse } from '../../src/api/types';

jest.mock('@actions/core');

describe('Table Reporter', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('generateTableOutput', () => {
    it('should print "No active vulnerabilities found." for clean scan', () => {
      generateTableOutput(cleanScanResponse);

      expect(core.info).toHaveBeenCalledWith('No active vulnerabilities found.');
      expect(core.info).toHaveBeenCalledTimes(1);
    });

    it('should output table with header, separator, and rows for vulnerable scan', () => {
      generateTableOutput(vulnerableScanResponse);

      const infoMock = core.info as jest.Mock;
      const calls = infoMock.mock.calls.map(call => call[0]);

      // Should start with empty line
      expect(calls[0]).toBe('');

      // Should have header
      expect(calls[1]).toContain('Package');
      expect(calls[1]).toContain('Version');
      expect(calls[1]).toContain('Vulnerability');
      expect(calls[1]).toContain('Severity');
      expect(calls[1]).toContain('EPSS');
      expect(calls[1]).toContain('KEV');
      expect(calls[1]).toContain('Fix');

      // Should have separator (Unicode box-drawing character)
      expect(calls[2]).toMatch(/\u2500+/);

      // Should have vulnerability row
      expect(calls[3]).toContain('lodash');
      expect(calls[3]).toContain('4.17.20');
      expect(calls[3]).toContain('CVE-2021-23337');
      expect(calls[3]).toContain('HIGH');
      expect(calls[3]).toContain('0.2%'); // EPSS 0.00234 * 100
      expect(calls[3]).toContain('-'); // Not KEV

      // Should end with empty line
      expect(calls[4]).toBe('');

      // Total calls: empty line + header + separator + 1 vuln + empty line
      expect(infoMock).toHaveBeenCalledTimes(5);
    });

    it('should exclude ignored vulnerabilities from table output', () => {
      const responseWithIgnored: ApiResponse = {
        success: true,
        data: {
          summary: {
            total_packages: 1,
            vulnerable_packages: 1,
            safe_packages: 0,
          },
          results: [
            {
              ecosystem: 'npm',
              package: 'test-pkg',
              version: '1.0.0',
              affected: true,
              severity: 'HIGH',
              vulnerabilities: [
                {
                  id: 'CVE-2024-0001',
                  summary: 'Active vulnerability',
                  cvss_score: 7.5,
                  epss_score: 0.5,
                },
                {
                  id: 'CVE-2024-0002',
                  summary: 'Ignored vulnerability',
                  cvss_score: 9.0,
                  _ignored: true,
                },
              ],
            },
          ],
        },
      };

      generateTableOutput(responseWithIgnored);

      const infoMock = core.info as jest.Mock;
      const allOutput = infoMock.mock.calls.map(call => call[0]).join('\n');

      // Should contain the active vulnerability
      expect(allOutput).toContain('CVE-2024-0001');

      // Should NOT contain the ignored vulnerability
      expect(allOutput).not.toContain('CVE-2024-0002');

      // Should have exactly 1 vulnerability row (not 2)
      // empty line + header + separator + 1 row + empty line = 5 calls
      expect(infoMock).toHaveBeenCalledTimes(5);
    });

    it('should exclude all ignored vulnerabilities and print "No active vulnerabilities" message', () => {
      const allIgnoredResponse: ApiResponse = {
        success: true,
        data: {
          summary: {
            total_packages: 1,
            vulnerable_packages: 1,
            safe_packages: 0,
          },
          results: [
            {
              ecosystem: 'npm',
              package: 'test-pkg',
              version: '1.0.0',
              affected: true,
              severity: 'HIGH',
              vulnerabilities: [
                {
                  id: 'CVE-2024-0001',
                  summary: 'Ignored vulnerability 1',
                  cvss_score: 7.5,
                  _ignored: true,
                },
                {
                  id: 'CVE-2024-0002',
                  summary: 'Ignored vulnerability 2',
                  cvss_score: 9.0,
                  _ignored: true,
                },
              ],
            },
          ],
        },
      };

      generateTableOutput(allIgnoredResponse);

      expect(core.info).toHaveBeenCalledWith('No active vulnerabilities found.');
      expect(core.info).toHaveBeenCalledTimes(1);
    });

    it('should return early without calling core.info for error response', () => {
      generateTableOutput(authErrorResponse as ApiResponse);
      expect(core.info).not.toHaveBeenCalled();

      jest.clearAllMocks();

      generateTableOutput(serverErrorResponse as ApiResponse);
      expect(core.info).not.toHaveBeenCalled();
    });

    it('should return early without calling core.info for failed response', () => {
      const failedResponse: ApiResponse = {
        success: false,
        error: 'API Error',
        type: 'api_error',
      };

      generateTableOutput(failedResponse);
      expect(core.info).not.toHaveBeenCalled();
    });

    it('should sort KEV vulnerabilities first', () => {
      const kevSortingResponse: ApiResponse = {
        success: true,
        data: {
          summary: {
            total_packages: 3,
            vulnerable_packages: 3,
            safe_packages: 0,
          },
          results: [
            {
              ecosystem: 'npm',
              package: 'pkg-low-cvss',
              version: '1.0.0',
              affected: true,
              severity: 'MEDIUM',
              vulnerabilities: [
                {
                  id: 'CVE-2024-0001',
                  summary: 'KEV with low CVSS',
                  cvss_score: 5.0,
                  epss_score: 0.1,
                  is_known_exploited: true,
                },
              ],
            },
            {
              ecosystem: 'npm',
              package: 'pkg-high-cvss',
              version: '2.0.0',
              affected: true,
              severity: 'CRITICAL',
              vulnerabilities: [
                {
                  id: 'CVE-2024-0002',
                  summary: 'High CVSS but not KEV',
                  cvss_score: 10.0,
                  epss_score: 0.9,
                  is_known_exploited: false,
                },
              ],
            },
            {
              ecosystem: 'npm',
              package: 'pkg-kev-critical',
              version: '3.0.0',
              affected: true,
              severity: 'CRITICAL',
              vulnerabilities: [
                {
                  id: 'CVE-2024-0003',
                  summary: 'KEV with critical CVSS',
                  cvss_score: 9.5,
                  epss_score: 0.8,
                  is_known_exploited: true,
                },
              ],
            },
          ],
        },
      };

      generateTableOutput(kevSortingResponse);

      const infoMock = core.info as jest.Mock;
      const calls = infoMock.mock.calls.map(call => call[0]);

      // Find vulnerability rows (skip empty line, header, separator)
      const rows = calls.slice(3, -1); // Exclude trailing empty line

      // First row should be KEV with critical CVSS
      expect(rows[0]).toContain('CVE-2024-0003');
      expect(rows[0]).toContain('YES'); // KEV indicator

      // Second row should be KEV with low CVSS
      expect(rows[1]).toContain('CVE-2024-0001');
      expect(rows[1]).toContain('YES'); // KEV indicator

      // Third row should be non-KEV with high CVSS
      expect(rows[2]).toContain('CVE-2024-0002');
      expect(rows[2]).toContain('-'); // Not KEV (should have 3 dashes, one for EPSS might be replaced with percentage)
    });

    it('should sort by EPSS score (desc) when KEV status is equal', () => {
      const epssSortingResponse: ApiResponse = {
        success: true,
        data: {
          summary: {
            total_packages: 3,
            vulnerable_packages: 3,
            safe_packages: 0,
          },
          results: [
            {
              ecosystem: 'npm',
              package: 'pkg-low-epss',
              version: '1.0.0',
              affected: true,
              severity: 'HIGH',
              vulnerabilities: [
                {
                  id: 'CVE-2024-0001',
                  summary: 'Low EPSS',
                  cvss_score: 7.5,
                  epss_score: 0.1,
                  is_known_exploited: false,
                },
              ],
            },
            {
              ecosystem: 'npm',
              package: 'pkg-high-epss',
              version: '2.0.0',
              affected: true,
              severity: 'HIGH',
              vulnerabilities: [
                {
                  id: 'CVE-2024-0002',
                  summary: 'High EPSS',
                  cvss_score: 7.5,
                  epss_score: 0.9,
                  is_known_exploited: false,
                },
              ],
            },
            {
              ecosystem: 'npm',
              package: 'pkg-medium-epss',
              version: '3.0.0',
              affected: true,
              severity: 'HIGH',
              vulnerabilities: [
                {
                  id: 'CVE-2024-0003',
                  summary: 'Medium EPSS',
                  cvss_score: 7.5,
                  epss_score: 0.5,
                  is_known_exploited: false,
                },
              ],
            },
          ],
        },
      };

      generateTableOutput(epssSortingResponse);

      const infoMock = core.info as jest.Mock;
      const calls = infoMock.mock.calls.map(call => call[0]);
      const rows = calls.slice(3, -1);

      // Should be sorted by EPSS desc: 0.9, 0.5, 0.1
      expect(rows[0]).toContain('CVE-2024-0002');
      expect(rows[0]).toContain('90.0%'); // 0.9 * 100

      expect(rows[1]).toContain('CVE-2024-0003');
      expect(rows[1]).toContain('50.0%'); // 0.5 * 100

      expect(rows[2]).toContain('CVE-2024-0001');
      expect(rows[2]).toContain('10.0%'); // 0.1 * 100
    });

    it('should sort by CVSS score (desc) when KEV and EPSS are equal', () => {
      const cvssSortingResponse: ApiResponse = {
        success: true,
        data: {
          summary: {
            total_packages: 3,
            vulnerable_packages: 3,
            safe_packages: 0,
          },
          results: [
            {
              ecosystem: 'npm',
              package: 'pkg-low-cvss',
              version: '1.0.0',
              affected: true,
              severity: 'MEDIUM',
              vulnerabilities: [
                {
                  id: 'CVE-2024-0001',
                  summary: 'Low CVSS',
                  cvss_score: 5.0,
                  epss_score: 0.5,
                  is_known_exploited: false,
                },
              ],
            },
            {
              ecosystem: 'npm',
              package: 'pkg-high-cvss',
              version: '2.0.0',
              affected: true,
              severity: 'CRITICAL',
              vulnerabilities: [
                {
                  id: 'CVE-2024-0002',
                  summary: 'High CVSS',
                  cvss_score: 9.5,
                  epss_score: 0.5,
                  is_known_exploited: false,
                },
              ],
            },
            {
              ecosystem: 'npm',
              package: 'pkg-medium-cvss',
              version: '3.0.0',
              affected: true,
              severity: 'HIGH',
              vulnerabilities: [
                {
                  id: 'CVE-2024-0003',
                  summary: 'Medium CVSS',
                  cvss_score: 7.5,
                  epss_score: 0.5,
                  is_known_exploited: false,
                },
              ],
            },
          ],
        },
      };

      generateTableOutput(cvssSortingResponse);

      const infoMock = core.info as jest.Mock;
      const calls = infoMock.mock.calls.map(call => call[0]);
      const rows = calls.slice(3, -1);

      // Should be sorted by CVSS desc: 9.5, 7.5, 5.0
      expect(rows[0]).toContain('CVE-2024-0002');
      expect(rows[0]).toContain('CRITICAL');

      expect(rows[1]).toContain('CVE-2024-0003');
      expect(rows[1]).toContain('HIGH');

      expect(rows[2]).toContain('CVE-2024-0001');
      expect(rows[2]).toContain('MEDIUM');
    });

    it('should display "-" for missing EPSS data', () => {
      generateTableOutput(missingEnrichmentResponse);

      const infoMock = core.info as jest.Mock;
      const calls = infoMock.mock.calls.map(call => call[0]);
      const vulnRow = calls[3]; // First vulnerability row after header and separator

      // Should show dash for missing EPSS
      expect(vulnRow).toContain('CVE-2024-9999');
      expect(vulnRow).toContain('UNKNOWN'); // Severity when CVSS is null

      // The row should contain multiple dashes for missing data (EPSS and KEV)
      // Format: Package  Version  Vulnerability  Severity  EPSS  KEV  Fix
      // With null values, we expect: "-" for EPSS, "-" for KEV (not KEV), "-" for fix
      expect(vulnRow).toMatch(/UNKNOWN\s+-\s+-\s+-/);
    });

    it('should display "-" for missing fix version', () => {
      const noFixResponse: ApiResponse = {
        success: true,
        data: {
          summary: {
            total_packages: 1,
            vulnerable_packages: 1,
            safe_packages: 0,
          },
          results: [
            {
              ecosystem: 'npm',
              package: 'no-fix-pkg',
              version: '1.0.0',
              affected: true,
              severity: 'HIGH',
              vulnerabilities: [
                {
                  id: 'CVE-2024-9998',
                  summary: 'Vulnerability without fix',
                  cvss_score: 7.5,
                  epss_score: 0.3,
                  is_known_exploited: false,
                  fix_version: null,
                },
              ],
            },
          ],
        },
      };

      generateTableOutput(noFixResponse);

      const infoMock = core.info as jest.Mock;
      const calls = infoMock.mock.calls.map(call => call[0]);
      const vulnRow = calls[3];

      // Should end with dash for missing fix
      expect(vulnRow).toContain('CVE-2024-9998');
      expect(vulnRow.trim()).toMatch(/-$/); // Ends with dash
    });

    it('should display fix version when available', () => {
      const withFixResponse: ApiResponse = {
        success: true,
        data: {
          summary: {
            total_packages: 1,
            vulnerable_packages: 1,
            safe_packages: 0,
          },
          results: [
            {
              ecosystem: 'npm',
              package: 'fixable-pkg',
              version: '1.0.0',
              affected: true,
              severity: 'HIGH',
              vulnerabilities: [
                {
                  id: 'CVE-2024-9997',
                  summary: 'Vulnerability with fix',
                  cvss_score: 7.5,
                  epss_score: 0.3,
                  is_known_exploited: false,
                  fix_version: '1.2.3',
                },
              ],
            },
          ],
        },
      };

      generateTableOutput(withFixResponse);

      const infoMock = core.info as jest.Mock;
      const calls = infoMock.mock.calls.map(call => call[0]);
      const vulnRow = calls[3];

      // Should show fix version at end
      expect(vulnRow).toContain('CVE-2024-9997');
      expect(vulnRow).toContain('1.2.3');
    });

    it('should handle package with multiple vulnerabilities', () => {
      const multiVulnResponse: ApiResponse = {
        success: true,
        data: {
          summary: {
            total_packages: 1,
            vulnerable_packages: 1,
            safe_packages: 0,
          },
          results: [
            {
              ecosystem: 'npm',
              package: 'multi-vuln-pkg',
              version: '1.0.0',
              affected: true,
              severity: 'CRITICAL',
              vulnerabilities: [
                {
                  id: 'CVE-2024-0001',
                  summary: 'First vulnerability',
                  cvss_score: 9.0,
                  epss_score: 0.8,
                  is_known_exploited: true,
                },
                {
                  id: 'CVE-2024-0002',
                  summary: 'Second vulnerability',
                  cvss_score: 7.0,
                  epss_score: 0.5,
                  is_known_exploited: false,
                },
                {
                  id: 'CVE-2024-0003',
                  summary: 'Third vulnerability',
                  cvss_score: 5.0,
                  epss_score: 0.2,
                  is_known_exploited: false,
                },
              ],
            },
          ],
        },
      };

      generateTableOutput(multiVulnResponse);

      const infoMock = core.info as jest.Mock;
      const calls = infoMock.mock.calls.map(call => call[0]);

      // Should have 3 vulnerability rows
      // empty line + header + separator + 3 vulns + empty line = 7 calls
      expect(infoMock).toHaveBeenCalledTimes(7);

      const allOutput = calls.join('\n');
      expect(allOutput).toContain('CVE-2024-0001');
      expect(allOutput).toContain('CVE-2024-0002');
      expect(allOutput).toContain('CVE-2024-0003');

      // All should show same package
      const rows = calls.slice(3, -1);
      rows.forEach(row => {
        expect(row).toContain('multi-vuln-pkg');
      });
    });

    it('should format EPSS scores as percentages with one decimal place', () => {
      generateTableOutput(criticalVulnResponse);

      const infoMock = core.info as jest.Mock;
      const calls = infoMock.mock.calls.map(call => call[0]);
      const vulnRow = calls[3];

      // EPSS score 0.97534 should be displayed as "97.5%"
      expect(vulnRow).toContain('97.5%');
    });

    it('should display "YES" for KEV vulnerabilities', () => {
      generateTableOutput(criticalVulnResponse);

      const infoMock = core.info as jest.Mock;
      const calls = infoMock.mock.calls.map(call => call[0]);
      const vulnRow = calls[3];

      // Should show YES for KEV
      expect(vulnRow).toContain('YES');
      expect(vulnRow).toContain('CVE-2021-44228');
    });

    it('should handle empty results array', () => {
      const emptyResultsResponse: ApiResponse = {
        success: true,
        data: {
          summary: {
            total_packages: 0,
            vulnerable_packages: 0,
            safe_packages: 0,
          },
          results: [],
        },
      };

      generateTableOutput(emptyResultsResponse);

      expect(core.info).toHaveBeenCalledWith('No active vulnerabilities found.');
      expect(core.info).toHaveBeenCalledTimes(1);
    });

    it('should return early when response.data is undefined', () => {
      const response: ApiResponse = {
        success: true,
      } as ApiResponse;

      generateTableOutput(response);
      expect(core.info).not.toHaveBeenCalled();
    });

    it('should handle results with no affected packages', () => {
      const noAffectedResponse: ApiResponse = {
        success: true,
        data: {
          summary: {
            total_packages: 2,
            vulnerable_packages: 0,
            safe_packages: 2,
          },
          results: [
            {
              ecosystem: 'npm',
              package: 'safe-pkg-1',
              version: '1.0.0',
              affected: false,
              vulnerabilities: [],
              severity: 'NONE',
            },
            {
              ecosystem: 'npm',
              package: 'safe-pkg-2',
              version: '2.0.0',
              affected: false,
              vulnerabilities: [],
              severity: 'NONE',
            },
          ],
        },
      };

      generateTableOutput(noAffectedResponse);

      expect(core.info).toHaveBeenCalledWith('No active vulnerabilities found.');
      expect(core.info).toHaveBeenCalledTimes(1);
    });
  });
});
