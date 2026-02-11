/**
 * Tests for output management and failure thresholds
 */

import * as core from '@actions/core';
import { setActionOutputs, checkFailureThresholds } from '../../src/reporter/output-manager';
import { ApiResponse, ActionInputs, Vulnerability, ScanResult } from '../../src/api/types';

jest.mock('@actions/core');

/**
 * Helper to create ActionInputs with defaults
 */
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

/**
 * Helper to create a vulnerability object
 */
function makeVuln(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: 'GHSA-test-1234',
    summary: 'Test vulnerability',
    severity: [{ type: 'CVSS_V3', score: '7.5' }],
    ...overrides,
  };
}

/**
 * Helper to create a ScanResult
 */
function makeScanResult(vulnerabilities: Vulnerability[]): ScanResult {
  return {
    ecosystem: 'npm',
    package: 'test-package',
    version: '1.0.0',
    affected: vulnerabilities.length > 0,
    vulnerabilities,
    severity: vulnerabilities.length > 0 ? 'HIGH' : 'NONE',
  };
}

/**
 * Helper to create an ApiResponse
 */
function makeResponse(results: ScanResult[]): ApiResponse {
  const vulnerablePackages = results.filter(r => r.affected).length;
  const totalPackages = results.length;

  return {
    success: true,
    data: {
      results,
      summary: {
        total_packages: totalPackages,
        vulnerable_packages: vulnerablePackages,
        safe_packages: totalPackages - vulnerablePackages,
      },
    },
  };
}

describe('setActionOutputs', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should set outputs for successful scan with no vulnerabilities', () => {
    const response = makeResponse([
      makeScanResult([]),
    ]);

    setActionOutputs(response);

    expect(core.setOutput).toHaveBeenCalledWith('total-packages', '1');
    expect(core.setOutput).toHaveBeenCalledWith('vulnerable-packages', '0');
    expect(core.setOutput).toHaveBeenCalledWith('safe-packages', '1');
    expect(core.setOutput).toHaveBeenCalledWith('critical-count', '0');
    expect(core.setOutput).toHaveBeenCalledWith('high-count', '0');
    expect(core.setOutput).toHaveBeenCalledWith('medium-count', '0');
    expect(core.setOutput).toHaveBeenCalledWith('low-count', '0');
    expect(core.setOutput).toHaveBeenCalledWith('has-vulnerabilities', 'false');
  });

  it('should set ERROR status for failed scan', () => {
    const response: ApiResponse = {
      success: false,
      error: 'API error',
    };

    setActionOutputs(response);

    expect(core.setOutput).toHaveBeenCalledWith('scan-status', 'ERROR');
    expect(core.setOutput).toHaveBeenCalledWith('has-vulnerabilities', 'false');
  });

  describe('DATA-001: Count only active (non-ignored) vulnerabilities', () => {
    it('should exclude ignored vulnerabilities from severity counts', () => {
      const response = makeResponse([
        makeScanResult([
          // 2 ignored critical vulnerabilities
          makeVuln({
            id: 'GHSA-crit-0001',
            severity: [{ type: 'CVSS_V3', score: '9.8' }],
            _ignored: true,
            _ignoreReason: 'False positive',
          }),
          makeVuln({
            id: 'GHSA-crit-0002',
            severity: [{ type: 'CVSS_V3', score: '9.0' }],
            _ignored: true,
            _ignoreReason: 'Not applicable',
          }),
          // 1 active low vulnerability
          makeVuln({
            id: 'GHSA-low-0001',
            severity: [{ type: 'CVSS_V3', score: '2.5' }],
            _ignored: false,
          }),
        ]),
      ]);

      setActionOutputs(response);

      // Should count only the active low vulnerability
      expect(core.setOutput).toHaveBeenCalledWith('critical-count', '0');
      expect(core.setOutput).toHaveBeenCalledWith('high-count', '0');
      expect(core.setOutput).toHaveBeenCalledWith('medium-count', '0');
      expect(core.setOutput).toHaveBeenCalledWith('low-count', '1');
    });

    it('should count all vulnerabilities when none are ignored', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            id: 'GHSA-crit-0001',
            severity: [{ type: 'CVSS_V3', score: '9.8' }],
          }),
          makeVuln({
            id: 'GHSA-high-0001',
            severity: [{ type: 'CVSS_V3', score: '7.5' }],
          }),
          makeVuln({
            id: 'GHSA-med-0001',
            severity: [{ type: 'CVSS_V3', score: '5.0' }],
          }),
          makeVuln({
            id: 'GHSA-low-0001',
            severity: [{ type: 'CVSS_V3', score: '2.0' }],
          }),
        ]),
      ]);

      setActionOutputs(response);

      expect(core.setOutput).toHaveBeenCalledWith('critical-count', '1');
      expect(core.setOutput).toHaveBeenCalledWith('high-count', '1');
      expect(core.setOutput).toHaveBeenCalledWith('medium-count', '1');
      expect(core.setOutput).toHaveBeenCalledWith('low-count', '1');
    });

    it('should handle mixed ignored and active vulnerabilities across multiple packages', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            id: 'GHSA-crit-0001',
            severity: [{ type: 'CVSS_V3', score: '9.5' }],
            _ignored: true,
          }),
          makeVuln({
            id: 'GHSA-high-0001',
            severity: [{ type: 'CVSS_V3', score: '7.5' }],
          }),
        ]),
        makeScanResult([
          makeVuln({
            id: 'GHSA-med-0001',
            severity: [{ type: 'CVSS_V3', score: '5.0' }],
            _ignored: true,
          }),
          makeVuln({
            id: 'GHSA-low-0001',
            severity: [{ type: 'CVSS_V3', score: '3.0' }],
          }),
        ]),
      ]);

      setActionOutputs(response);

      // Only 1 high and 1 low should be counted (2 ignored)
      expect(core.setOutput).toHaveBeenCalledWith('critical-count', '0');
      expect(core.setOutput).toHaveBeenCalledWith('high-count', '1');
      expect(core.setOutput).toHaveBeenCalledWith('medium-count', '0');
      expect(core.setOutput).toHaveBeenCalledWith('low-count', '1');
    });

    it('should set has-vulnerabilities to false when all vulns are ignored', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            id: 'GHSA-crit-0001',
            severity: [{ type: 'CVSS_V3', score: '9.8' }],
            _ignored: true,
            _ignoreReason: 'False positive',
          }),
        ]),
      ]);

      setActionOutputs(response);

      expect(core.setOutput).toHaveBeenCalledWith('has-vulnerabilities', 'false');
      expect(core.setOutput).toHaveBeenCalledWith('vulnerable-packages', '0');
    });

    it('should compute corrected package counts when some vulns are ignored', () => {
      // 2 packages: first has all vulns ignored, second has active vulns
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            id: 'GHSA-ignored',
            severity: [{ type: 'CVSS_V3', score: '9.0' }],
            _ignored: true,
          }),
        ]),
        makeScanResult([
          makeVuln({
            id: 'GHSA-active',
            severity: [{ type: 'CVSS_V3', score: '7.5' }],
          }),
        ]),
      ]);

      setActionOutputs(response);

      // Raw summary says 2 vulnerable, but corrected should be 1
      expect(core.setOutput).toHaveBeenCalledWith('vulnerable-packages', '1');
      expect(core.setOutput).toHaveBeenCalledWith('safe-packages', '1');
      expect(core.setOutput).toHaveBeenCalledWith('has-vulnerabilities', 'true');
    });
  });
});

describe('checkFailureThresholds', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should pass when no vulnerabilities found', () => {
    const response = makeResponse([makeScanResult([])]);
    const inputs = makeInputs({ severityThreshold: 'critical' });

    const result = checkFailureThresholds(response, inputs);

    expect(result.shouldFail).toBe(false);
    expect(result.status).toBe('PASS');
    expect(result.reasons).toEqual([]);
  });

  it('should return ERROR status for failed scan', () => {
    const response: ApiResponse = { success: false, error: 'API error' };
    const inputs = makeInputs();

    const result = checkFailureThresholds(response, inputs);

    expect(result.shouldFail).toBe(true);
    expect(result.status).toBe('ERROR');
    expect(result.reason).toBe('Scan failed');
  });

  describe('severity threshold', () => {
    it('should fail when critical vulnerability found and threshold is critical', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            severity: [{ type: 'CVSS_V3', score: '9.5' }],
          }),
        ]),
      ]);
      const inputs = makeInputs({ severityThreshold: 'critical' });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(true);
      expect(result.status).toBe('FAIL');
      expect(result.reasons).toContain('Found 1 vulnerability at or above critical severity');
    });

    it('should pass when only low vulnerabilities and threshold is high', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            severity: [{ type: 'CVSS_V3', score: '2.5' }],
          }),
        ]),
      ]);
      const inputs = makeInputs({ severityThreshold: 'high' });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(false);
      expect(result.status).toBe('PASS');
    });

    it('should exclude ignored vulnerabilities from threshold check', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            severity: [{ type: 'CVSS_V3', score: '9.5' }],
            _ignored: true,
          }),
        ]),
      ]);
      const inputs = makeInputs({ severityThreshold: 'critical' });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(false);
      expect(result.status).toBe('PASS');
    });
  });

  describe('KEV (Known Exploited Vulnerabilities)', () => {
    it('should fail when KEV vulnerability found and failOnKev is true', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            is_known_exploited: true,
            kev_date_added: '2024-01-15',
          }),
        ]),
      ]);
      const inputs = makeInputs({ failOnKev: true });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(true);
      expect(result.status).toBe('FAIL');
      expect(result.reasons).toContain('Found 1 CISA Known Exploited vulnerability');
    });

    it('should pass when KEV vulnerability is ignored', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            is_known_exploited: true,
            _ignored: true,
          }),
        ]),
      ]);
      const inputs = makeInputs({ failOnKev: true });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(false);
      expect(result.status).toBe('PASS');
    });
  });

  describe('GATE-001: EPSS threshold uses >= (not >)', () => {
    it('should fail when EPSS score exactly matches threshold', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            id: 'GHSA-epss-exact',
            epss_score: 0.5,
            epss_percentile: 0.85,
          }),
        ]),
      ]);
      const inputs = makeInputs({ epssThreshold: 0.5 });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(true);
      expect(result.status).toBe('FAIL');
      expect(result.reasons).toContain('Found 1 vulnerability with EPSS score at or above 0.5');
    });

    it('should fail when EPSS score exceeds threshold', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            epss_score: 0.75,
          }),
        ]),
      ]);
      const inputs = makeInputs({ epssThreshold: 0.5 });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(true);
      expect(result.status).toBe('FAIL');
    });

    it('should pass when EPSS score is below threshold', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            epss_score: 0.49,
          }),
        ]),
      ]);
      const inputs = makeInputs({ epssThreshold: 0.5 });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(false);
      expect(result.status).toBe('PASS');
    });

    it('should handle edge case with EPSS threshold of 0.0', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            epss_score: 0.0,
          }),
        ]),
      ]);
      const inputs = makeInputs({ epssThreshold: 0.0 });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(true);
      expect(result.status).toBe('FAIL');
    });

    it('should handle edge case with EPSS threshold of 1.0', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            epss_score: 1.0,
          }),
        ]),
      ]);
      const inputs = makeInputs({ epssThreshold: 1.0 });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(true);
      expect(result.status).toBe('FAIL');
    });

    it('should exclude ignored vulnerabilities from EPSS check', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            epss_score: 0.9,
            _ignored: true,
          }),
        ]),
      ]);
      const inputs = makeInputs({ epssThreshold: 0.5 });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(false);
      expect(result.status).toBe('PASS');
    });

    it('should handle null EPSS scores', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            epss_score: null,
          }),
        ]),
      ]);
      const inputs = makeInputs({ epssThreshold: 0.5 });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(false);
      expect(result.status).toBe('PASS');
    });

    it('should handle undefined EPSS scores', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            // epss_score not set (undefined)
          }),
        ]),
      ]);
      const inputs = makeInputs({ epssThreshold: 0.5 });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(false);
      expect(result.status).toBe('PASS');
    });
  });

  describe('onlyFixed flag', () => {
    it('should only gate on vulnerabilities with fix_version when onlyFixed is true', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            id: 'GHSA-no-fix',
            severity: [{ type: 'CVSS_V3', score: '9.5' }],
            fix_version: null,
          }),
          makeVuln({
            id: 'GHSA-has-fix',
            severity: [{ type: 'CVSS_V3', score: '9.5' }],
            fix_version: '2.0.0',
          }),
        ]),
      ]);
      const inputs = makeInputs({
        severityThreshold: 'critical',
        onlyFixed: true,
      });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(true);
      expect(result.reasons).toContain('Found 1 vulnerability at or above critical severity');
    });

    it('should gate on all vulnerabilities when onlyFixed is false', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            severity: [{ type: 'CVSS_V3', score: '9.5' }],
            fix_version: null,
          }),
        ]),
      ]);
      const inputs = makeInputs({
        severityThreshold: 'critical',
        onlyFixed: false,
      });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(true);
    });
  });

  describe('multiple failure reasons', () => {
    it('should collect all failure reasons', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            severity: [{ type: 'CVSS_V3', score: '9.5' }],
            is_known_exploited: true,
            epss_score: 0.8,
          }),
        ]),
      ]);
      const inputs = makeInputs({
        severityThreshold: 'critical',
        failOnKev: true,
        epssThreshold: 0.5,
      });

      const result = checkFailureThresholds(response, inputs);

      expect(result.shouldFail).toBe(true);
      expect(result.reasons).toHaveLength(3);
      expect(result.reasons).toContain('Found 1 vulnerability at or above critical severity');
      expect(result.reasons).toContain('Found 1 CISA Known Exploited vulnerability');
      expect(result.reasons).toContain('Found 1 vulnerability with EPSS score at or above 0.5');
      expect(result.reason).toBe(
        'Found 1 vulnerability at or above critical severity; Found 1 CISA Known Exploited vulnerability; Found 1 vulnerability with EPSS score at or above 0.5'
      );
    });

    it('should handle plural counts correctly in failure messages', () => {
      const response = makeResponse([
        makeScanResult([
          makeVuln({
            id: 'GHSA-1',
            severity: [{ type: 'CVSS_V3', score: '9.5' }],
            is_known_exploited: true,
            epss_score: 0.8,
          }),
          makeVuln({
            id: 'GHSA-2',
            severity: [{ type: 'CVSS_V3', score: '9.0' }],
            is_known_exploited: true,
            epss_score: 0.9,
          }),
        ]),
      ]);
      const inputs = makeInputs({
        severityThreshold: 'critical',
        failOnKev: true,
        epssThreshold: 0.5,
      });

      const result = checkFailureThresholds(response, inputs);

      expect(result.reasons).toContain('Found 2 vulnerabilities at or above critical severity');
      expect(result.reasons).toContain('Found 2 CISA Known Exploited vulnerabilities');
      expect(result.reasons).toContain('Found 2 vulnerabilities with EPSS score at or above 0.5');
    });
  });
});
