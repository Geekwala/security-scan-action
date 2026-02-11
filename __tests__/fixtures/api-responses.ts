/**
 * Mock API responses for testing
 */

import { ApiResponse } from '../../src/api/types';

/**
 * Successful scan - No vulnerabilities
 */
export const cleanScanResponse: ApiResponse = {
  success: true,
  data: {
    summary: {
      total_packages: 1,
      vulnerable_packages: 0,
      safe_packages: 1,
    },
    results: [
      {
        ecosystem: 'npm',
        package: 'express',
        version: '4.18.2',
        affected: false,
        vulnerabilities: [],
        severity: 'NONE',
      },
    ],
  },
};

/**
 * Successful scan - With vulnerabilities (lodash CVE-2021-23337)
 */
export const vulnerableScanResponse: ApiResponse = {
  success: true,
  data: {
    summary: {
      total_packages: 2,
      vulnerable_packages: 1,
      safe_packages: 1,
    },
    results: [
      {
        ecosystem: 'npm',
        package: 'lodash',
        version: '4.17.20',
        affected: true,
        severity: 'HIGH',
        vulnerabilities: [
          {
            id: 'CVE-2021-23337',
            summary: 'Command injection in lodash',
            details:
              'Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.',
            aliases: ['GHSA-35jh-r3h4-6jhm'],
            modified: '2021-03-15T12:00:00Z',
            published: '2021-02-15T12:00:00Z',
            references: [
              {
                type: 'WEB',
                url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337',
              },
              {
                type: 'ADVISORY',
                url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
              },
            ],
            severity: [
              {
                type: 'CVSS_V3',
                score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
              },
            ],
            epss_score: 0.00234,
            epss_percentile: 0.62345,
            is_known_exploited: false,
            kev_date_added: null,
            cvss_score: 7.2,
          },
        ],
      },
      {
        ecosystem: 'npm',
        package: 'express',
        version: '4.18.2',
        affected: false,
        vulnerabilities: [],
        severity: 'NONE',
      },
    ],
  },
};

/**
 * Successful scan - Critical vulnerability
 */
export const criticalVulnResponse: ApiResponse = {
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
        package: 'log4js',
        version: '6.3.0',
        affected: true,
        severity: 'CRITICAL',
        vulnerabilities: [
          {
            id: 'CVE-2021-44228',
            summary: 'Remote code execution in Log4j',
            details: 'Critical RCE vulnerability in Log4j library',
            aliases: ['GHSA-jfh8-c2jp-5v3q'],
            modified: '2021-12-15T12:00:00Z',
            published: '2021-12-10T12:00:00Z',
            references: [
              {
                type: 'WEB',
                url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
              },
            ],
            severity: [
              {
                type: 'CVSS_V3',
                score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
              },
            ],
            epss_score: 0.97534,
            epss_percentile: 0.99876,
            is_known_exploited: true,
            kev_date_added: '2021-12-10',
            cvss_score: 10.0,
          },
        ],
      },
    ],
  },
};

/**
 * Successful scan - Mixed severity levels
 */
export const mixedSeverityResponse: ApiResponse = {
  success: true,
  data: {
    summary: {
      total_packages: 7,
      vulnerable_packages: 7,
      safe_packages: 0,
    },
    results: [
      {
        ecosystem: 'npm',
        package: 'critical-pkg',
        version: '1.0.0',
        affected: true,
        severity: 'CRITICAL',
        vulnerabilities: [
          {
            id: 'CVE-2024-0001',
            summary: 'Critical vulnerability',
            cvss_score: 9.8,
            is_known_exploited: true,
            epss_score: 0.95,
          },
        ],
      },
      {
        ecosystem: 'npm',
        package: 'high-pkg-1',
        version: '2.0.0',
        affected: true,
        severity: 'HIGH',
        vulnerabilities: [
          {
            id: 'CVE-2024-0002',
            summary: 'High severity issue #1',
            cvss_score: 8.1,
          },
        ],
      },
      {
        ecosystem: 'npm',
        package: 'high-pkg-2',
        version: '2.1.0',
        affected: true,
        severity: 'HIGH',
        vulnerabilities: [
          {
            id: 'CVE-2024-0003',
            summary: 'High severity issue #2',
            cvss_score: 7.5,
          },
        ],
      },
      {
        ecosystem: 'npm',
        package: 'medium-pkg-1',
        version: '3.0.0',
        affected: true,
        severity: 'MEDIUM',
        vulnerabilities: [
          {
            id: 'CVE-2024-0004',
            summary: 'Medium severity issue #1',
            cvss_score: 5.3,
          },
        ],
      },
      {
        ecosystem: 'npm',
        package: 'medium-pkg-2',
        version: '3.1.0',
        affected: true,
        severity: 'MEDIUM',
        vulnerabilities: [
          {
            id: 'CVE-2024-0005',
            summary: 'Medium severity issue #2',
            cvss_score: 4.8,
          },
        ],
      },
      {
        ecosystem: 'npm',
        package: 'medium-pkg-3',
        version: '3.2.0',
        affected: true,
        severity: 'MEDIUM',
        vulnerabilities: [
          {
            id: 'CVE-2024-0006',
            summary: 'Medium severity issue #3',
            cvss_score: 5.9,
          },
        ],
      },
      {
        ecosystem: 'npm',
        package: 'low-pkg',
        version: '4.0.0',
        affected: true,
        severity: 'LOW',
        vulnerabilities: [
          {
            id: 'CVE-2024-0007',
            summary: 'Low severity issue',
            cvss_score: 2.1,
          },
        ],
      },
    ],
  },
};

/**
 * Successful scan - Large vulnerability list (50+ CVEs)
 */
export const largeVulnListResponse: ApiResponse = {
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
        package: 'vulnerable-package',
        version: '1.0.0',
        affected: true,
        severity: 'HIGH',
        vulnerabilities: Array.from({ length: 55 }, (_, i) => ({
          id: `CVE-2024-${String(i + 1).padStart(4, '0')}`,
          summary: `Vulnerability #${i + 1}`,
          cvss_score: 7.0 + (i % 3),
          epss_score: 0.001 * (i + 1),
        })),
      },
    ],
  },
};

/**
 * Successful scan - Missing enrichment data (null EPSS/KEV)
 */
export const missingEnrichmentResponse: ApiResponse = {
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
        package: 'no-enrichment-pkg',
        version: '1.0.0',
        affected: true,
        severity: 'MEDIUM',
        vulnerabilities: [
          {
            id: 'CVE-2024-9999',
            summary: 'Vulnerability without enrichment',
            epss_score: null,
            epss_percentile: null,
            is_known_exploited: false,
            kev_date_added: null,
            cvss_score: null,
          },
        ],
      },
    ],
  },
};

/**
 * Successful scan - Unknown severity level
 */
export const unknownSeverityResponse: ApiResponse = {
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
        package: 'unknown-severity-pkg',
        version: '1.0.0',
        affected: true,
        severity: 'UNKNOWN',
        vulnerabilities: [
          {
            id: 'CVE-2024-8888',
            summary: 'Vulnerability with unknown severity',
          },
        ],
      },
    ],
  },
};

/**
 * Successful scan - Special characters in package names
 */
export const specialCharsResponse: ApiResponse = {
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
        package: '@babel/core',
        version: '7.23.0',
        affected: false,
        vulnerabilities: [],
        severity: 'NONE',
      },
      {
        ecosystem: 'npm',
        package: '@types/node',
        version: '20.11.0',
        affected: false,
        vulnerabilities: [],
        severity: 'NONE',
      },
    ],
  },
};

/**
 * Successful scan - Multiple ecosystems
 */
export const multiEcosystemResponse: ApiResponse = {
  success: true,
  data: {
    summary: {
      total_packages: 3,
      vulnerable_packages: 1,
      safe_packages: 2,
    },
    results: [
      {
        ecosystem: 'npm',
        package: 'express',
        version: '4.18.2',
        affected: false,
        vulnerabilities: [],
        severity: 'NONE',
      },
      {
        ecosystem: 'PyPI',
        package: 'requests',
        version: '2.31.0',
        affected: true,
        severity: 'MEDIUM',
        vulnerabilities: [
          {
            id: 'CVE-2024-1111',
            summary: 'Python requests vulnerability',
            cvss_score: 5.5,
          },
        ],
      },
      {
        ecosystem: 'Maven',
        package: 'org.springframework:spring-core',
        version: '5.3.20',
        affected: false,
        vulnerabilities: [],
        severity: 'NONE',
      },
    ],
  },
};

/**
 * Error: Authentication Failed (401)
 */
export const authErrorResponse = {
  success: false,
  error: 'Unauthorized',
  type: 'auth_error',
};

/**
 * Error: Validation Failed (422)
 */
export const validationErrorResponse = {
  success: false,
  error: 'Unsupported file type',
  type: 'validation_error',
};

/**
 * Error: Rate Limit (429)
 */
export const rateLimitErrorResponse = {
  success: false,
  error: 'Rate limit exceeded',
  type: 'rate_limit_error',
};

/**
 * Error: Server Error (500)
 */
export const serverErrorResponse = {
  success: false,
  error: 'Internal server error',
  type: 'server_error',
};
