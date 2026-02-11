/**
 * Tests for ignore application logic
 */

import { applyIgnores } from '../../src/ignore/index';
import { IgnoreConfig } from '../../src/ignore/parser';
import { ScanResult } from '../../src/api/types';

describe('Apply Ignores', () => {
  const makeResults = (): ScanResult[] => [
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
          aliases: ['GHSA-35jh-r3h4-6jhm'],
          cvss_score: 7.2,
          epss_score: 0.00234,
          is_known_exploited: false,
        },
        {
          id: 'CVE-2020-28500',
          summary: 'ReDoS in lodash',
          cvss_score: 5.3,
        },
      ],
    },
  ];

  it('should mark matching vuln as ignored by CVE ID', () => {
    const config: IgnoreConfig = {
      ignore: [{ id: 'CVE-2021-23337', reason: 'Not exploitable' }],
    };

    const { results, ignoredCount } = applyIgnores(makeResults(), config);

    expect(ignoredCount).toBe(1);
    expect(results[0].vulnerabilities[0]._ignored).toBe(true);
    expect(results[0].vulnerabilities[0]._ignoreReason).toBe('Not exploitable');
    expect(results[0].vulnerabilities[1]._ignored).toBeUndefined();
  });

  it('should match by GHSA alias', () => {
    const config: IgnoreConfig = {
      ignore: [{ id: 'GHSA-35jh-r3h4-6jhm', reason: 'Alias match' }],
    };

    const { results, ignoredCount } = applyIgnores(makeResults(), config);

    expect(ignoredCount).toBe(1);
    expect(results[0].vulnerabilities[0]._ignored).toBe(true);
  });

  it('should be case-insensitive', () => {
    const config: IgnoreConfig = {
      ignore: [{ id: 'cve-2021-23337', reason: 'Lower case' }],
    };

    const { ignoredCount } = applyIgnores(makeResults(), config);
    expect(ignoredCount).toBe(1);
  });

  it('should filter expired entries', () => {
    const config: IgnoreConfig = {
      ignore: [
        { id: 'CVE-2021-23337', reason: 'Expired', expires: '2020-01-01' },
      ],
    };

    const { results, ignoredCount } = applyIgnores(makeResults(), config);

    expect(ignoredCount).toBe(0);
    expect(results[0].vulnerabilities[0]._ignored).toBeUndefined();
  });

  it('should return correct ignored count', () => {
    const config: IgnoreConfig = {
      ignore: [
        { id: 'CVE-2021-23337', reason: 'Reason 1' },
        { id: 'CVE-2020-28500', reason: 'Reason 2' },
      ],
    };

    const { ignoredCount } = applyIgnores(makeResults(), config);
    expect(ignoredCount).toBe(2);
  });

  it('should handle empty ignore config', () => {
    const config: IgnoreConfig = { ignore: [] };

    const { results, ignoredCount } = applyIgnores(makeResults(), config);

    expect(ignoredCount).toBe(0);
    expect(results[0].vulnerabilities[0]._ignored).toBeUndefined();
  });

  it('should use fallback reason "Ignored" when reason is empty string', () => {
    const config: IgnoreConfig = {
      ignore: [{ id: 'CVE-2021-23337', reason: '' }],
    };

    const { results, ignoredCount } = applyIgnores(makeResults(), config);

    expect(ignoredCount).toBe(1);
    expect(results[0].vulnerabilities[0]._ignored).toBe(true);
    expect(results[0].vulnerabilities[0]._ignoreReason).toBe('Ignored');
  });
});
