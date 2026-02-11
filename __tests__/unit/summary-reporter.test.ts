/**
 * Tests for summary reporter
 */

import * as core from '@actions/core';
import { generateSummary } from '../../src/reporter/summary-reporter';
import { ApiResponse } from '../../src/api/types';

jest.mock('@actions/core');

describe('Summary Reporter', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    const mockSummary = {
      addHeading: jest.fn().mockReturnThis(),
      addRaw: jest.fn().mockReturnThis(),
      addBreak: jest.fn().mockReturnThis(),
      addTable: jest.fn().mockReturnThis(),
      write: jest.fn().mockResolvedValue(undefined),
    };
    (core.summary as any) = mockSummary;
  });

  it('should show fix version remediation guidance when fix_version is present', async () => {
    const response: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
        results: [{
          ecosystem: 'npm',
          package: 'lodash',
          version: '4.17.20',
          affected: true,
          severity: 'HIGH',
          vulnerabilities: [{
            id: 'CVE-2021-23337',
            summary: 'Command injection in lodash',
            cvss_score: 7.2,
            fix_version: '4.17.21',
          }],
        }],
      },
    };

    await generateSummary(response, 'package.json');

    const addRawCalls = (core.summary.addRaw as jest.Mock).mock.calls.map(c => c[0]);
    expect(addRawCalls).toContainEqual(
      expect.stringContaining('Upgrade to `4.17.21`')
    );
  });

  it('should show ignored count message when vulns exist and some are ignored', async () => {
    const response: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
        results: [{
          ecosystem: 'npm',
          package: 'lodash',
          version: '4.17.20',
          affected: true,
          severity: 'HIGH',
          vulnerabilities: [
            {
              id: 'CVE-2021-23337',
              summary: 'Active vuln',
              cvss_score: 7.2,
            },
            {
              id: 'CVE-2020-28500',
              summary: 'Ignored vuln',
              cvss_score: 5.3,
              _ignored: true,
              _ignoreReason: 'Not exploitable',
            },
          ],
        }],
      },
    };

    await generateSummary(response, 'package.json');

    const addRawCalls = (core.summary.addRaw as jest.Mock).mock.calls.map(c => c[0]);
    expect(addRawCalls).toContainEqual(
      expect.stringContaining('1 ignored vulnerability not shown above')
    );
  });

  it('should show ignored count message on clean scan when all vulns are ignored', async () => {
    const response: ApiResponse = {
      success: true,
      data: {
        summary: { total_packages: 1, vulnerable_packages: 1, safe_packages: 0 },
        results: [{
          ecosystem: 'npm',
          package: 'lodash',
          version: '4.17.20',
          affected: true,
          severity: 'HIGH',
          vulnerabilities: [
            {
              id: 'CVE-2021-23337',
              summary: 'Ignored vuln',
              cvss_score: 7.2,
              _ignored: true,
              _ignoreReason: 'Not exploitable',
            },
          ],
        }],
      },
    };

    await generateSummary(response, 'package.json');

    const addRawCalls = (core.summary.addRaw as jest.Mock).mock.calls.map(c => c[0]);
    expect(addRawCalls).toContainEqual(
      expect.stringContaining('1 vulnerability ignored')
    );
  });
});
