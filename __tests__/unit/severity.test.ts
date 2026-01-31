/**
 * Tests for severity classification
 */

import {
  normalizeSeverity,
  getSeverityFromCvss,
  getVulnerabilitySeverity,
  countBySeverity,
} from '../../src/utils/severity';
import { Vulnerability } from '../../src/api/types';

describe('Severity Classification', () => {
  describe('normalizeSeverity', () => {
    it('should normalize severity strings', () => {
      expect(normalizeSeverity('critical')).toBe('CRITICAL');
      expect(normalizeSeverity('CRITICAL')).toBe('CRITICAL');
      expect(normalizeSeverity('high')).toBe('HIGH');
      expect(normalizeSeverity('medium')).toBe('MEDIUM');
      expect(normalizeSeverity('moderate')).toBe('MEDIUM');
      expect(normalizeSeverity('low')).toBe('LOW');
      expect(normalizeSeverity('unknown')).toBe('UNKNOWN');
    });
  });

  describe('getSeverityFromCvss', () => {
    it('should classify CVSS scores correctly', () => {
      expect(getSeverityFromCvss(10.0)).toBe('CRITICAL');
      expect(getSeverityFromCvss(9.0)).toBe('CRITICAL');
      expect(getSeverityFromCvss(8.5)).toBe('HIGH');
      expect(getSeverityFromCvss(7.0)).toBe('HIGH');
      expect(getSeverityFromCvss(5.0)).toBe('MEDIUM');
      expect(getSeverityFromCvss(4.0)).toBe('MEDIUM');
      expect(getSeverityFromCvss(2.0)).toBe('LOW');
      expect(getSeverityFromCvss(0.1)).toBe('LOW');
      expect(getSeverityFromCvss(0)).toBe('UNKNOWN');
    });
  });

  describe('getVulnerabilitySeverity', () => {
    it('should use CVSS score if available', () => {
      const vuln: Vulnerability = {
        id: 'CVE-2021-1234',
        cvss_score: 9.8,
      };

      expect(getVulnerabilitySeverity(vuln)).toBe('CRITICAL');
    });

    it('should parse severity array if CVSS score not available', () => {
      const vuln: Vulnerability = {
        id: 'CVE-2021-1234',
        severity: [{ type: 'CVSS_V3', score: '7.5' }],
      };

      expect(getVulnerabilitySeverity(vuln)).toBe('HIGH');
    });

    it('should return UNKNOWN if no severity data', () => {
      const vuln: Vulnerability = {
        id: 'CVE-2021-1234',
      };

      expect(getVulnerabilitySeverity(vuln)).toBe('UNKNOWN');
    });
  });

  describe('countBySeverity', () => {
    it('should count vulnerabilities by severity', () => {
      const vulnerabilities: Vulnerability[] = [
        { id: 'CVE-1', cvss_score: 9.8 }, // CRITICAL
        { id: 'CVE-2', cvss_score: 8.5 }, // HIGH
        { id: 'CVE-3', cvss_score: 7.0 }, // HIGH
        { id: 'CVE-4', cvss_score: 5.0 }, // MEDIUM
        { id: 'CVE-5', cvss_score: 2.0 }, // LOW
      ];

      const counts = countBySeverity(vulnerabilities);

      expect(counts.critical).toBe(1);
      expect(counts.high).toBe(2);
      expect(counts.medium).toBe(1);
      expect(counts.low).toBe(1);
      expect(counts.unknown).toBe(0);
    });

    it('should handle empty array', () => {
      const counts = countBySeverity([]);

      expect(counts.critical).toBe(0);
      expect(counts.high).toBe(0);
      expect(counts.medium).toBe(0);
      expect(counts.low).toBe(0);
      expect(counts.unknown).toBe(0);
    });
  });
});
