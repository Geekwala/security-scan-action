/**
 * Integration tests for GeekWalaClient with mocked HTTP responses
 */

import nock from 'nock';
import { GeekWalaClient, GeekWalaApiError } from '../../src/api/client';
import { MockGeekWalaApi } from '../helpers/mock-api';
import * as fixtures from '../fixtures';

jest.setTimeout(15000);

describe('GeekWalaClient Integration', () => {
  const TEST_TOKEN = 'test-api-token-12345';
  const TEST_BASE_URL = 'https://geekwala.com';

  // Clean up nock after each test to prevent interference
  afterEach(() => {
    nock.cleanAll();
  });

  describe('Successful Scans', () => {
    it('should return results for clean scan with no vulnerabilities', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockSuccessfulScan(fixtures.cleanScanResponse);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);
      const result = await client.runScan('package.json', fixtures.cleanPackageJson);

      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.summary.vulnerable_packages).toBe(0);
      expect(result.data?.summary.total_packages).toBe(1);
      expect(result.data?.summary.safe_packages).toBe(1);
      expect(result.data?.results).toHaveLength(1);
      expect(result.data?.results[0].affected).toBe(false);
      expect(mockApi.isDone()).toBe(true);
    });

    it('should return vulnerabilities for vulnerable scan', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockSuccessfulScan(fixtures.vulnerableScanResponse);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);
      const result = await client.runScan('package.json', fixtures.vulnerablePackageJson);

      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data?.summary.vulnerable_packages).toBe(1);
      expect(result.data?.summary.total_packages).toBe(2);
      expect(result.data?.results).toHaveLength(2);

      // Check vulnerable package details
      const vulnPackage = result.data?.results.find((r) => r.package === 'lodash');
      expect(vulnPackage).toBeDefined();
      expect(vulnPackage?.affected).toBe(true);
      expect(vulnPackage?.severity).toBe('HIGH');
      expect(vulnPackage?.vulnerabilities).toHaveLength(1);

      // Check vulnerability details
      const vuln = vulnPackage?.vulnerabilities[0];
      expect(vuln?.id).toBe('CVE-2021-23337');
      expect(vuln?.summary).toContain('Command injection');
      expect(vuln?.epss_score).toBe(0.00234);
      expect(vuln?.is_kev).toBe(false);
      expect(vuln?.cvss_score).toBe(7.2);
      expect(mockApi.isDone()).toBe(true);
    });

    it('should handle critical vulnerabilities correctly', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockSuccessfulScan(fixtures.criticalVulnResponse);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);
      const result = await client.runScan('package.json', '{}');

      expect(result.success).toBe(true);
      expect(result.data?.summary.vulnerable_packages).toBe(1);

      const vulnPackage = result.data?.results[0];
      expect(vulnPackage).toBeDefined();
      expect(vulnPackage?.severity).toBe('CRITICAL');
      expect(vulnPackage?.vulnerabilities[0].is_kev).toBe(true);
      expect(vulnPackage?.vulnerabilities[0].cvss_score).toBe(10.0);
      expect(vulnPackage?.vulnerabilities[0].epss_score).toBeGreaterThan(0.9);
    });

    it('should handle large vulnerability lists (50+ CVEs)', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockSuccessfulScan(fixtures.largeVulnListResponse);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);
      const result = await client.runScan('package.json', '{}');

      expect(result.success).toBe(true);
      expect(result.data?.results[0].vulnerabilities).toHaveLength(55);
    });

    it('should handle missing enrichment data (null EPSS/KEV)', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockSuccessfulScan(fixtures.missingEnrichmentResponse);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);
      const result = await client.runScan('package.json', '{}');

      expect(result.success).toBe(true);
      const vuln = result.data?.results[0].vulnerabilities[0];
      expect(vuln?.epss_score).toBeNull();
      expect(vuln?.epss_percentile).toBeNull();
      expect(vuln?.cvss_score).toBeNull();
      expect(vuln?.is_kev).toBe(false);
    });

    it('should handle unknown severity levels', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockSuccessfulScan(fixtures.unknownSeverityResponse);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);
      const result = await client.runScan('package.json', '{}');

      expect(result.success).toBe(true);
      expect(result.data?.results[0].severity).toBe('UNKNOWN');
    });

    it('should handle special characters in package names', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockSuccessfulScan(fixtures.specialCharsResponse);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);
      const result = await client.runScan('package.json', '{}');

      expect(result.success).toBe(true);
      expect(result.data?.results.some((r) => r.package === '@babel/core')).toBe(true);
      expect(result.data?.results.some((r) => r.package === '@types/node')).toBe(true);
    });

    it('should handle multiple ecosystems in one response', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockSuccessfulScan(fixtures.multiEcosystemResponse);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);
      const result = await client.runScan('package.json', '{}');

      expect(result.success).toBe(true);
      expect(result.data?.results.some((r) => r.ecosystem === 'npm')).toBe(true);
      expect(result.data?.results.some((r) => r.ecosystem === 'PyPI')).toBe(true);
      expect(result.data?.results.some((r) => r.ecosystem === 'Maven')).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should throw GeekWalaApiError on 401 authentication failure', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockAuthError();

      const client = new GeekWalaClient('bad-token', TEST_BASE_URL, 300, 3);

      try {
        await client.runScan('package.json', '{}');
        fail('Should have thrown GeekWalaApiError');
      } catch (error) {
        expect(error).toBeInstanceOf(GeekWalaApiError);
        expect((error as Error).message).toContain('Authentication failed');
        expect((error as Error).message).toContain('scan:write');
      }
    });

    it('should throw GeekWalaApiError on 422 validation error', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockValidationError('Unsupported file type');

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);

      try {
        await client.runScan('unknown.txt', '{}');
        fail('Should have thrown GeekWalaApiError');
      } catch (error) {
        expect(error).toBeInstanceOf(GeekWalaApiError);
        expect((error as Error).message).toContain('Unsupported file type');
      }
    });

    it('should throw GeekWalaApiError on 429 rate limit with retry-after header', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockRateLimit(120);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 1); // Only 1 attempt to avoid long test

      try {
        await client.runScan('package.json', '{}');
        fail('Should have thrown GeekWalaApiError');
      } catch (error) {
        expect(error).toBeInstanceOf(GeekWalaApiError);
        expect((error as Error).message).toContain('Rate limit exceeded');
        expect((error as Error).message).toContain('Wait 120 seconds');
      }
    });

    it('should retry on 500 server error and eventually fail', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      // Mock 3 consecutive server errors (max retries = 3)
      mockApi.mockServerError(500);
      mockApi.mockServerError(500);
      mockApi.mockServerError(500);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);

      try {
        await client.runScan('package.json', '{}');
        fail('Should have thrown GeekWalaApiError');
      } catch (error) {
        expect(error).toBeInstanceOf(GeekWalaApiError);
        expect((error as Error).message).toContain('temporarily unavailable');
      }
    });

    it('should retry on 500 and succeed when server recovers', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      // First two attempts fail with 500, third succeeds
      mockApi.mockServerError(500);
      mockApi.mockServerError(500);
      mockApi.mockSuccessfulScan(fixtures.cleanScanResponse);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);
      const result = await client.runScan('package.json', fixtures.cleanPackageJson);

      expect(result.success).toBe(true);
      expect(mockApi.isDone()).toBe(true);
    });

    it('should handle 502 Bad Gateway errors', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockServerError(502);
      mockApi.mockServerError(502);
      mockApi.mockServerError(502);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);

      try {
        await client.runScan('package.json', '{}');
        fail('Should have thrown GeekWalaApiError');
      } catch (error) {
        expect(error).toBeInstanceOf(GeekWalaApiError);
        expect((error as Error).message).toContain('temporarily unavailable');
        expect((error as Error).message).toContain('502');
      }
    });

    it('should handle 503 Service Unavailable errors', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockServerError(503);
      mockApi.mockServerError(503);
      mockApi.mockServerError(503);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);

      try {
        await client.runScan('package.json', '{}');
        fail('Should have thrown GeekWalaApiError');
      } catch (error) {
        expect(error).toBeInstanceOf(GeekWalaApiError);
        expect((error as Error).message).toContain('temporarily unavailable');
        expect((error as Error).message).toContain('503');
      }
    });

    it('should handle network errors gracefully', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockNetworkError();

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 1);

      try {
        await client.runScan('package.json', '{}');
        fail('Should have thrown GeekWalaApiError');
      } catch (error) {
        expect(error).toBeInstanceOf(GeekWalaApiError);
        expect((error as Error).message).toContain('Network error');
      }
    });
  });

  describe('File Size Validation', () => {
    it('should reject files exceeding 500KB', async () => {
      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);

      try {
        await client.runScan('package.json', fixtures.largeFileContent);
        fail('Should have thrown GeekWalaApiError');
      } catch (error) {
        expect(error).toBeInstanceOf(GeekWalaApiError);
        expect((error as Error).message).toContain('exceeds maximum allowed size');
        expect((error as Error).message).toContain('500KB');
      }
    });

    it('should accept files under 500KB', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockSuccessfulScan(fixtures.cleanScanResponse);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);
      const result = await client.runScan('package.json', fixtures.validLargeFileContent);

      expect(result.success).toBe(true);
    });

    it('should calculate file size correctly', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      // Test exact boundary (500KB)
      const exactLimit = 'x'.repeat(500 * 1024);
      mockApi.mockSuccessfulScan(fixtures.cleanScanResponse);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);
      const result = await client.runScan('package.json', exactLimit);
      expect(result.success).toBe(true);
    });

    it('should reject files just over 500KB', async () => {
      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);

      // 500KB + 1 byte
      const justOverLimit = 'x'.repeat(500 * 1024 + 1);

      await expect(client.runScan('package.json', justOverLimit)).rejects.toThrow(
        /exceeds maximum allowed size/
      );
    });
  });

  describe('HTTP Headers', () => {
    it('should send correct authorization header', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockSuccessfulScan(fixtures.cleanScanResponse);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);
      await client.runScan('package.json', '{}');

      expect(mockApi.isDone()).toBe(true);
    });

    it('should send correct content-type and accept headers', async () => {
      const mockApi = new MockGeekWalaApi(TEST_BASE_URL);
      mockApi.mockSuccessfulScan(fixtures.cleanScanResponse);

      const client = new GeekWalaClient(TEST_TOKEN, TEST_BASE_URL, 300, 3);
      await client.runScan('package.json', '{}');

      expect(mockApi.isDone()).toBe(true);
    });
  });
});
