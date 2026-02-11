/**
 * Integration tests for main entry point workflow
 */

import * as core from '@actions/core';
import * as fs from 'fs/promises';
import * as path from 'path';
import { MockGeekWalaApi } from '../helpers/mock-api';
import * as fixtures from '../fixtures';

// Mock @actions/core
jest.mock('@actions/core');

import { validateInputs } from '../../src/validators/input-validator';
import { detectDependencyFile, validateFile, readFile } from '../../src/detector/file-detector';
import { GeekWalaClient } from '../../src/api/client';
import { setActionOutputs, checkFailureThresholds } from '../../src/reporter/output-manager';
import { generateSummary } from '../../src/reporter/summary-reporter';

jest.setTimeout(15000);

describe('Main Entry Point Integration', () => {
  let mockApi: MockGeekWalaApi;
  const TEST_WORKSPACE = '/tmp/test-workspace-main';

  beforeEach(async () => {
    mockApi = new MockGeekWalaApi('https://geekwala.com');
    jest.clearAllMocks();

    await fs.mkdir(TEST_WORKSPACE, { recursive: true });

    (core.getInput as jest.Mock).mockImplementation((name: string) => {
      const inputs: Record<string, string> = {
        'api-token': 'test-api-token-12345',
        'api-base-url': 'https://geekwala.com',
        'fail-on-critical': 'true',
        'fail-on-high': 'false',
        'retry-attempts': '3',
        'timeout-seconds': '300',
      };
      return inputs[name] || '';
    });

    (core.setOutput as jest.Mock).mockImplementation(() => {});
    (core.setFailed as jest.Mock).mockImplementation(() => {});
    (core.info as jest.Mock).mockImplementation(() => {});
    (core.error as jest.Mock).mockImplementation(() => {});
    (core.debug as jest.Mock).mockImplementation(() => {});

    const mockSummary = {
      addHeading: jest.fn().mockReturnThis(),
      addRaw: jest.fn().mockReturnThis(),
      addBreak: jest.fn().mockReturnThis(),
      addTable: jest.fn().mockReturnThis(),
      write: jest.fn().mockResolvedValue(undefined),
    };
    (core.summary as any) = mockSummary;
  });

  afterEach(async () => {
    mockApi.cleanup();

    try {
      await fs.rm(TEST_WORKSPACE, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('Full Workflow - Clean Scan', () => {
    it('should complete full flow for clean scan successfully', async () => {
      const packageJsonPath = path.join(TEST_WORKSPACE, 'package.json');
      await fs.writeFile(packageJsonPath, fixtures.cleanPackageJson);

      mockApi.mockSuccessfulScan(fixtures.cleanScanResponse);

      const inputs = validateInputs();
      const filePath = await detectDependencyFile(TEST_WORKSPACE);
      const content = await readFile(filePath);

      const client = new GeekWalaClient(
        inputs.apiToken,
        inputs.apiBaseUrl,
        inputs.timeoutSeconds,
        inputs.retryAttempts
      );

      const response = await client.runScan('package.json', content);

      setActionOutputs(response);
      await generateSummary(response, 'package.json');
      const { shouldFail, status } = checkFailureThresholds(response, inputs);

      expect(core.setOutput).toHaveBeenCalledWith('total-packages', '1');
      expect(core.setOutput).toHaveBeenCalledWith('vulnerable-packages', '0');
      expect(shouldFail).toBe(false);
      expect(status).toBe('PASS');
    });
  });

  describe('Full Workflow - Vulnerable Scan', () => {
    it('should fail workflow on critical vulnerabilities when fail-on-critical=true', async () => {
      const packageJsonPath = path.join(TEST_WORKSPACE, 'package.json');
      await fs.writeFile(packageJsonPath, fixtures.vulnerablePackageJson);

      mockApi.mockSuccessfulScan(fixtures.criticalVulnResponse);

      const inputs = validateInputs();
      const filePath = await detectDependencyFile(TEST_WORKSPACE);
      const content = await readFile(filePath);

      const client = new GeekWalaClient(
        inputs.apiToken,
        inputs.apiBaseUrl,
        inputs.timeoutSeconds,
        inputs.retryAttempts
      );

      const response = await client.runScan('package.json', content);

      setActionOutputs(response);
      const { shouldFail, reason, status } = checkFailureThresholds(response, inputs);

      expect(shouldFail).toBe(true);
      expect(status).toBe('FAIL');
      expect(reason).toContain('critical');
      expect(core.setOutput).toHaveBeenCalledWith('critical-count', '1');
    });

    it('should pass workflow on high vulnerabilities when fail-on-high=false', async () => {
      const packageJsonPath = path.join(TEST_WORKSPACE, 'package.json');
      await fs.writeFile(packageJsonPath, fixtures.vulnerablePackageJson);

      mockApi.mockSuccessfulScan(fixtures.vulnerableScanResponse);

      const inputs = validateInputs();
      const filePath = await detectDependencyFile(TEST_WORKSPACE);
      const content = await readFile(filePath);

      const client = new GeekWalaClient(
        inputs.apiToken,
        inputs.apiBaseUrl,
        inputs.timeoutSeconds,
        inputs.retryAttempts
      );

      const response = await client.runScan('package.json', content);

      setActionOutputs(response);
      const { shouldFail, status } = checkFailureThresholds(response, inputs);

      expect(shouldFail).toBe(false);
      expect(status).toBe('PASS');
      expect(core.setOutput).toHaveBeenCalledWith('high-count', '1');
    });

    it('should fail workflow on high vulnerabilities when fail-on-high=true', async () => {
      const packageJsonPath = path.join(TEST_WORKSPACE, 'package.json');
      await fs.writeFile(packageJsonPath, fixtures.vulnerablePackageJson);

      mockApi.mockSuccessfulScan(fixtures.vulnerableScanResponse);

      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        const inputs: Record<string, string> = {
          'api-token': 'test-api-token-12345',
          'api-base-url': 'https://geekwala.com',
          'fail-on-critical': 'true',
          'fail-on-high': 'true',
          'retry-attempts': '3',
          'timeout-seconds': '300',
        };
        return inputs[name] || '';
      });

      const inputs = validateInputs();
      const filePath = await detectDependencyFile(TEST_WORKSPACE);
      const content = await readFile(filePath);

      const client = new GeekWalaClient(
        inputs.apiToken,
        inputs.apiBaseUrl,
        inputs.timeoutSeconds,
        inputs.retryAttempts
      );

      const response = await client.runScan('package.json', content);

      setActionOutputs(response);
      const { shouldFail, reason, status } = checkFailureThresholds(response, inputs);

      expect(shouldFail).toBe(true);
      expect(status).toBe('FAIL');
      expect(reason).toContain('high');
    });
  });

  describe('File Detection', () => {
    it('should auto-detect package.json when no lockfile exists', async () => {
      const packageJsonPath = path.join(TEST_WORKSPACE, 'package.json');
      await fs.writeFile(packageJsonPath, fixtures.cleanPackageJson);

      const detectedPath = await detectDependencyFile(TEST_WORKSPACE);

      expect(path.basename(detectedPath)).toBe('package.json');
    });

    it('should prefer lockfile over manifest when both exist', async () => {
      const packageJsonPath = path.join(TEST_WORKSPACE, 'package.json');
      const lockfilePath = path.join(TEST_WORKSPACE, 'package-lock.json');

      await fs.writeFile(packageJsonPath, fixtures.cleanPackageJson);
      await fs.writeFile(lockfilePath, fixtures.cleanPackageLock);

      const detectedPath = await detectDependencyFile(TEST_WORKSPACE);

      expect(path.basename(detectedPath)).toBe('package-lock.json');
    });

    it('should validate specified file path correctly', async () => {
      const packageJsonPath = path.join(TEST_WORKSPACE, 'package.json');
      await fs.writeFile(packageJsonPath, fixtures.cleanPackageJson);

      await expect(validateFile(packageJsonPath)).resolves.toBeUndefined();
    });

    it('should throw error for unsupported file type', async () => {
      const unsupportedPath = path.join(TEST_WORKSPACE, 'README.md');
      await fs.writeFile(unsupportedPath, '# Test');

      await expect(validateFile(unsupportedPath)).rejects.toThrow(/Unsupported file/);
    });
  });

  describe('Error Handling', () => {
    it('should handle API authentication errors gracefully', async () => {
      const packageJsonPath = path.join(TEST_WORKSPACE, 'package.json');
      await fs.writeFile(packageJsonPath, fixtures.cleanPackageJson);

      mockApi.mockAuthError();

      const inputs = validateInputs();
      const filePath = await detectDependencyFile(TEST_WORKSPACE);
      const content = await readFile(filePath);

      const client = new GeekWalaClient(
        'bad-token',
        inputs.apiBaseUrl,
        inputs.timeoutSeconds,
        inputs.retryAttempts
      );

      await expect(client.runScan('package.json', content)).rejects.toThrow(
        /Authentication failed/
      );
    });

    it('should handle file not found errors', async () => {
      await expect(detectDependencyFile(TEST_WORKSPACE)).rejects.toThrow(
        /No supported dependency files found/
      );
    });

    it('should handle file size validation errors', async () => {
      const packageJsonPath = path.join(TEST_WORKSPACE, 'package.json');
      await fs.writeFile(packageJsonPath, fixtures.largeFileContent);

      await expect(readFile(packageJsonPath)).rejects.toThrow(
        /exceeds maximum allowed size/
      );
    });
  });

  describe('Input Validation', () => {
    it('should validate inputs successfully with defaults', () => {
      const inputs = validateInputs();

      expect(inputs.apiToken).toBe('test-api-token-12345');
      expect(inputs.apiBaseUrl).toBe('https://geekwala.com');
      expect(inputs.failOnCritical).toBe(true);
      expect(inputs.failOnHigh).toBe(false);
      expect(inputs.severityThreshold).toBe('critical');
      expect(inputs.retryAttempts).toBe(3);
      expect(inputs.timeoutSeconds).toBe(300);
    });

    it('should throw error for missing API token', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return '';
        return 'value';
      });

      expect(() => validateInputs()).toThrow(/api-token is required/);
    });

    it('should parse boolean inputs correctly', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        const inputs: Record<string, string> = {
          'api-token': 'test-token',
          'fail-on-critical': 'false',
          'fail-on-high': 'true',
          'retry-attempts': '5',
          'timeout-seconds': '120',
        };
        return inputs[name] || '';
      });

      const inputs = validateInputs();

      expect(inputs.failOnCritical).toBe(false);
      expect(inputs.failOnHigh).toBe(true);
      expect(inputs.retryAttempts).toBe(5);
      expect(inputs.timeoutSeconds).toBe(120);
    });
  });

  describe('Complete E2E Scenarios', () => {
    it('should handle mixed severity vulnerabilities correctly', async () => {
      const packageJsonPath = path.join(TEST_WORKSPACE, 'package.json');
      await fs.writeFile(packageJsonPath, '{}');

      mockApi.mockSuccessfulScan(fixtures.mixedSeverityResponse);

      const inputs = validateInputs();
      const filePath = await detectDependencyFile(TEST_WORKSPACE);
      const content = await readFile(filePath);

      const client = new GeekWalaClient(
        inputs.apiToken,
        inputs.apiBaseUrl,
        inputs.timeoutSeconds,
        inputs.retryAttempts
      );

      const response = await client.runScan('package.json', content);

      setActionOutputs(response);
      await generateSummary(response, 'package.json');

      expect(core.setOutput).toHaveBeenCalledWith('critical-count', '1');
      expect(core.setOutput).toHaveBeenCalledWith('high-count', '2');
      expect(core.setOutput).toHaveBeenCalledWith('medium-count', '3');
      expect(core.setOutput).toHaveBeenCalledWith('low-count', '1');
    });

    it('should handle large vulnerability lists', async () => {
      const packageJsonPath = path.join(TEST_WORKSPACE, 'package.json');
      await fs.writeFile(packageJsonPath, '{}');

      mockApi.mockSuccessfulScan(fixtures.largeVulnListResponse);

      const inputs = validateInputs();
      const filePath = await detectDependencyFile(TEST_WORKSPACE);
      const content = await readFile(filePath);

      const client = new GeekWalaClient(
        inputs.apiToken,
        inputs.apiBaseUrl,
        inputs.timeoutSeconds,
        inputs.retryAttempts
      );

      const response = await client.runScan('package.json', content);

      expect(response.success).toBe(true);
      expect(response.data?.results[0].vulnerabilities).toHaveLength(55);
    });
  });
});
