/**
 * Tests for input validation
 */

import * as core from '@actions/core';
import * as path from 'path';
import { validateInputs, InputValidationError } from '../../src/validators/input-validator';

const WORKSPACE = process.env.GITHUB_WORKSPACE || '/tmp/test-workspace';

// Mock @actions/core
jest.mock('@actions/core');

describe('Input Validation', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should validate valid inputs', () => {
    (core.getInput as jest.Mock).mockImplementation((name: string) => {
      const inputs: Record<string, string> = {
        'api-token': 'test-token-123',
        'fail-on-critical': 'true',
        'fail-on-high': 'false',
        'api-base-url': 'https://geekwala.com',
        'retry-attempts': '3',
        'timeout-seconds': '300',
      };
      return inputs[name] || '';
    });

    const inputs = validateInputs();

    expect(inputs.apiToken).toBe('test-token-123');
    expect(inputs.failOnCritical).toBe(true);
    expect(inputs.failOnHigh).toBe(false);
    expect(inputs.severityThreshold).toBe('critical'); // derived from failOnCritical=true
    expect(inputs.failOnKev).toBe(false);
    expect(inputs.epssThreshold).toBeUndefined();
    expect(inputs.onlyFixed).toBe(false);
    expect(inputs.outputFormat).toEqual(['summary']);
    expect(inputs.apiBaseUrl).toBe('https://geekwala.com');
    expect(inputs.retryAttempts).toBe(3);
    expect(inputs.timeoutSeconds).toBe(300);
  });

  it('should require api-token', () => {
    (core.getInput as jest.Mock).mockImplementation((name: string) => {
      if (name === 'api-token') return '';
      return 'default';
    });

    expect(() => validateInputs()).toThrow(InputValidationError);
  });

  it('should validate boolean inputs', () => {
    (core.getInput as jest.Mock).mockImplementation((name: string) => {
      const inputs: Record<string, string> = {
        'api-token': 'test-token',
        'fail-on-critical': '1',
        'fail-on-high': 'yes',
      };
      return inputs[name] || '';
    });

    const inputs = validateInputs();

    expect(inputs.failOnCritical).toBe(true);
    expect(inputs.failOnHigh).toBe(true);
  });

  it('should reject invalid retry attempts', () => {
    (core.getInput as jest.Mock).mockImplementation((name: string) => {
      if (name === 'api-token') return 'test-token';
      if (name === 'retry-attempts') return '20'; // Too high
      return '';
    });

    expect(() => validateInputs()).toThrow('retry-attempts must be between 1 and 10');
  });

  it('should reject invalid timeout', () => {
    (core.getInput as jest.Mock).mockImplementation((name: string) => {
      if (name === 'api-token') return 'test-token';
      if (name === 'timeout-seconds') return '1000'; // Too high
      return '';
    });

    expect(() => validateInputs()).toThrow('timeout-seconds must be between 10 and 600');
  });

  it('should reject invalid URL', () => {
    (core.getInput as jest.Mock).mockImplementation((name: string) => {
      if (name === 'api-token') return 'test-token';
      if (name === 'api-base-url') return 'not-a-url';
      return '';
    });

    expect(() => validateInputs()).toThrow('Invalid api-base-url');
  });

  describe('severity-threshold', () => {
    it('should parse valid severity-threshold values', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'severity-threshold') return 'medium';
        return '';
      });

      const inputs = validateInputs();
      expect(inputs.severityThreshold).toBe('medium');
    });

    it('should reject invalid severity-threshold', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'severity-threshold') return 'extreme';
        return '';
      });

      expect(() => validateInputs()).toThrow('Invalid severity-threshold');
    });

    it('should derive from legacy fail-on-critical when severity-threshold not set', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'fail-on-critical') return 'true';
        if (name === 'fail-on-high') return 'false';
        return '';
      });

      expect(validateInputs().severityThreshold).toBe('critical');
    });

    it('should derive from legacy fail-on-high when severity-threshold not set', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'fail-on-critical') return 'false';
        if (name === 'fail-on-high') return 'true';
        return '';
      });

      expect(validateInputs().severityThreshold).toBe('high');
    });

    it('should default to none when no fail inputs are set', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'fail-on-critical') return 'false';
        if (name === 'fail-on-high') return 'false';
        return '';
      });

      expect(validateInputs().severityThreshold).toBe('none');
    });
  });

  describe('epss-threshold', () => {
    it('should parse valid epss-threshold', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'epss-threshold') return '0.5';
        return '';
      });

      expect(validateInputs().epssThreshold).toBe(0.5);
    });

    it('should reject invalid epss-threshold', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'epss-threshold') return '1.5';
        return '';
      });

      expect(() => validateInputs()).toThrow('Invalid epss-threshold');
    });
  });

  describe('output-format', () => {
    it('should parse comma-separated output formats', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'output-format') return 'summary,json,table';
        return '';
      });

      expect(validateInputs().outputFormat).toEqual(['summary', 'json', 'table']);
    });

    it('should reject invalid output format', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'output-format') return 'xml';
        return '';
      });

      expect(() => validateInputs()).toThrow('Invalid output-format');
    });

    it('should handle whitespace in comma-separated formats', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'output-format') return ' summary , json ';
        return '';
      });

      expect(validateInputs().outputFormat).toEqual(['summary', 'json']);
    });

    it('should default to summary when empty', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        return '';
      });

      expect(validateInputs().outputFormat).toEqual(['summary']);
    });
  });

  describe('file-path', () => {
    it('should return undefined when file-path is empty', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        return '';
      });

      expect(validateInputs().filePath).toBeUndefined();
    });

    it('should return resolved file-path when specified', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'file-path') return 'package-lock.json';
        return '';
      });

      expect(validateInputs().filePath).toBe(path.resolve(WORKSPACE, 'package-lock.json'));
    });

    it('should reject file-path path traversal', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'file-path') return '../../etc/passwd';
        return '';
      });

      expect(() => validateInputs()).toThrow('must be within the workspace directory');
    });
  });

  describe('sarif-file', () => {
    it('should return undefined when sarif-file is empty', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        return '';
      });

      expect(validateInputs().sarifFile).toBeUndefined();
    });

    it('should return sarif-file when specified', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'sarif-file') return 'results.sarif';
        return '';
      });

      expect(validateInputs().sarifFile).toBe(path.resolve(WORKSPACE, 'results.sarif'));
    });
  });

  describe('ignore-file', () => {
    it('should default to .geekwala-ignore.yml', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'ignore-file') return '.geekwala-ignore.yml';
        return '';
      });

      expect(validateInputs().ignoreFile).toBe(path.resolve(WORKSPACE, '.geekwala-ignore.yml'));
    });

    it('should return undefined when explicitly set to empty string', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'ignore-file') return '';
        return '';
      });

      expect(validateInputs().ignoreFile).toBeUndefined();
    });
  });

  describe('json-file', () => {
    it('should return undefined when json-file is empty', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        return '';
      });

      expect(validateInputs().jsonFile).toBeUndefined();
    });

    it('should return json-file when specified', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'json-file') return 'report.json';
        return '';
      });

      expect(validateInputs().jsonFile).toBe(path.resolve(WORKSPACE, 'report.json'));
    });
  });

  describe('path traversal protection', () => {
    it('should reject sarif-file path traversal', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'sarif-file') return '../../etc/passwd';
        return '';
      });

      expect(() => validateInputs()).toThrow('must be within the workspace directory');
    });

    it('should reject json-file path traversal', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'json-file') return '../../../secret.json';
        return '';
      });

      expect(() => validateInputs()).toThrow('must be within the workspace directory');
    });

    it('should reject ignore-file path traversal', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'ignore-file') return '../../etc/shadow';
        return '';
      });

      expect(() => validateInputs()).toThrow('must be within the workspace directory');
    });

    it('should allow subdirectory paths', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'sarif-file') return 'reports/results.sarif';
        return '';
      });

      expect(validateInputs().sarifFile).toBe(path.resolve(WORKSPACE, 'reports/results.sarif'));
    });
  });

  describe('fail-on-kev', () => {
    it('should default to false', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        return '';
      });

      expect(validateInputs().failOnKev).toBe(false);
    });

    it('should parse true', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'fail-on-kev') return 'true';
        return '';
      });

      expect(validateInputs().failOnKev).toBe(true);
    });
  });

  describe('only-fixed', () => {
    it('should default to false', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        return '';
      });

      expect(validateInputs().onlyFixed).toBe(false);
    });

    it('should parse true', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'only-fixed') return 'true';
        return '';
      });

      expect(validateInputs().onlyFixed).toBe(true);
    });
  });

  describe('boolean edge cases', () => {
    it('should reject invalid boolean value like "maybe"', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'fail-on-kev') return 'maybe';
        return '';
      });

      expect(() => validateInputs()).toThrow('Invalid boolean value for fail-on-kev');
    });

    it('should accept "0" as false', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'fail-on-kev') return '0';
        return '';
      });

      expect(validateInputs().failOnKev).toBe(false);
    });

    it('should accept "no" as false', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'only-fixed') return 'no';
        return '';
      });

      expect(validateInputs().onlyFixed).toBe(false);
    });
  });

  describe('retry-attempts boundaries', () => {
    it('should accept minimum (1)', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'retry-attempts') return '1';
        return '';
      });

      expect(validateInputs().retryAttempts).toBe(1);
    });

    it('should accept maximum (10)', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'retry-attempts') return '10';
        return '';
      });

      expect(validateInputs().retryAttempts).toBe(10);
    });

    it('should reject 0', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'retry-attempts') return '0';
        return '';
      });

      expect(() => validateInputs()).toThrow('Invalid positive integer');
    });

    it('should reject 11', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'retry-attempts') return '11';
        return '';
      });

      expect(() => validateInputs()).toThrow('retry-attempts must be between 1 and 10');
    });
  });

  describe('timeout-seconds boundaries', () => {
    it('should accept minimum (10)', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'timeout-seconds') return '10';
        return '';
      });

      expect(validateInputs().timeoutSeconds).toBe(10);
    });

    it('should accept maximum (600)', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'timeout-seconds') return '600';
        return '';
      });

      expect(validateInputs().timeoutSeconds).toBe(600);
    });

    it('should reject 9', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'timeout-seconds') return '9';
        return '';
      });

      expect(() => validateInputs()).toThrow('timeout-seconds must be between 10 and 600');
    });

    it('should reject 601', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'timeout-seconds') return '601';
        return '';
      });

      expect(() => validateInputs()).toThrow('timeout-seconds must be between 10 and 600');
    });
  });

  describe('epss-threshold edge cases', () => {
    it('should reject negative number', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'epss-threshold') return '-0.1';
        return '';
      });

      expect(() => validateInputs()).toThrow('Invalid epss-threshold');
    });

    it('should reject non-numeric string', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'epss-threshold') return 'abc';
        return '';
      });

      expect(() => validateInputs()).toThrow('Invalid epss-threshold');
    });

    it('should accept 0.0', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'epss-threshold') return '0.0';
        return '';
      });

      expect(validateInputs().epssThreshold).toBe(0.0);
    });

    it('should accept 1.0', () => {
      (core.getInput as jest.Mock).mockImplementation((name: string) => {
        if (name === 'api-token') return 'test-token';
        if (name === 'epss-threshold') return '1.0';
        return '';
      });

      expect(validateInputs().epssThreshold).toBe(1.0);
    });
  });
});
