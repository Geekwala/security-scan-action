/**
 * Tests for input validation
 */

import * as core from '@actions/core';
import { validateInputs, InputValidationError } from '../../src/validators/input-validator';

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
});
