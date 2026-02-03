/**
 * Input validation for GitHub Action inputs
 */

import * as core from '@actions/core';
import { ActionInputs } from '../api/types';

export class InputValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InputValidationError';
  }
}

/**
 * Parse and validate GitHub Action inputs
 */
export function validateInputs(): ActionInputs {
  // Required inputs
  const apiToken = core.getInput('api-token', { required: true });
  if (!apiToken || apiToken.trim().length === 0) {
    throw new InputValidationError('api-token is required');
  }

  // Optional inputs with defaults
  const filePath = core.getInput('file-path') || undefined;

  const failOnCritical = parseBoolean(
    core.getInput('fail-on-critical') || 'true',
    'fail-on-critical'
  );

  const failOnHigh = parseBoolean(core.getInput('fail-on-high') || 'false', 'fail-on-high');

  const apiBaseUrl = core.getInput('api-base-url') || 'https://geekwala.com';
  if (!isValidUrl(apiBaseUrl)) {
    throw new InputValidationError(`Invalid api-base-url: ${apiBaseUrl}`);
  }

  const retryAttempts = parsePositiveInteger(
    core.getInput('retry-attempts') || '3',
    'retry-attempts'
  );

  if (retryAttempts < 1 || retryAttempts > 10) {
    throw new InputValidationError('retry-attempts must be between 1 and 10');
  }

  const timeoutSeconds = parsePositiveInteger(
    core.getInput('timeout-seconds') || '300',
    'timeout-seconds'
  );

  if (timeoutSeconds < 10 || timeoutSeconds > 600) {
    throw new InputValidationError('timeout-seconds must be between 10 and 600');
  }

  return {
    apiToken,
    filePath,
    failOnCritical,
    failOnHigh,
    apiBaseUrl,
    retryAttempts,
    timeoutSeconds,
  };
}

/**
 * Parse boolean input
 */
function parseBoolean(value: string, inputName: string): boolean {
  const normalized = value.toLowerCase().trim();

  if (normalized === 'true' || normalized === '1' || normalized === 'yes') {
    return true;
  }

  if (normalized === 'false' || normalized === '0' || normalized === 'no') {
    return false;
  }

  throw new InputValidationError(
    `Invalid boolean value for ${inputName}: ${value}. Use true/false.`
  );
}

/**
 * Parse positive integer input
 */
function parsePositiveInteger(value: string, inputName: string): number {
  const parsed = parseInt(value, 10);

  if (isNaN(parsed) || parsed < 1) {
    throw new InputValidationError(`Invalid positive integer for ${inputName}: ${value}`);
  }

  return parsed;
}

/**
 * Validate URL format
 */
function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}
