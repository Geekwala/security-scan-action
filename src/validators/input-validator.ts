/**
 * Input validation for GitHub Action inputs
 */

import * as core from '@actions/core';
import * as path from 'path';
import { ActionInputs, SeverityThreshold } from '../api/types';

export class InputValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InputValidationError';
  }
}

const VALID_SEVERITY_THRESHOLDS: SeverityThreshold[] = [
  'none',
  'low',
  'medium',
  'high',
  'critical',
];

/**
 * Parse and validate GitHub Action inputs
 */
export function validateInputs(): ActionInputs {
  // Required inputs
  const apiToken = core.getInput('api-token', { required: true });
  if (apiToken) {
    core.setSecret(apiToken);
  }
  if (!apiToken || apiToken.trim().length === 0) {
    throw new InputValidationError('api-token is required');
  }

  // Optional inputs with defaults
  const filePathRaw = core.getInput('file-path') || undefined;
  const filePath = filePathRaw ? validateFilePath(filePathRaw, 'file-path') : undefined;

  const failOnCritical = parseBoolean(
    core.getInput('fail-on-critical') || 'true',
    'fail-on-critical'
  );

  const failOnHigh = parseBoolean(core.getInput('fail-on-high') || 'false', 'fail-on-high');

  // New gate inputs
  const severityThresholdRaw = core.getInput('severity-threshold') || '';
  const severityThreshold = parseSeverityThreshold(
    severityThresholdRaw,
    failOnCritical,
    failOnHigh
  );

  const failOnKev = parseBoolean(core.getInput('fail-on-kev') || 'false', 'fail-on-kev');

  const epssThresholdRaw = core.getInput('epss-threshold') || '';
  const epssThreshold = epssThresholdRaw ? parseEpssThreshold(epssThresholdRaw) : undefined;

  const onlyFixed = parseBoolean(core.getInput('only-fixed') || 'false', 'only-fixed');

  // SARIF
  const sarifFileRaw = core.getInput('sarif-file') || undefined;
  const sarifFile = sarifFileRaw ? validateFilePath(sarifFileRaw, 'sarif-file') : undefined;

  // Ignore file
  const ignoreFileRaw = core.getInput('ignore-file');
  const ignoreFilePath = ignoreFileRaw === '' ? undefined : ignoreFileRaw || '.geekwala-ignore.yml';
  const ignoreFile = ignoreFilePath ? validateFilePath(ignoreFilePath, 'ignore-file') : undefined;

  // Output format
  const outputFormatRaw = core.getInput('output-format') || 'summary';
  const outputFormat = outputFormatRaw
    .split(',')
    .map(f => f.trim())
    .filter(Boolean);
  for (const fmt of outputFormat) {
    if (!['summary', 'json', 'table'].includes(fmt)) {
      throw new InputValidationError(
        `Invalid output-format: ${fmt}. Valid values: summary, json, table`
      );
    }
  }

  const jsonFileRaw = core.getInput('json-file') || undefined;
  const jsonFile = jsonFileRaw ? validateFilePath(jsonFileRaw, 'json-file') : undefined;

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
    severityThreshold,
    failOnKev,
    epssThreshold,
    onlyFixed,
    sarifFile,
    ignoreFile,
    outputFormat,
    jsonFile,
    apiBaseUrl,
    retryAttempts,
    timeoutSeconds,
  };
}

/**
 * Parse severity threshold, falling back to legacy inputs if not set
 */
function parseSeverityThreshold(
  raw: string,
  failOnCritical: boolean,
  failOnHigh: boolean
): SeverityThreshold {
  if (raw) {
    const normalized = raw.toLowerCase().trim() as SeverityThreshold;
    if (!VALID_SEVERITY_THRESHOLDS.includes(normalized)) {
      throw new InputValidationError(
        `Invalid severity-threshold: ${raw}. Valid values: ${VALID_SEVERITY_THRESHOLDS.join(', ')}`
      );
    }
    return normalized;
  }

  // Legacy: derive from fail-on-critical / fail-on-high
  if (failOnHigh) return 'high';
  if (failOnCritical) return 'critical';
  return 'none';
}

/**
 * Parse EPSS threshold (0.0 to 1.0)
 */
function parseEpssThreshold(raw: string): number {
  const parsed = parseFloat(raw);
  if (isNaN(parsed) || parsed < 0 || parsed > 1) {
    throw new InputValidationError(
      `Invalid epss-threshold: ${raw}. Must be a number between 0.0 and 1.0`
    );
  }
  return parsed;
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
 * Validate that a file path stays within the workspace directory (defense-in-depth against path traversal)
 */
export function validateFilePath(filePath: string, inputName: string): string {
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const resolved = path.resolve(workspace, filePath);
  if (
    !resolved.startsWith(path.resolve(workspace) + path.sep) &&
    resolved !== path.resolve(workspace)
  ) {
    throw new InputValidationError(
      `${inputName} must be within the workspace directory. Got: ${filePath}`
    );
  }
  return resolved;
}

/**
 * Validate URL format
 */
function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}
