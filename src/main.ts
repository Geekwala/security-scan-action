/**
 * GeekWala Security Scan GitHub Action
 * Main entry point
 */

import * as core from '@actions/core';
import * as path from 'path';
import { validateInputs } from './validators/input-validator';
import { detectDependencyFile, validateFile, readFile } from './detector/file-detector';
import { GeekWalaClient, GeekWalaApiError } from './api/client';
import { setActionOutputs, checkFailureThresholds } from './reporter/output-manager';
import { generateSummary } from './reporter/summary-reporter';

/**
 * Main action execution
 */
async function run(): Promise<void> {
  try {
    core.info('🛡️ GeekWala Security Scan starting...');

    // Step 1: Validate inputs
    core.info('Validating inputs...');
    const inputs = validateInputs();

    // Step 2: Detect or validate file
    let filePath: string;
    if (inputs.filePath) {
      core.info(`Using specified file: ${inputs.filePath}`);
      await validateFile(inputs.filePath);
      filePath = inputs.filePath;
    } else {
      core.info('Auto-detecting dependency file...');
      filePath = await detectDependencyFile(process.env.GITHUB_WORKSPACE || '.');
      core.info(`Detected file: ${filePath}`);
    }

    const fileName = path.basename(filePath);

    // Step 3: Read file content
    core.info(`Reading file: ${fileName}`);
    const content = await readFile(filePath);
    const contentSizeKb = (Buffer.byteLength(content, 'utf-8') / 1024).toFixed(2);
    core.info(`File size: ${contentSizeKb}KB`);

    // Step 4: Initialize API client
    const client = new GeekWalaClient(
      inputs.apiToken,
      inputs.apiBaseUrl,
      inputs.timeoutSeconds,
      inputs.retryAttempts
    );

    // Step 5: Run scan
    core.info('Calling GeekWala API...');
    const response = await client.runScan(fileName, content);

    if (!response.success || !response.data) {
      throw new Error(response.error || 'Scan failed with unknown error');
    }

    core.info('✅ Scan completed successfully');
    core.info(`Total packages: ${response.data.summary.total_packages}`);
    core.info(`Vulnerable packages: ${response.data.summary.vulnerable_packages}`);

    // Step 6: Set action outputs
    setActionOutputs(response);

    // Step 7: Generate workflow summary
    await generateSummary(response, fileName);

    // Step 8: Check failure thresholds
    const { shouldFail, reason, status } = checkFailureThresholds(response, inputs);

    // Set scan status output
    core.setOutput('scan-status', status);

    if (shouldFail) {
      core.setFailed(reason || 'Vulnerability threshold exceeded');
    } else {
      core.info(`✅ Scan passed! Status: ${status}`);
    }
  } catch (error) {
    handleError(error);
  }
}

/**
 * Handle errors and set appropriate failure messages
 */
function handleError(error: unknown): void {
  if (error instanceof GeekWalaApiError) {
    // API-specific errors with helpful context
    core.setFailed(error.message);
    core.setOutput('scan-status', 'ERROR');

    // Add specific guidance based on error type
    if (error.type === 'auth_error') {
      core.error('💡 Tip: Verify your API token at https://geekwala.com/dashboard/tokens');
    } else if (error.type === 'rate_limit_error') {
      core.error('💡 Tip: Consider spacing out your scans or upgrading your plan');
    } else if (error.type === 'validation_error') {
      core.error('💡 Tip: Check that your dependency file has exact package versions');
    }
  } else if (error instanceof Error) {
    // Generic errors
    core.setFailed(`Action failed: ${error.message}`);
    core.setOutput('scan-status', 'ERROR');

    // Log stack trace for debugging
    if (error.stack) {
      core.debug(error.stack);
    }
  } else {
    // Unknown error type
    core.setFailed(`Action failed with unknown error: ${String(error)}`);
    core.setOutput('scan-status', 'ERROR');
  }
}

// Run the action
run();
