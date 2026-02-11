/**
 * GeekWala Security Scan GitHub Action
 * Main entry point
 */

import * as core from '@actions/core';
import * as fs from 'fs/promises';
import * as path from 'path';
import { validateInputs } from './validators/input-validator';
import { detectDependencyFile, validateFile, readFile } from './detector/file-detector';
import { GeekWalaClient } from './api/client';
import { handleError } from './utils/error-handler';
import { setActionOutputs, checkFailureThresholds } from './reporter/output-manager';
import { generateSummary } from './reporter/summary-reporter';
import { loadIgnoreFile, applyIgnores } from './ignore/index';
import { generateSarif } from './sarif/index';
import { generateJsonReport } from './reporter/json-reporter';
import { generateTableOutput } from './reporter/table-reporter';
import { pluralizeVulnerabilities } from './utils/format';

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

    const workspace = process.env.GITHUB_WORKSPACE || '.';
    const fileName = path.relative(workspace, filePath);

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

    // Step 6: Apply ignore rules
    if (inputs.ignoreFile) {
      const ignoreConfig = await loadIgnoreFile(inputs.ignoreFile);
      if (ignoreConfig) {
        const { results, ignoredCount } = applyIgnores(response.data.results, ignoreConfig);
        response.data.results = results;
        core.setOutput('ignored-count', ignoredCount.toString());
        if (ignoredCount > 0) {
          core.info(`Suppressed ${ignoredCount} ignored ${pluralizeVulnerabilities(ignoredCount)}`);
        }
      } else {
        core.setOutput('ignored-count', '0');
      }
    } else {
      core.setOutput('ignored-count', '0');
    }

    // Step 7: Set action outputs
    setActionOutputs(response);

    // Step 8: Generate SARIF if requested
    if (inputs.sarifFile) {
      core.info(`Generating SARIF report: ${inputs.sarifFile}`);
      const sarif = generateSarif(response, fileName);
      await fs.writeFile(inputs.sarifFile, JSON.stringify(sarif, null, 2));
      core.setOutput('sarif-file', inputs.sarifFile);
    }

    // Step 9: Generate outputs based on format
    if (inputs.outputFormat.includes('summary')) {
      await generateSummary(response, fileName);
    }

    if (inputs.outputFormat.includes('table')) {
      generateTableOutput(response);
    }

    if (inputs.outputFormat.includes('json')) {
      const jsonReport = generateJsonReport(response, fileName);
      if (inputs.jsonFile) {
        await fs.writeFile(inputs.jsonFile, JSON.stringify(jsonReport, null, 2));
        core.info(`JSON report saved to: ${inputs.jsonFile}`);
      } else {
        core.info(JSON.stringify(jsonReport, null, 2));
      }
    }

    // Step 10: Check failure thresholds
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

// Run the action
run();
