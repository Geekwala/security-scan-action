/**
 * Error handling utilities for the action
 */

import * as core from '@actions/core';
import { GeekWalaApiError } from '../api/client';
import { FileSizeError } from '../detector/file-detector';

/**
 * Handle errors and set appropriate failure messages
 */
export function handleError(error: unknown): void {
  if (error instanceof FileSizeError) {
    core.setFailed(error.message);
    core.setOutput('scan-status', 'ERROR');
    core.error(
      '💡 Tip: The file size limit is 512KB. For large lockfiles, consider scanning the manifest instead.'
    );
  } else if (error instanceof GeekWalaApiError) {
    core.setFailed(error.message);
    core.setOutput('scan-status', 'ERROR');

    if (error.type === 'auth_error') {
      core.error('💡 Tip: Verify your API token at https://geekwala.com/developers/api-tokens');
    } else if (error.type === 'rate_limit_error') {
      core.error('💡 Tip: Consider spacing out your scans or upgrading your plan');
    } else if (error.type === 'validation_error') {
      core.error('💡 Tip: Check that your dependency file has exact package versions');
    } else if (error.type === 'timeout_error') {
      core.error('💡 Tip: Try increasing timeout-seconds or reducing the dependency file size');
    }
  } else if (error instanceof Error) {
    core.setFailed(`Action failed: ${error.message}`);
    core.setOutput('scan-status', 'ERROR');

    if (error.stack) {
      core.debug(error.stack);
    }
  } else {
    core.setFailed(`Action failed with unknown error: ${String(error)}`);
    core.setOutput('scan-status', 'ERROR');
  }
}
