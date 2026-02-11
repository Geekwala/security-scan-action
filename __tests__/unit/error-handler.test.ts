/**
 * Tests for error handler
 */

import * as core from '@actions/core';
import { GeekWalaApiError } from '../../src/api/client';
import { FileSizeError } from '../../src/detector/file-detector';
import { handleError } from '../../src/utils/error-handler';

jest.mock('@actions/core');

describe('handleError', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('FileSizeError handling', () => {
    it('should handle file size errors with tip', () => {
      const error = new FileSizeError('File is 513KB, exceeds maximum allowed size of 512KB');
      handleError(error);

      expect(core.setFailed).toHaveBeenCalledWith(error.message);
      expect(core.setOutput).toHaveBeenCalledWith('scan-status', 'ERROR');
      expect(core.error).toHaveBeenCalledWith(
        expect.stringContaining('512KB')
      );
    });
  });

  describe('GeekWalaApiError handling', () => {
    it('should handle auth_error with tip', () => {
      const error = new GeekWalaApiError('Unauthorized', 401, 'auth_error');
      handleError(error);

      expect(core.setFailed).toHaveBeenCalledWith('Unauthorized');
      expect(core.setOutput).toHaveBeenCalledWith('scan-status', 'ERROR');
      expect(core.error).toHaveBeenCalledWith(
        expect.stringContaining('Verify your API token')
      );
    });

    it('should handle rate_limit_error with tip', () => {
      const error = new GeekWalaApiError('Rate limit exceeded', 429, 'rate_limit_error');
      handleError(error);

      expect(core.setFailed).toHaveBeenCalledWith('Rate limit exceeded');
      expect(core.setOutput).toHaveBeenCalledWith('scan-status', 'ERROR');
      expect(core.error).toHaveBeenCalledWith(
        expect.stringContaining('spacing out your scans')
      );
    });

    it('should handle validation_error with tip', () => {
      const error = new GeekWalaApiError('Invalid file format', 422, 'validation_error');
      handleError(error);

      expect(core.setFailed).toHaveBeenCalledWith('Invalid file format');
      expect(core.setOutput).toHaveBeenCalledWith('scan-status', 'ERROR');
      expect(core.error).toHaveBeenCalledWith(
        expect.stringContaining('exact package versions')
      );
    });

    it('should handle timeout_error with tip', () => {
      const error = new GeekWalaApiError('Request timed out', undefined, 'timeout_error');
      handleError(error);

      expect(core.setFailed).toHaveBeenCalledWith('Request timed out');
      expect(core.setOutput).toHaveBeenCalledWith('scan-status', 'ERROR');
      expect(core.error).toHaveBeenCalledWith(
        expect.stringContaining('increasing timeout-seconds')
      );
    });

    it('should handle unrecognized API error type without tip', () => {
      const error = new GeekWalaApiError('Internal server error', 500, 'server_error');
      handleError(error);

      expect(core.setFailed).toHaveBeenCalledWith('Internal server error');
      expect(core.setOutput).toHaveBeenCalledWith('scan-status', 'ERROR');
      expect(core.error).not.toHaveBeenCalled();
    });
  });

  describe('generic Error handling', () => {
    it('should handle Error with stack trace', () => {
      const error = new Error('Something broke');
      error.stack = 'Error: Something broke\n    at test.ts:1';
      handleError(error);

      expect(core.setFailed).toHaveBeenCalledWith('Action failed: Something broke');
      expect(core.setOutput).toHaveBeenCalledWith('scan-status', 'ERROR');
      expect(core.debug).toHaveBeenCalledWith(error.stack);
    });

    it('should handle Error without stack trace', () => {
      const error = new Error('No stack');
      error.stack = undefined;
      handleError(error);

      expect(core.setFailed).toHaveBeenCalledWith('Action failed: No stack');
      expect(core.setOutput).toHaveBeenCalledWith('scan-status', 'ERROR');
      expect(core.debug).not.toHaveBeenCalled();
    });
  });

  describe('unknown error handling', () => {
    it('should handle string thrown value', () => {
      handleError('string error');

      expect(core.setFailed).toHaveBeenCalledWith(
        'Action failed with unknown error: string error'
      );
      expect(core.setOutput).toHaveBeenCalledWith('scan-status', 'ERROR');
    });

    it('should handle null thrown value', () => {
      handleError(null);

      expect(core.setFailed).toHaveBeenCalledWith(
        'Action failed with unknown error: null'
      );
      expect(core.setOutput).toHaveBeenCalledWith('scan-status', 'ERROR');
    });
  });
});
