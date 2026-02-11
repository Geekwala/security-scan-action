/**
 * Mock API helper using nock for HTTP mocking
 */

import nock from 'nock';
import { ApiResponse } from '../../src/api/types';

export class MockGeekWalaApi {
  private scope: nock.Scope;

  constructor(baseUrl = 'https://geekwala.com') {
    this.scope = nock(baseUrl);
  }

  /**
   * Mock successful scan response
   */
  mockSuccessfulScan(response: ApiResponse): nock.Scope {
    return this.scope
      .post('/api/v1/vulnerability-scan/run')
      .matchHeader('authorization', /^Bearer .+/)
      .matchHeader('content-type', 'application/json')
      .matchHeader('accept', 'application/json')
      .reply(200, response);
  }

  /**
   * Mock authentication error (401)
   */
  mockAuthError(): nock.Scope {
    return this.scope.post('/api/v1/vulnerability-scan/run').reply(401, {
      success: false,
      error: 'Unauthorized',
      type: 'auth_error',
    });
  }

  /**
   * Mock validation error (422)
   */
  mockValidationError(message: string): nock.Scope {
    return this.scope.post('/api/v1/vulnerability-scan/run').reply(422, {
      success: false,
      error: message,
      type: 'validation_error',
    });
  }

  /**
   * Mock rate limit error (429)
   */
  mockRateLimit(retryAfterSeconds = 60): nock.Scope {
    return this.scope
      .post('/api/v1/vulnerability-scan/run')
      .reply(
        429,
        {
          success: false,
          error: 'Rate limit exceeded',
          type: 'rate_limit_error',
        },
        {
          'Retry-After': String(retryAfterSeconds),
        }
      );
  }

  /**
   * Mock server error (500)
   */
  mockServerError(statusCode = 500): nock.Scope {
    return this.scope.post('/api/v1/vulnerability-scan/run').reply(statusCode, {
      success: false,
      error: 'Internal server error',
      type: 'server_error',
    });
  }

  /**
   * Mock network error (connection refused)
   */
  mockNetworkError(): nock.Scope {
    return this.scope
      .post('/api/v1/vulnerability-scan/run')
      .replyWithError('connect ECONNREFUSED');
  }

  /**
   * Get the nock scope for advanced usage
   */
  getScope(): nock.Scope {
    return this.scope;
  }

  /**
   * Check if all mocked requests have been called
   */
  isDone(): boolean {
    return this.scope.isDone();
  }

  /**
   * Clean up all mocks
   */
  cleanup(): void {
    nock.cleanAll();
  }

  /**
   * Clean up only this instance's mocks
   */
  cleanupInstance(): void {
    nock.cleanAll(); // Note: nock doesn't support per-instance cleanup
  }
}

/**
 * Helper to create a mock API instance
 */
export function createMockApi(baseUrl?: string): MockGeekWalaApi {
  return new MockGeekWalaApi(baseUrl);
}
