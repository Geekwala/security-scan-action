/**
 * GeekWala API Client
 */

import axios, { AxiosInstance, AxiosError } from 'axios';
import { ApiResponse } from './types';
import { retryWithBackoff } from '../utils/retry';

export class GeekWalaApiError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public type?: string
  ) {
    super(message);
    this.name = 'GeekWalaApiError';
  }
}

export class GeekWalaClient {
  private client: AxiosInstance;
  private retryAttempts: number;

  constructor(apiToken: string, baseUrl: string, timeoutSeconds: number, retryAttempts: number) {
    this.client = axios.create({
      baseURL: baseUrl,
      timeout: timeoutSeconds * 1000,
      headers: {
        'Authorization': `Bearer ${apiToken}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'GeekWala-GitHub-Action/1.0.0',
      },
    });

    this.retryAttempts = retryAttempts;
  }

  /**
   * Run a vulnerability scan
   */
  async runScan(fileName: string, content: string): Promise<ApiResponse> {
    // Validate file size client-side (256KB limit for authenticated users)
    const maxSizeKb = 256;
    const contentSizeKb = Buffer.byteLength(content, 'utf-8') / 1024;

    if (contentSizeKb > maxSizeKb) {
      throw new GeekWalaApiError(
        `File size (${contentSizeKb.toFixed(2)}KB) exceeds maximum allowed size (${maxSizeKb}KB)`,
        400,
        'file_size_error'
      );
    }

    const scanRequest = async () => {
      try {
        const response = await this.client.post<ApiResponse>(
          '/api/v1/vulnerability-scan/run',
          {
            file_name: fileName,
            content: content,
          }
        );

        return response.data;
      } catch (error) {
        throw this.handleError(error as AxiosError);
      }
    };

    return retryWithBackoff(scanRequest, {
      maxAttempts: this.retryAttempts,
    });
  }

  /**
   * Handle API errors and convert to meaningful messages
   */
  private handleError(error: AxiosError): GeekWalaApiError {
    // Network errors
    if (!error.response) {
      return new GeekWalaApiError(
        `Network error: ${error.message}. Check your internet connection and verify GeekWala API is accessible.`,
        undefined,
        'network_error'
      );
    }

    const status = error.response.status;
    const data = error.response.data as any;

    switch (status) {
      case 401:
        return new GeekWalaApiError(
          `Authentication failed. Verify your API token has 'scan:write' ability. Create a token at https://geekwala.com/dashboard/tokens`,
          401,
          'auth_error'
        );

      case 422:
        const validationMsg = data?.error || 'Validation error';
        return new GeekWalaApiError(
          `Validation error: ${validationMsg}`,
          422,
          data?.type || 'validation_error'
        );

      case 429:
        const retryAfter = error.response.headers['retry-after'];
        const waitTime = retryAfter ? `Wait ${retryAfter} seconds` : 'Wait a few minutes';
        return new GeekWalaApiError(
          `Rate limit exceeded (50 scans/hour). ${waitTime} and try again.`,
          429,
          'rate_limit_error'
        );

      case 500:
      case 502:
      case 503:
        return new GeekWalaApiError(
          `GeekWala API is temporarily unavailable (${status}). This is usually transient - retrying automatically.`,
          status,
          'server_error'
        );

      default:
        return new GeekWalaApiError(
          `API error (${status}): ${data?.error || error.message}`,
          status,
          'unknown_error'
        );
    }
  }
}
