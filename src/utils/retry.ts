/**
 * Retry logic with exponential backoff and jitter
 */

export interface RetryOptions {
  maxAttempts: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  shouldRetry?: (error: Error) => boolean;
}

/**
 * Calculate delay with exponential backoff and jitter
 */
export function calculateDelay(attempt: number, baseMs = 1000, maxMs = 30000): number {
  const exponentialDelay = Math.min(baseMs * Math.pow(2, attempt - 1), maxMs);
  const jitter = Math.random() * 1000; // 0-1 second random jitter
  return exponentialDelay + jitter;
}

/**
 * Determine if an error should trigger a retry
 */
export function isRetryableError(error: any): boolean {
  // Network errors
  if (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT' || error.code === 'ENOTFOUND') {
    return true;
  }

  // HTTP status codes that should be retried
  const status = error.response?.status;
  if (status === 429 || status === 500 || status === 502 || status === 503) {
    return true;
  }

  // Don't retry client errors or auth errors
  if (status >= 400 && status < 500 && status !== 429) {
    return false;
  }

  return false;
}

/**
 * Retry a function with exponential backoff
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  options: RetryOptions
): Promise<T> {
  const {
    maxAttempts,
    baseDelayMs = 1000,
    maxDelayMs = 30000,
    shouldRetry = isRetryableError,
  } = options;

  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;

      // Don't retry if this is the last attempt
      if (attempt === maxAttempts) {
        throw error;
      }

      // Check if we should retry this error
      if (!shouldRetry(error as Error)) {
        throw error;
      }

      // Calculate delay and wait
      const delay = calculateDelay(attempt, baseDelayMs, maxDelayMs);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  throw lastError;
}
