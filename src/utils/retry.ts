/**
 * Retry logic with exponential backoff and jitter
 */

export interface RetryOptions {
  maxAttempts: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  shouldRetry?: (error: unknown) => boolean;
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
export function isRetryableError(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) {
    return false;
  }
  const err = error as Record<string, unknown>;

  // Network errors
  if (
    err.code === 'ECONNRESET' ||
    err.code === 'ETIMEDOUT' ||
    err.code === 'ENOTFOUND' ||
    err.code === 'ECONNABORTED'
  ) {
    return true;
  }

  // HTTP status codes that should be retried (supports both AxiosError and GeekWalaApiError)
  const response = err.response as Record<string, unknown> | undefined;
  const status = response?.status ?? err.statusCode;
  if (status === 429 || status === 500 || status === 502 || status === 503) {
    return true;
  }

  // Don't retry client errors or auth errors
  if (typeof status === 'number' && status >= 400 && status < 500 && status !== 429) {
    return false;
  }

  return false;
}

/**
 * Retry a function with exponential backoff
 */
export async function retryWithBackoff<T>(fn: () => Promise<T>, options: RetryOptions): Promise<T> {
  const {
    maxAttempts,
    baseDelayMs = 1000,
    maxDelayMs = 30000,
    shouldRetry = isRetryableError,
  } = options;

  if (maxAttempts < 1) {
    throw new Error('maxAttempts must be at least 1');
  }

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      // Don't retry if this is the last attempt
      if (attempt === maxAttempts) {
        throw error;
      }

      // Check if we should retry this error
      if (!shouldRetry(error)) {
        throw error;
      }

      // Use Retry-After header delay if available, otherwise exponential backoff
      const retryAfterMs =
        typeof error === 'object' &&
        error !== null &&
        'retryAfterMs' in error &&
        typeof (error as Record<string, unknown>).retryAfterMs === 'number'
          ? ((error as Record<string, unknown>).retryAfterMs as number)
          : 0;
      const delay = retryAfterMs || calculateDelay(attempt, baseDelayMs, maxDelayMs);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  throw new Error('Retry logic error: no attempts made');
}
