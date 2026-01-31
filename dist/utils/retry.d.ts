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
export declare function calculateDelay(attempt: number, baseMs?: number, maxMs?: number): number;
/**
 * Determine if an error should trigger a retry
 */
export declare function isRetryableError(error: any): boolean;
/**
 * Retry a function with exponential backoff
 */
export declare function retryWithBackoff<T>(fn: () => Promise<T>, options: RetryOptions): Promise<T>;
//# sourceMappingURL=retry.d.ts.map