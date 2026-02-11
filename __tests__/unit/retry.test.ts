/**
 * Tests for retry logic
 */

import { calculateDelay, isRetryableError, retryWithBackoff } from '../../src/utils/retry';

describe('Retry Logic', () => {
  describe('calculateDelay', () => {
    it('should calculate exponential backoff with jitter', () => {
      const delay1 = calculateDelay(1, 1000, 30000);
      expect(delay1).toBeGreaterThanOrEqual(1000); // 1s + 0-1s jitter
      expect(delay1).toBeLessThanOrEqual(2000);

      const delay2 = calculateDelay(2, 1000, 30000);
      expect(delay2).toBeGreaterThanOrEqual(2000); // 2s + 0-1s jitter
      expect(delay2).toBeLessThanOrEqual(3000);

      const delay3 = calculateDelay(3, 1000, 30000);
      expect(delay3).toBeGreaterThanOrEqual(4000); // 4s + 0-1s jitter
      expect(delay3).toBeLessThanOrEqual(5000);
    });

    it('should respect max delay', () => {
      const delay = calculateDelay(10, 1000, 30000);
      expect(delay).toBeLessThanOrEqual(31000); // 30s max + 1s jitter
    });
  });

  describe('isRetryableError', () => {
    it('should retry on network errors', () => {
      const networkError = { code: 'ECONNRESET' };
      expect(isRetryableError(networkError)).toBe(true);

      const timeoutError = { code: 'ETIMEDOUT' };
      expect(isRetryableError(timeoutError)).toBe(true);
    });

    it('should retry on server errors via response.status (AxiosError)', () => {
      const error429 = { response: { status: 429 } };
      expect(isRetryableError(error429)).toBe(true);

      const error500 = { response: { status: 500 } };
      expect(isRetryableError(error500)).toBe(true);

      const error503 = { response: { status: 503 } };
      expect(isRetryableError(error503)).toBe(true);
    });

    it('should retry on server errors via statusCode (GeekWalaApiError)', () => {
      const error429 = { statusCode: 429 };
      expect(isRetryableError(error429)).toBe(true);

      const error500 = { statusCode: 500 };
      expect(isRetryableError(error500)).toBe(true);

      const error502 = { statusCode: 502 };
      expect(isRetryableError(error502)).toBe(true);

      const error503 = { statusCode: 503 };
      expect(isRetryableError(error503)).toBe(true);
    });

    it('should retry on ECONNABORTED (axios timeout)', () => {
      const abortedError = { code: 'ECONNABORTED' };
      expect(isRetryableError(abortedError)).toBe(true);
    });

    it('should retry on ENOTFOUND', () => {
      const dnsError = { code: 'ENOTFOUND' };
      expect(isRetryableError(dnsError)).toBe(true);
    });

    it('should not retry on unknown errors without status', () => {
      expect(isRetryableError({})).toBe(false);
      expect(isRetryableError(new Error('something'))).toBe(false);
    });

    it('should not retry on primitive errors (string, number, null)', () => {
      expect(isRetryableError('network error')).toBe(false);
      expect(isRetryableError(42)).toBe(false);
      expect(isRetryableError(null)).toBe(false);
      expect(isRetryableError(undefined)).toBe(false);
      expect(isRetryableError(true)).toBe(false);
    });

    it('should not retry on client errors', () => {
      const error400 = { response: { status: 400 } };
      expect(isRetryableError(error400)).toBe(false);

      const error401 = { response: { status: 401 } };
      expect(isRetryableError(error401)).toBe(false);

      const error422 = { response: { status: 422 } };
      expect(isRetryableError(error422)).toBe(false);
    });

    it('should not retry on client errors via statusCode', () => {
      const error401 = { statusCode: 401 };
      expect(isRetryableError(error401)).toBe(false);

      const error422 = { statusCode: 422 };
      expect(isRetryableError(error422)).toBe(false);
    });
  });

  describe('retryWithBackoff', () => {
    it('should succeed on first attempt', async () => {
      const fn = jest.fn().mockResolvedValue('success');

      const result = await retryWithBackoff(fn, { maxAttempts: 3 });

      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('should retry on retryable errors', async () => {
      const fn = jest
        .fn()
        .mockRejectedValueOnce({ response: { status: 500 } })
        .mockResolvedValueOnce('success');

      const result = await retryWithBackoff(fn, { maxAttempts: 3, baseDelayMs: 10 });

      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(2);
    });

    it('should retry on GeekWalaApiError with retryable statusCode', async () => {
      const fn = jest
        .fn()
        .mockRejectedValueOnce({ statusCode: 500 })
        .mockResolvedValueOnce('success');

      const result = await retryWithBackoff(fn, { maxAttempts: 3, baseDelayMs: 10 });

      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(2);
    });

    it('should not retry on non-retryable errors', async () => {
      const fn = jest.fn().mockRejectedValue({ response: { status: 401 } });

      await expect(retryWithBackoff(fn, { maxAttempts: 3 })).rejects.toEqual({
        response: { status: 401 },
      });

      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('should fail after max attempts', async () => {
      const fn = jest.fn().mockRejectedValue({ response: { status: 500 } });

      await expect(retryWithBackoff(fn, { maxAttempts: 3, baseDelayMs: 10 })).rejects.toEqual({
        response: { status: 500 },
      });

      expect(fn).toHaveBeenCalledTimes(3);
    });

    it('should use retryAfterMs when available on error', async () => {
      const error = { statusCode: 429, retryAfterMs: 50 };
      const fn = jest
        .fn()
        .mockRejectedValueOnce(error)
        .mockResolvedValueOnce('success');

      const start = Date.now();
      const result = await retryWithBackoff(fn, { maxAttempts: 3, baseDelayMs: 10 });
      const elapsed = Date.now() - start;

      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(2);
      // Should wait ~50ms (retryAfterMs), not the exponential backoff
      expect(elapsed).toBeGreaterThanOrEqual(40);
    });
  });
});
