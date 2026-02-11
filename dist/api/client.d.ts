/**
 * GeekWala API Client
 */
import { ApiResponse } from './types';
export declare class GeekWalaApiError extends Error {
    statusCode?: number | undefined;
    type?: string | undefined;
    retryAfterMs?: number;
    constructor(message: string, statusCode?: number | undefined, type?: string | undefined);
}
export declare class GeekWalaClient {
    private client;
    private retryAttempts;
    constructor(apiToken: string, baseUrl: string, timeoutSeconds: number, retryAttempts: number);
    /**
     * Run a vulnerability scan
     */
    runScan(fileName: string, content: string): Promise<ApiResponse>;
    /**
     * Validate API response shape to prevent downstream crashes from malformed data
     */
    private validateResponse;
    /**
     * Handle API errors and convert to meaningful messages
     */
    private handleError;
}
//# sourceMappingURL=client.d.ts.map