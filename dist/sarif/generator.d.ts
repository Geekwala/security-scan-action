/**
 * SARIF 2.1.0 report generator
 * Pure data transformation — no @actions/core dependency for testability.
 */
import { ApiResponse } from '../api/types';
import { SarifLog } from './types';
/**
 * Generate a SARIF 2.1.0 log from scan results
 */
export declare function generateSarif(response: ApiResponse, fileName: string): SarifLog;
//# sourceMappingURL=generator.d.ts.map