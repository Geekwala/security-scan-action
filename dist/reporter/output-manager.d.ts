/**
 * GitHub Actions output management
 */
import { ApiResponse, ActionInputs } from '../api/types';
export type ScanStatus = 'PASS' | 'FAIL' | 'ERROR';
/**
 * Set GitHub Action outputs
 */
export declare function setActionOutputs(response: ApiResponse): void;
/**
 * Check if workflow should fail based on severity thresholds.
 * Collects ALL fail reasons rather than short-circuiting on first match.
 */
export declare function checkFailureThresholds(response: ApiResponse, inputs: ActionInputs): {
    shouldFail: boolean;
    reason?: string;
    reasons: string[];
    status: ScanStatus;
};
//# sourceMappingURL=output-manager.d.ts.map