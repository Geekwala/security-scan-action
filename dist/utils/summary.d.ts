/**
 * Summary recomputation utilities
 */
import { ScanResult, ScanSummary } from '../api/types';
/**
 * Recompute summary counts from results, accounting for ignored vulnerabilities.
 * A package is "vulnerable" only if it has at least one active (non-ignored) vulnerability.
 */
export declare function recomputeSummary(results: ScanResult[]): ScanSummary;
//# sourceMappingURL=summary.d.ts.map