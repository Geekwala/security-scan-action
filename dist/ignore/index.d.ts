/**
 * Vulnerability ignore/suppress system
 */
import { ScanResult } from '../api/types';
import { IgnoreConfig } from './parser';
export { loadIgnoreFile, IgnoreConfig, IgnoreEntry } from './parser';
/**
 * Apply ignore rules to scan results.
 * Marks matching vulnerabilities with _ignored and _ignoreReason.
 */
export declare function applyIgnores(results: ScanResult[], config: IgnoreConfig): {
    results: ScanResult[];
    ignoredCount: number;
};
//# sourceMappingURL=index.d.ts.map