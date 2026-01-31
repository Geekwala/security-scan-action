/**
 * Severity classification utilities
 */
import { Vulnerability, SeverityCounts } from '../api/types';
/**
 * Normalize severity from various formats to standard levels
 */
export declare function normalizeSeverity(severity: string): string;
/**
 * Get severity from CVSS score
 */
export declare function getSeverityFromCvss(score: number): string;
/**
 * Extract highest severity from vulnerability data
 */
export declare function getVulnerabilitySeverity(vuln: Vulnerability): string;
/**
 * Count vulnerabilities by severity
 */
export declare function countBySeverity(vulnerabilities: Vulnerability[]): SeverityCounts;
//# sourceMappingURL=severity.d.ts.map