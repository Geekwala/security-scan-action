/**
 * JSON report generator
 */
import { ApiResponse } from '../api/types';
export interface JsonReport {
    version: string;
    generatedAt: string;
    scanDurationMs?: number;
    tool: string;
    fileScanned: string;
    summary: {
        total_packages: number;
        vulnerable_packages: number;
        safe_packages: number;
    };
    vulnerabilities: Array<{
        id: string;
        package: string;
        version: string;
        ecosystem: string;
        severity: string;
        summary?: string;
        cvss_score?: number | null;
        epss_score?: number | null;
        is_known_exploited?: boolean;
        fix_version?: string | null;
        ignored: boolean;
        ignoreReason?: string;
    }>;
    ignoredCount: number;
}
/**
 * Generate structured JSON report from scan results
 */
export declare function generateJsonReport(response: ApiResponse, fileName: string, scanDurationMs?: number): JsonReport;
//# sourceMappingURL=json-reporter.d.ts.map