/**
 * TypeScript interfaces for GeekWala API
 */

export type SeverityThreshold = 'none' | 'low' | 'medium' | 'high' | 'critical';

export interface VulnerabilitySeverity {
  type: string;
  score: string;
}

export interface Vulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  references?: Array<{ type: string; url: string }>;
  severity?: VulnerabilitySeverity[];
  epss_score?: number | null;
  epss_percentile?: number | null;
  is_kev?: boolean;
  kev_date_added?: string | null;
  cvss_score?: number | null;
  fix_version?: string | null;
  cwe_ids?: string[];
  _ignored?: boolean;
  _ignoreReason?: string;
}

export interface ScanResult {
  ecosystem: string;
  package: string;
  version: string;
  affected: boolean;
  vulnerabilities: Vulnerability[];
  severity: string;
}

export interface ScanSummary {
  total_packages: number;
  vulnerable_packages: number;
  safe_packages: number;
}

export interface ApiResponse {
  success: boolean;
  data?: {
    results: ScanResult[];
    summary: ScanSummary;
  };
  error?: string;
  type?: string;
}

export interface ActionInputs {
  apiToken: string;
  filePath?: string;
  failOnCritical: boolean;
  failOnHigh: boolean;
  severityThreshold: SeverityThreshold;
  failOnKev: boolean;
  epssThreshold?: number;
  onlyFixed: boolean;
  sarifFile?: string;
  ignoreFile?: string;
  outputFormat: string[];
  jsonFile?: string;
  apiBaseUrl: string;
  retryAttempts: number;
  timeoutSeconds: number;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}
