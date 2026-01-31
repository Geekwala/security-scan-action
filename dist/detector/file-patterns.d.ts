/**
 * Supported dependency file patterns and detection rules
 */
export interface FilePattern {
    name: string;
    priority: number;
    isLockfile: boolean;
    ecosystem: string;
}
/**
 * Supported dependency files in priority order (lockfiles first)
 */
export declare const SUPPORTED_FILES: FilePattern[];
/**
 * Check if a file is supported
 */
export declare function isFileSupported(fileName: string): boolean;
/**
 * Get file priority (lower = higher priority)
 */
export declare function getFilePriority(fileName: string): number;
/**
 * Get supported file names in priority order
 */
export declare function getSupportedFileNames(): string[];
//# sourceMappingURL=file-patterns.d.ts.map