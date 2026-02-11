/**
 * Dependency file detection logic
 */
export declare class FileNotFoundError extends Error {
    constructor(message: string);
}
/**
 * Detect dependency file in the repository
 * Searches in priority order (lockfiles before manifests)
 */
export declare function detectDependencyFile(workspaceDir?: string): Promise<string>;
/**
 * Validate that a file exists and is supported
 */
export declare function validateFile(filePath: string): Promise<void>;
/**
 * Read file content with size guard to prevent OOM on large files
 */
export declare function readFile(filePath: string, maxSizeBytes?: number): Promise<string>;
//# sourceMappingURL=file-detector.d.ts.map