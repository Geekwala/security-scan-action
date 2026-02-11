/**
 * YAML ignore file parser
 */
export interface IgnoreEntry {
    id: string;
    reason: string;
    expires?: string;
}
export interface IgnoreConfig {
    ignore: IgnoreEntry[];
}
/**
 * Load and parse the ignore file. Returns null if file doesn't exist.
 */
export declare function loadIgnoreFile(filePath: string): Promise<IgnoreConfig | null>;
/**
 * Filter out expired ignore entries
 */
export declare function filterExpiredEntries(config: IgnoreConfig): IgnoreConfig;
//# sourceMappingURL=parser.d.ts.map