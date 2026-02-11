/**
 * Vulnerability ignore/suppress system
 */

import { ScanResult } from '../api/types';
import { IgnoreConfig, filterExpiredEntries } from './parser';

export { loadIgnoreFile, IgnoreConfig, IgnoreEntry } from './parser';

/**
 * Apply ignore rules to scan results.
 * Marks matching vulnerabilities with _ignored and _ignoreReason.
 */
export function applyIgnores(
  results: ScanResult[],
  config: IgnoreConfig
): { results: ScanResult[]; ignoredCount: number } {
  const activeConfig = filterExpiredEntries(config);
  const ignoreIds = new Set(activeConfig.ignore.map(e => e.id.toUpperCase()));
  const reasonMap = new Map(activeConfig.ignore.map(e => [e.id.toUpperCase(), e.reason]));

  let ignoredCount = 0;

  const updatedResults = results.map(result => ({
    ...result,
    vulnerabilities: result.vulnerabilities.map(vuln => {
      // Check if the vuln ID or any alias matches
      const allIds = [vuln.id, ...(vuln.aliases || [])].map(id => id.toUpperCase());
      const matchedId = allIds.find(id => ignoreIds.has(id));

      if (matchedId) {
        ignoredCount++;
        return {
          ...vuln,
          _ignored: true,
          _ignoreReason: reasonMap.get(matchedId) || 'Ignored',
        };
      }

      return vuln;
    }),
  }));

  return { results: updatedResults, ignoredCount };
}
