/**
 * YAML ignore file parser
 */

import * as fs from 'fs/promises';
import * as core from '@actions/core';
import * as yaml from 'js-yaml';

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
export async function loadIgnoreFile(filePath: string): Promise<IgnoreConfig | null> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const parsed = yaml.load(content, { schema: yaml.DEFAULT_SCHEMA }) as Record<string, unknown>;

    if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.ignore)) {
      return { ignore: [] };
    }

    const entries: IgnoreEntry[] = [];
    for (const entry of parsed.ignore) {
      if (
        typeof entry === 'object' &&
        entry !== null &&
        typeof (entry as Record<string, unknown>).id === 'string'
      ) {
        const e = entry as Record<string, unknown>;
        entries.push({
          id: String(e.id),
          reason: String(e.reason || 'No reason provided'),
          expires: e.expires ? String(e.expires) : undefined,
        });
      }
    }

    return { ignore: entries };
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

/**
 * Filter out expired ignore entries
 */
export function filterExpiredEntries(config: IgnoreConfig): IgnoreConfig {
  const now = new Date();
  return {
    ignore: config.ignore.filter(entry => {
      if (!entry.expires) return true;
      const expiryDate = new Date(entry.expires);
      if (isNaN(expiryDate.getTime())) {
        core.warning(
          `Invalid expiry date "${entry.expires}" for ignore entry ${entry.id}, treating as expired (fail-safe)`
        );
        return false;
      }
      return expiryDate > now;
    }),
  };
}
