/**
 * Tests for ignore file parser
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as core from '@actions/core';
import { loadIgnoreFile, filterExpiredEntries, IgnoreConfig } from '../../src/ignore/parser';

jest.mock('@actions/core');

const TEST_DIR = '/tmp/test-ignore-parser';

describe('Ignore Parser', () => {
  beforeEach(async () => {
    await fs.mkdir(TEST_DIR, { recursive: true });
  });

  afterEach(async () => {
    try {
      await fs.rm(TEST_DIR, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  describe('loadIgnoreFile', () => {
    it('should parse valid YAML ignore file', async () => {
      const filePath = path.join(TEST_DIR, '.geekwala-ignore.yml');
      await fs.writeFile(filePath, `
ignore:
  - id: CVE-2021-23337
    reason: "Not exploitable in our usage of lodash"
  - id: GHSA-xxxx-yyyy
    reason: "Accepted risk per security review #42"
    expires: "2030-06-01"
`);

      const config = await loadIgnoreFile(filePath);

      expect(config).not.toBeNull();
      expect(config!.ignore).toHaveLength(2);
      expect(config!.ignore[0].id).toBe('CVE-2021-23337');
      expect(config!.ignore[0].reason).toBe('Not exploitable in our usage of lodash');
      expect(config!.ignore[0].expires).toBeUndefined();
      expect(config!.ignore[1].id).toBe('GHSA-xxxx-yyyy');
      expect(config!.ignore[1].expires).toBe('2030-06-01');
    });

    it('should return null for missing file', async () => {
      const config = await loadIgnoreFile(path.join(TEST_DIR, 'nonexistent.yml'));
      expect(config).toBeNull();
    });

    it('should handle empty file', async () => {
      const filePath = path.join(TEST_DIR, '.geekwala-ignore.yml');
      await fs.writeFile(filePath, '');

      const config = await loadIgnoreFile(filePath);
      expect(config).toEqual({ ignore: [] });
    });

    it('should handle file with empty ignore list', async () => {
      const filePath = path.join(TEST_DIR, '.geekwala-ignore.yml');
      await fs.writeFile(filePath, 'ignore: []');

      const config = await loadIgnoreFile(filePath);
      expect(config!.ignore).toHaveLength(0);
    });

    it('should skip entries without id', async () => {
      const filePath = path.join(TEST_DIR, '.geekwala-ignore.yml');
      await fs.writeFile(filePath, `
ignore:
  - reason: "Missing ID"
  - id: CVE-2021-1234
    reason: "Valid entry"
`);

      const config = await loadIgnoreFile(filePath);
      expect(config!.ignore).toHaveLength(1);
      expect(config!.ignore[0].id).toBe('CVE-2021-1234');
    });

    it('should default reason to "No reason provided"', async () => {
      const filePath = path.join(TEST_DIR, '.geekwala-ignore.yml');
      await fs.writeFile(filePath, `
ignore:
  - id: CVE-2021-1234
`);

      const config = await loadIgnoreFile(filePath);
      expect(config!.ignore[0].reason).toBe('No reason provided');
    });
  });

  describe('filterExpiredEntries', () => {
    it('should keep non-expired entries', () => {
      const config: IgnoreConfig = {
        ignore: [
          { id: 'CVE-1', reason: 'test', expires: '2099-01-01' },
          { id: 'CVE-2', reason: 'test' }, // no expiry
        ],
      };

      const filtered = filterExpiredEntries(config);
      expect(filtered.ignore).toHaveLength(2);
    });

    it('should remove expired entries', () => {
      const config: IgnoreConfig = {
        ignore: [
          { id: 'CVE-1', reason: 'test', expires: '2020-01-01' },
          { id: 'CVE-2', reason: 'test' },
        ],
      };

      const filtered = filterExpiredEntries(config);
      expect(filtered.ignore).toHaveLength(1);
      expect(filtered.ignore[0].id).toBe('CVE-2');
    });

    it('should treat invalid expiry dates as expired (fail-safe) and warn', () => {
      const config: IgnoreConfig = {
        ignore: [
          { id: 'CVE-1', reason: 'test', expires: 'not-a-date' },
          { id: 'CVE-2', reason: 'test', expires: '2020-01-01' },
          { id: 'CVE-3', reason: 'test' }, // no expiry — kept
        ],
      };

      const filtered = filterExpiredEntries(config);
      // CVE-1 with invalid date should be removed (fail-safe)
      // CVE-2 with expired date should be removed
      // CVE-3 with no expiry should be kept
      expect(filtered.ignore).toHaveLength(1);
      expect(filtered.ignore[0].id).toBe('CVE-3');
      expect(core.warning).toHaveBeenCalledWith(
        expect.stringContaining('Invalid expiry date "not-a-date"')
      );
    });
  });
});
