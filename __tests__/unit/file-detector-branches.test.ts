/**
 * Tests for file-detector branch coverage
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { detectDependencyFile, validateFile, readFile } from '../../src/detector/file-detector';

describe('File Detector Branches', () => {
  const TEST_DIR = '/tmp/test-file-detector-branches';

  beforeEach(async () => {
    await fs.mkdir(TEST_DIR, { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
  });

  describe('detectDependencyFile with .csproj', () => {
    it('should detect .csproj files in workspace', async () => {
      const csprojPath = path.join(TEST_DIR, 'MyApp.csproj');
      await fs.writeFile(csprojPath, '<Project></Project>');

      const detected = await detectDependencyFile(TEST_DIR);
      expect(path.basename(detected)).toBe('MyApp.csproj');
    });

    it('should prefer lockfile over .csproj when both exist', async () => {
      await fs.writeFile(path.join(TEST_DIR, 'MyApp.csproj'), '<Project></Project>');
      await fs.writeFile(path.join(TEST_DIR, 'package-lock.json'), '{}');

      const detected = await detectDependencyFile(TEST_DIR);
      expect(path.basename(detected)).toBe('package-lock.json');
    });
  });

  describe('validateFile', () => {
    it('should throw for file that does not exist', async () => {
      const missingPath = path.join(TEST_DIR, 'package.json');
      await expect(validateFile(missingPath)).rejects.toThrow(/File not found or not readable/);
    });
  });

  describe('readFile', () => {
    it('should throw FileNotFoundError for non-existent file', async () => {
      const missingPath = path.join(TEST_DIR, 'missing.json');
      await expect(readFile(missingPath)).rejects.toThrow(/Failed to read file/);
    });
  });
});
