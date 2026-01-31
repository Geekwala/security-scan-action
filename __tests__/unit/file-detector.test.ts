/**
 * Tests for file detection
 */

import { isFileSupported, getFilePriority, getSupportedFileNames } from '../../src/detector/file-patterns';

describe('File Detection', () => {
  describe('isFileSupported', () => {
    it('should recognize npm files', () => {
      expect(isFileSupported('package.json')).toBe(true);
      expect(isFileSupported('package-lock.json')).toBe(true);
      expect(isFileSupported('yarn.lock')).toBe(true);
      expect(isFileSupported('pnpm-lock.yaml')).toBe(true);
    });

    it('should recognize Python files', () => {
      expect(isFileSupported('requirements.txt')).toBe(true);
      expect(isFileSupported('poetry.lock')).toBe(true);
      expect(isFileSupported('Pipfile.lock')).toBe(true);
    });

    it('should recognize PHP files', () => {
      expect(isFileSupported('composer.json')).toBe(true);
      expect(isFileSupported('composer.lock')).toBe(true);
    });

    it('should recognize Go files', () => {
      expect(isFileSupported('go.mod')).toBe(true);
      expect(isFileSupported('go.sum')).toBe(true);
    });

    it('should recognize Rust files', () => {
      expect(isFileSupported('Cargo.toml')).toBe(true);
      expect(isFileSupported('Cargo.lock')).toBe(true);
    });

    it('should recognize .csproj files', () => {
      expect(isFileSupported('MyProject.csproj')).toBe(true);
      expect(isFileSupported('Web.csproj')).toBe(true);
    });

    it('should reject unsupported files', () => {
      expect(isFileSupported('README.md')).toBe(false);
      expect(isFileSupported('unknown.txt')).toBe(false);
    });
  });

  describe('getFilePriority', () => {
    it('should prioritize lockfiles over manifests', () => {
      expect(getFilePriority('package-lock.json')).toBeLessThan(getFilePriority('package.json'));
      expect(getFilePriority('composer.lock')).toBeLessThan(getFilePriority('composer.json'));
      expect(getFilePriority('poetry.lock')).toBeLessThan(getFilePriority('requirements.txt'));
    });

    it('should prioritize npm lockfiles in order', () => {
      const packageLock = getFilePriority('package-lock.json');
      const yarnLock = getFilePriority('yarn.lock');
      const pnpmLock = getFilePriority('pnpm-lock.yaml');

      expect(packageLock).toBeLessThan(yarnLock);
      expect(yarnLock).toBeLessThan(pnpmLock);
    });
  });

  describe('getSupportedFileNames', () => {
    it('should return all supported file names', () => {
      const files = getSupportedFileNames();

      expect(files).toContain('package.json');
      expect(files).toContain('package-lock.json');
      expect(files).toContain('composer.json');
      expect(files).toContain('requirements.txt');
      expect(files).toContain('*.csproj');
    });
  });
});
