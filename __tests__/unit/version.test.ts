/**
 * Tests for version export
 */

import { VERSION } from '../../src/version';

describe('VERSION', () => {
  it('should export a valid semver version string from package.json', () => {
    expect(VERSION).toBeDefined();
    expect(typeof VERSION).toBe('string');
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});
