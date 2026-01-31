/**
 * Supported dependency file patterns and detection rules
 */

export interface FilePattern {
  name: string;
  priority: number; // Lower = higher priority
  isLockfile: boolean;
  ecosystem: string;
}

/**
 * Supported dependency files in priority order (lockfiles first)
 */
export const SUPPORTED_FILES: FilePattern[] = [
  // npm ecosystem (lockfiles first)
  { name: 'package-lock.json', priority: 1, isLockfile: true, ecosystem: 'npm' },
  { name: 'yarn.lock', priority: 2, isLockfile: true, ecosystem: 'npm' },
  { name: 'pnpm-lock.yaml', priority: 3, isLockfile: true, ecosystem: 'npm' },
  { name: 'package.json', priority: 10, isLockfile: false, ecosystem: 'npm' },

  // Python ecosystem
  { name: 'poetry.lock', priority: 4, isLockfile: true, ecosystem: 'PyPI' },
  { name: 'Pipfile.lock', priority: 5, isLockfile: true, ecosystem: 'PyPI' },
  { name: 'requirements.txt', priority: 11, isLockfile: false, ecosystem: 'PyPI' },

  // PHP ecosystem
  { name: 'composer.lock', priority: 6, isLockfile: true, ecosystem: 'Packagist' },
  { name: 'composer.json', priority: 12, isLockfile: false, ecosystem: 'Packagist' },

  // Go ecosystem
  { name: 'go.sum', priority: 7, isLockfile: true, ecosystem: 'Go' },
  { name: 'go.mod', priority: 13, isLockfile: false, ecosystem: 'Go' },

  // Rust ecosystem
  { name: 'Cargo.lock', priority: 8, isLockfile: true, ecosystem: 'crates.io' },
  { name: 'Cargo.toml', priority: 14, isLockfile: false, ecosystem: 'crates.io' },

  // Ruby ecosystem
  { name: 'Gemfile.lock', priority: 9, isLockfile: true, ecosystem: 'RubyGems' },

  // .NET ecosystem
  { name: 'packages.lock.json', priority: 15, isLockfile: true, ecosystem: 'NuGet' },
];

/**
 * Check if a file is supported
 */
export function isFileSupported(fileName: string): boolean {
  // Exact match
  if (SUPPORTED_FILES.some(f => f.name === fileName)) {
    return true;
  }

  // .csproj pattern match
  if (fileName.endsWith('.csproj')) {
    return true;
  }

  return false;
}

/**
 * Get file priority (lower = higher priority)
 */
export function getFilePriority(fileName: string): number {
  const pattern = SUPPORTED_FILES.find(f => f.name === fileName);
  if (pattern) {
    return pattern.priority;
  }

  // .csproj files have low priority (manifest, not lockfile)
  if (fileName.endsWith('.csproj')) {
    return 16;
  }

  return 999; // Unknown files last
}

/**
 * Get supported file names in priority order
 */
export function getSupportedFileNames(): string[] {
  return [...SUPPORTED_FILES]
    .sort((a, b) => a.priority - b.priority)
    .map(f => f.name)
    .concat('*.csproj'); // Add wildcard pattern at end
}
