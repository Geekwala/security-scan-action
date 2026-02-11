/**
 * Sample dependency files for testing
 */

/**
 * Clean package.json (npm manifest)
 */
export const cleanPackageJson = JSON.stringify(
  {
    name: 'test-app',
    version: '1.0.0',
    dependencies: {
      express: '^4.18.2',
    },
  },
  null,
  2
);

/**
 * Vulnerable package.json with lodash 4.17.20
 */
export const vulnerablePackageJson = JSON.stringify(
  {
    name: 'vulnerable-app',
    version: '1.0.0',
    dependencies: {
      lodash: '4.17.20',
      express: '^4.18.2',
    },
  },
  null,
  2
);

/**
 * Clean package-lock.json (npm lockfile)
 */
export const cleanPackageLock = JSON.stringify(
  {
    name: 'test-app',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': {
        name: 'test-app',
        version: '1.0.0',
        dependencies: {
          express: '^4.18.2',
        },
      },
      'node_modules/express': {
        version: '4.18.2',
        resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
      },
    },
  },
  null,
  2
);

/**
 * Composer.json (PHP manifest)
 */
export const composerJson = JSON.stringify(
  {
    name: 'test/php-app',
    require: {
      'symfony/console': '^6.0',
      'guzzlehttp/guzzle': '^7.5',
    },
  },
  null,
  2
);

/**
 * Requirements.txt (Python)
 */
export const requirementsTxt = `Django==4.2.0
requests==2.31.0
pytest==7.4.0
`;

/**
 * Go.mod (Go)
 */
export const goMod = `module github.com/test/go-app

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/stretchr/testify v1.8.4
)
`;

/**
 * Large file content (513KB - exceeds 512KB limit)
 */
export const largeFileContent = 'x'.repeat(513 * 1024);

/**
 * Valid large file (511KB - under limit)
 */
export const validLargeFileContent = 'x'.repeat(511 * 1024);
