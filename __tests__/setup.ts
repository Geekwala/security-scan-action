/**
 * Test environment setup
 */

import nock from 'nock';

// Disable real HTTP requests during tests
beforeAll(() => {
  nock.disableNetConnect();
  // Allow localhost for local testing if needed
  nock.enableNetConnect('127.0.0.1');
});

afterAll(() => {
  nock.cleanAll();
  nock.enableNetConnect();
});

// Mock GitHub Actions environment
process.env.GITHUB_WORKSPACE = '/tmp/test-workspace';
process.env.GITHUB_REPOSITORY = 'test-org/test-repo';
process.env.GITHUB_RUN_ID = '12345';
process.env.GITHUB_SERVER_URL = 'https://github.com';
