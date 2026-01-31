# GeekWala Security Scan Action

[![Test](https://github.com/Geekwala/security-scan-action/actions/workflows/test.yml/badge.svg)](https://github.com/Geekwala/security-scan-action/actions/workflows/test.yml)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-GeekWala%20Security%20Scan-blue.svg)](https://github.com/marketplace/actions/geekwala-security-scan)

GitHub Action to scan your dependencies for known vulnerabilities using the [GeekWala](https://geekwala.com) API, enriched with EPSS (Exploit Prediction Scoring System) and CISA KEV (Known Exploited Vulnerabilities) data.

## Features

- 🔍 **Auto-detects dependency files** - Automatically finds and scans lockfiles and manifests
- 🛡️ **Multi-ecosystem support** - npm, PyPI, Maven, Packagist, Go, Rust, Ruby, NuGet
- 📊 **Rich workflow summaries** - Detailed vulnerability reports with CVSS, EPSS, and KEV data
- ⚡ **Fast and reliable** - Exponential backoff retry logic for transient failures
- 🎯 **Configurable thresholds** - Fail builds on critical or high severity vulnerabilities
- 📦 **Prioritizes lockfiles** - Scans `package-lock.json` before `package.json` for accuracy

## Quick Start

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan for vulnerabilities
        uses: geekwala/security-scan-action@v1
        with:
          api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `api-token` | GeekWala API token with `scan:write` ability | ✅ Yes | - |
| `file-path` | Path to dependency file (auto-detected if omitted) | No | Auto-detect |
| `fail-on-critical` | Fail workflow if critical vulnerabilities found | No | `true` |
| `fail-on-high` | Fail workflow if high severity vulnerabilities found | No | `false` |
| `api-base-url` | GeekWala API base URL | No | `https://geekwala.com` |
| `retry-attempts` | Number of retry attempts for transient failures | No | `3` |
| `timeout-seconds` | Request timeout in seconds | No | `300` |

## Outputs

| Output | Description | Example |
|--------|-------------|---------|
| `total-packages` | Total number of packages scanned | `150` |
| `vulnerable-packages` | Number of packages with vulnerabilities | `3` |
| `safe-packages` | Number of packages without vulnerabilities | `147` |
| `critical-count` | Number of critical severity vulnerabilities | `1` |
| `high-count` | Number of high severity vulnerabilities | `2` |
| `medium-count` | Number of medium severity vulnerabilities | `5` |
| `low-count` | Number of low severity vulnerabilities | `10` |
| `scan-status` | Overall scan status: `PASS`, `FAIL`, or `ERROR` | `PASS` |
| `has-vulnerabilities` | Boolean indicating if vulnerabilities were found | `true` |

## Supported Ecosystems

### Lockfiles (Prioritized)
- **npm**: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- **Python**: `poetry.lock`, `Pipfile.lock`
- **PHP**: `composer.lock`
- **Go**: `go.sum`
- **Rust**: `Cargo.lock`
- **Ruby**: `Gemfile.lock`
- **.NET**: `packages.lock.json`

### Manifests
- **npm**: `package.json`
- **Python**: `requirements.txt`
- **PHP**: `composer.json`
- **Java**: `pom.xml`
- **Go**: `go.mod`
- **Rust**: `Cargo.toml`
- **.NET**: `*.csproj`

## Usage Examples

### Basic Usage with Auto-Detection

The action automatically detects dependency files in your repository:

```yaml
- uses: geekwala/security-scan-action@v1
  with:
    api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
```

### Scan Specific File

```yaml
- uses: geekwala/security-scan-action@v1
  with:
    api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
    file-path: ./backend/composer.lock
```

### Fail on High Severity Vulnerabilities

```yaml
- uses: geekwala/security-scan-action@v1
  with:
    api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
    fail-on-critical: true
    fail-on-high: true
```

### Use Outputs in Later Steps

```yaml
- uses: geekwala/security-scan-action@v1
  id: scan
  with:
    api-token: ${{ secrets.GEEKWALA_API_TOKEN }}

- name: Comment on PR
  if: steps.scan.outputs.has-vulnerabilities == 'true'
  run: |
    echo "Found ${{ steps.scan.outputs.vulnerable-packages }} vulnerable packages"
    echo "Critical: ${{ steps.scan.outputs.critical-count }}"
    echo "High: ${{ steps.scan.outputs.high-count }}"
```

### Scan Multiple Ecosystems in Monorepo

```yaml
jobs:
  scan-frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: geekwala/security-scan-action@v1
        with:
          api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
          file-path: ./frontend/package-lock.json

  scan-backend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: geekwala/security-scan-action@v1
        with:
          api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
          file-path: ./backend/composer.lock
```

### Only Warn on Vulnerabilities (Don't Fail)

```yaml
- uses: geekwala/security-scan-action@v1
  with:
    api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
    fail-on-critical: false
    fail-on-high: false
```

## Getting an API Token

1. Sign up at [geekwala.com](https://geekwala.com)
2. Navigate to [Dashboard → API Tokens](https://geekwala.com/dashboard/tokens)
3. Create a new token with `scan:write` ability
4. Add the token to your repository secrets as `GEEKWALA_API_TOKEN`

## Workflow Summary

The action generates a comprehensive workflow summary visible in the GitHub Actions UI:

- 🛡️ Overall scan status with emoji indicators
- 📊 Severity breakdown table (Critical, High, Medium, Low)
- 📦 Detailed vulnerability information per package
- 🔍 CVSS scores, EPSS probabilities, and CISA KEV flags
- 🔗 Direct links to vulnerability details

## Rate Limits

- **Authenticated users**: 50 scans per hour
- **File size limit**: 256KB

If you hit rate limits, the action will automatically retry with exponential backoff.

## Troubleshooting

### Authentication Failed

**Error:** `Authentication failed. Verify your API token has 'scan:write' ability.`

**Solution:**
1. Check your token at https://geekwala.com/dashboard/tokens
2. Ensure the token has `scan:write` permission
3. Verify the secret is named correctly in your repository settings

### No Dependency File Found

**Error:** `No supported dependency files found`

**Solution:**
1. Ensure your repository contains a supported dependency file
2. Use the `file-path` input to specify the file explicitly
3. Check that the file is committed to the repository (not in `.gitignore`)

### File Size Exceeded

**Error:** `File size exceeds maximum allowed size (256KB)`

**Solution:**
1. For large lockfiles, consider scanning the manifest instead
2. Contact GeekWala support to discuss higher limits for enterprise

### Rate Limit Exceeded

**Error:** `Rate limit exceeded (50 scans/hour)`

**Solution:**
1. Space out your scans (avoid running on every commit)
2. Use conditional execution: `if: github.event_name == 'pull_request'`
3. Upgrade to GeekWala Pro for higher limits

## Contributing

Contributions are welcome! Please open an issue or pull request.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- [GeekWala Website](https://geekwala.com)
- [API Documentation](https://geekwala.com/docs/api)
- [Issue Tracker](https://github.com/Geekwala/security-scan-action/issues)
- [GitHub Marketplace](https://github.com/marketplace/actions/geekwala-security-scan)

---

**Powered by GeekWala** • Enriched with EPSS & CISA KEV data
