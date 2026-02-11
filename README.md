# GeekWala Security Scan Action

[![Test](https://github.com/Geekwala/security-scan-action/actions/workflows/test.yml/badge.svg)](https://github.com/Geekwala/security-scan-action/actions/workflows/test.yml)
[![Coverage](https://img.shields.io/badge/coverage-85%25+-brightgreen.svg)](https://github.com/Geekwala/security-scan-action)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-GeekWala%20Security%20Scan-blue.svg)](https://github.com/marketplace/actions/geekwala-security-scan)

GitHub Action to scan your dependencies for known vulnerabilities using the [GeekWala](https://geekwala.com) API, enriched with **EPSS** (Exploit Prediction Scoring System) and **CISA KEV** (Known Exploited Vulnerabilities) data.

## Why GeekWala?

| Feature | GeekWala | Trivy | Grype | Snyk |
|---------|----------|-------|-------|------|
| EPSS scores | Native | No | No | No |
| CISA KEV flags | Native | Partial | No | No |
| Fail on exploited vulns (`fail-on-kev`) | Yes | No | No | No |
| EPSS-based gates (`epss-threshold`) | Yes | No | No | No |
| SARIF output | Yes | Yes | Yes | Yes |
| Vulnerability suppression | Yes | Yes | Yes | Yes |
| Free tier | Yes | Yes | Yes | Limited |

**GeekWala's unique edge**: Native EPSS + CISA KEV enrichment with actionable CI/CD gates. Fail on actually-exploited vulnerabilities, not just CVSS scores.

## Quick Start

```yaml
- uses: geekwala/security-scan-action@v1
  with:
    api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `api-token` | GeekWala API token with `scan:write` ability | **Yes** | - |
| `file-path` | Path to dependency file (auto-detected if omitted) | No | Auto-detect |
| `severity-threshold` | Minimum severity that triggers failure: `none`, `low`, `medium`, `high`, `critical` | No | `critical` (via legacy `fail-on-critical`) |
| `fail-on-kev` | Fail if any CISA Known Exploited Vulnerability found | No | `false` |
| `epss-threshold` | Fail if any vulnerability EPSS score exceeds this (0.0-1.0) | No | Disabled |
| `only-fixed` | Only count vulnerabilities with known fixes toward failure | No | `false` |
| `sarif-file` | Path to save SARIF file for GitHub Code Scanning | No | Disabled |
| `ignore-file` | Path to ignore config YAML (empty string to disable) | No | `.geekwala-ignore.yml` |
| `output-format` | Comma-separated: `summary`, `json`, `table` | No | `summary` |
| `json-file` | Path to save JSON report | No | Disabled |
| `fail-on-critical` | *(Legacy)* Fail on critical vulns. Use `severity-threshold` instead. | No | `true` |
| `fail-on-high` | *(Legacy)* Fail on high vulns. Use `severity-threshold` instead. | No | `false` |
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
| `unknown-count` | Number of vulnerabilities with unknown severity | `0` |
| `scan-status` | Overall scan status: `PASS`, `FAIL`, or `ERROR` | `PASS` |
| `has-vulnerabilities` | Boolean indicating if vulnerabilities were found | `true` |
| `ignored-count` | Number of suppressed vulnerabilities | `2` |
| `sarif-file` | Path to generated SARIF file | `results.sarif` |

## Example Workflows

### Basic Scan

```yaml
- uses: geekwala/security-scan-action@v1
  with:
    api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
```

### Strict Security Gate

Fail on any high+ vulnerability and any known-exploited vulnerability:

```yaml
- uses: geekwala/security-scan-action@v1
  with:
    api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
    severity-threshold: high
    fail-on-kev: true
```

### SARIF + GitHub Code Scanning

Upload results to GitHub's Security tab. Requires `security-events: write` permission:

```yaml
permissions:
  security-events: write

steps:
  - uses: geekwala/security-scan-action@v1
    id: scan
    with:
      api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
      sarif-file: results.sarif
      severity-threshold: none  # Don't fail, just report

  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: results.sarif
```

### EPSS-Based Filtering

Only fail on vulnerabilities with >30% exploit probability:

```yaml
- uses: geekwala/security-scan-action@v1
  with:
    api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
    epss-threshold: '0.3'
    severity-threshold: none
```

### Warn-Only Mode

Report vulnerabilities without failing the build:

```yaml
- uses: geekwala/security-scan-action@v1
  with:
    api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
    severity-threshold: none
```

### Soft-Fail (Report + Continue)

Report vulnerabilities and mark the step as failed, but don't block the workflow:

```yaml
- uses: geekwala/security-scan-action@v1
  continue-on-error: true
  with:
    api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
    severity-threshold: high
```

### Using an Ignore File

Create `.geekwala-ignore.yml` in your repo root:

```yaml
ignore:
  - id: CVE-2021-23337
    reason: "Not exploitable in our usage of lodash"
    expires: 2027-06-01  # auto-unignore after this date
  - id: GHSA-xxxx-yyyy
    reason: "Accepted risk per security review #42"
```

The action picks it up automatically:

```yaml
- uses: geekwala/security-scan-action@v1
  with:
    api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
```

### Scheduled Weekly Scan

```yaml
name: Weekly Security Scan
on:
  schedule:
    - cron: '0 9 * * 1'  # Every Monday at 9am

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: geekwala/security-scan-action@v1
        with:
          api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
          severity-threshold: low
          fail-on-kev: true
          output-format: summary,table
```

### Only Fail on Fixable Vulnerabilities

```yaml
- uses: geekwala/security-scan-action@v1
  with:
    api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
    severity-threshold: high
    only-fixed: true
```

## Supported Ecosystems

| Ecosystem | Lockfiles (Prioritized) | Manifests |
|-----------|-------------------------|-----------|
| **npm** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `package.json` |
| **Python** | `poetry.lock`, `Pipfile.lock` | `requirements.txt` |
| **PHP** | `composer.lock` | `composer.json` |
| **Go** | `go.sum` | `go.mod` |
| **Rust** | `Cargo.lock` | `Cargo.toml` |
| **Ruby** | `Gemfile.lock` | - |
| **.NET** | `packages.lock.json` | `*.csproj` |

## Getting an API Token

1. Sign up at [geekwala.com](https://geekwala.com)
2. Navigate to [Developers > API Tokens](https://geekwala.com/developers/api-tokens)
3. Create a new token with `scan:write` ability
4. Add the token to your repository secrets as `GEEKWALA_API_TOKEN`

## Troubleshooting

### Authentication Failed
Verify your token at https://geekwala.com/developers/api-tokens and ensure it has `scan:write` permission.

### No Dependency File Found
Ensure your repository contains a supported dependency file, or use the `file-path` input to specify it.

### File Size Exceeded
The file size limit is 512KB for authenticated users. For large lockfiles, consider scanning the manifest instead.

### Rate Limit Exceeded
The rate limit is 50 scans/hour. Space out your scans or use conditional execution (`if: github.event_name == 'pull_request'`). [Upgrade to Pro](https://geekwala.com/pricing) for unlimited monthly scans.

### Monorepo Support
Auto-detection only scans the repository root for dependency files. For monorepos or projects with dependency files in subdirectories, use the `file-path` input to specify the exact path:

```yaml
- uses: geekwala/security-scan-action@v1
  with:
    api-token: ${{ secrets.GEEKWALA_API_TOKEN }}
    file-path: packages/backend/package-lock.json
```

To scan multiple dependency files, use separate steps for each file.

## Contributing

Contributions are welcome! Please open an issue or pull request.

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Powered by [GeekWala](https://geekwala.com)** | Enriched with EPSS & CISA KEV data
