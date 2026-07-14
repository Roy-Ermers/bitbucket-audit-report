# bitbucket-audit-report

[![License](https://img.shields.io/badge/license-Very%20Open%20License-blue.svg)](LICENSE.md)

A Bitbucket Pipelines utility that automatically runs `pnpm audit --json` and posts the security audit results as a **Code Insights** report and inline annotations directly on your commits and pull requests.

![Bitbucket Code Insights Report](example-report.png)

## Features

- **Pnpm Audit Integration**: Designed to work out-of-the-box with `pnpm` workspace or single-project repositories.
- **Bitbucket Code Insights**: Publishes a security report directly to the commit page with high-level summary statistics (vulnerability status, duration, total dependencies checked).
- **Inline Annotations**: Highlights each security advisory directly on the `package.json` file on your Pull Request diffs with detailed fix recommendations, severity, and URLs.
- **Smart Build Failures**: Can fail your pipeline builds automatically if vulnerabilities are found that exceed your configured threshold.
- **Highly Configurable**: Control maximum acceptable severity, logging filters, and report IDs via standard environment variables.

---

## How It Works

During a Bitbucket Pipelines run, the tool runs `pnpm audit --json`. It parses the JSON output to extract vulnerabilities, maps them to Bitbucket's report severity values, and pushes the summary and detailed code annotations to Bitbucket's built-in REST API (using Bitbucket’s HTTP proxy server).

### Severity Mapping

| `pnpm audit` Severity | Bitbucket Report Severity |
| --------------------- | ------------------------- |
| `info`                | `LOW`                     |
| `low`                 | `LOW`                     |
| `moderate`            | `MEDIUM`                  |
| `high`                | `HIGH`                    |
| `critical`            | `CRITICAL`                |

---

## Configuration

This tool is configured entirely using environment variables.

### Bitbucket-provided Variables (Required)

The following variables are automatically injected by Bitbucket Pipelines:

- `BITBUCKET_BRANCH`
- `BITBUCKET_COMMIT`
- `BITBUCKET_REPO_OWNER`
- `BITBUCKET_REPO_SLUG`

### Customization Variables (Optional)

| Variable              | Description                                                                                                                                                                                                                                                               | Default                               |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| `BPR_LEVEL`           | **Maximum acceptable vulnerability level** to consider the build safe. Valid options are `info`, `low`, `moderate`, `high`, `critical`. If any vulnerability above this level is found, the build report status is marked as `FAILED` and the script exits with code `1`. | `high`                                |
| `BPR_LOG`             | **Annotation severity floor**. If specified, only security advisories at or above this level will be published as inline annotations. Options: `info`, `low`, `moderate`, `high`, `critical`.                                                                             | _None (All advisories are annotated)_ |
| `BPR_NAME`            | The title of the Bitbucket Code Insights report.                                                                                                                                                                                                                          | `Security: npm audit`                 |
| `BPR_ID`              | The unique ID of the Bitbucket Code Insights report.                                                                                                                                                                                                                      | `npmaudit`                            |
| `BPR_PROXY`           | The Bitbucket Pipelines proxy host format. Use `local` for `127.0.0.1` or `pipe` for `host.docker.internal`.                                                                                                                                                              | `local`                               |
| `BPR_MAX_BUFFER_SIZE` | Maximum process stdout buffer size in bytes for spawning the `pnpm audit` command (useful for large mono-repos).                                                                                                                                                          | `10485760` (10MB)                     |

---

## Installation & Usage

Make sure `pnpm` is installed and available in your pipeline execution step environment.

### 1. In Bitbucket Pipelines (`bitbucket-pipelines.yml`)

Add the tool as a pipeline step using `npx`:

```yaml
image: node:20

pipelines:
  default:
    - step:
        name: Security Audit
        script:
          - corepack enable pnpm
          - pnpm dlx bitbucket-audit-report
```

### 2. Customizing Security Thresholds

If you want the build to fail on `moderate` or higher vulnerabilities, and only annotate `high` or `critical` issues:

```yaml
image: node:20

pipelines:
  default:
    - step:
        name: Security Audit
        script:
          - corepack enable pnpm
          - export BPR_LEVEL=low # Fails the build if any moderate, high, or critical issues are found
          - export BPR_LOG=high # Only create inline annotations for high or critical severities
          - pnpm dlx bitbucket-audit-report
```

---

## Limitations

- **Annotation Limit**: Bitbucket Reports API enforces a maximum of **1000 annotations** per report. Any vulnerabilities beyond the first 1000 will be omitted from the inline annotations, but will still count towards the main report status.

---

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on filing pull requests and commit guidelines.

## License

This project is licensed under the terms of the [Very Open License (VOL)](LICENSE.md).
