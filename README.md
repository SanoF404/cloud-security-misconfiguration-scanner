# Cloud Security Misconfiguration Scanner

A lightweight Python security auditing tool that detects common cloud configuration misconfigurations in JSON files.

This project demonstrates fundamental defensive security concepts, configuration validation, automated testing, and security report generation.

## Features

- Detects publicly accessible cloud storage.
- Identifies storage resources with encryption disabled.
- Detects SSH access exposed to the entire internet.
- Validates configuration file structures.
- Generates CSV reports for security findings.
- Includes automated unit tests.
- Uses only the Python standard library.

## Security Checks

| Rule ID | Severity | Description |
|---|---|---|
| CLOUD001 | CRITICAL | Public storage access |
| CLOUD002 | HIGH | Storage encryption disabled |
| CLOUD003 | HIGH | SSH accessible from anywhere |

## Project Structure

```text
cloud-security-misconfiguration-scanner/
├── cloud_scanner/
│   ├── __init__.py
│   ├── scanner.py
│   └── reporting.py
├── examples/
│   └── cloud_config.json
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   └── test_reporting.py
├── reports/
├── main.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Requirements

- Python 3.10 or newer recommended.
- No third-party Python packages required.

## Usage

Run the scanner with the example configuration:

```powershell
python main.py
```

Export the findings to a CSV report:

```powershell
python main.py --csv reports/security_findings.csv
```

The scanner displays detected security findings and their remediation recommendations.

## Running the Tests

Run the automated test suite:

```powershell
python -m unittest -v
```

The tests cover security detection rules, configuration validation, and CSV report generation.

## Example Findings

The example configuration demonstrates three security issues:

- **CRITICAL:** Public access enabled for a storage resource.
- **HIGH:** Storage encryption disabled.
- **HIGH:** SSH access allowed from any IPv4 address.

## Limitations

This project analyzes local JSON configuration files. It does not connect to AWS or other cloud providers, inspect live infrastructure, or make changes to cloud resources.

The findings are based on the specific rules implemented in this educational version and do not represent a complete cloud security audit.

## Disclaimer

This tool is intended for educational purposes and defensive security analysis. Only analyze configurations you are authorized to inspect.
## Demo

Run the scanner against the example configuration:

```text
Cloud Security Scanner
Configuration: examples\cloud_config.json
Findings detected: 3

[1] CRITICAL - Public storage access
    Rule: CLOUD001
    Resource: company-backups

[2] HIGH - Storage encryption disabled
    Rule: CLOUD002
    Resource: company-backups

[3] HIGH - SSH accessible from anywhere
    Rule: CLOUD003
    Resource: web-server-rules
```

Each finding includes a remediation recommendation. The scanner can also export findings to a CSV report for further analysis.

**Note:** The demonstration uses a fictional local configuration and does not inspect live cloud infrastructure.
