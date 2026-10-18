# Cloud Security Misconfiguration Scanner

A Python-based defensive security tool that identifies selected cloud configuration risks in local JSON files and checks Amazon S3 bucket public-access protections through the AWS API.

The project focuses on cloud security fundamentals, read-only inspection, automated testing, and actionable remediation guidance.

## Features

- Analyzes local JSON configurations for selected security misconfigurations.
- Detects publicly exposed storage configurations in supported JSON input.
- Identifies storage configurations with encryption disabled.
- Detects SSH ingress rules open to the internet.
- Inspects Amazon S3 bucket-level Block Public Access settings using Boto3.
- Generates CSV reports for findings from the local configuration scanner.
- Includes automated tests for detection rules, validation, reporting, and simulated AWS responses.
- Performs read-only AWS API operations; it does not modify cloud resources.

## Security Checks

### Local JSON scanner

| Rule ID | Severity | Description |
|---|---|---|
| CLOUD001 | CRITICAL | Public storage access in the supplied configuration |
| CLOUD002 | HIGH | Storage encryption disabled in the supplied configuration |
| CLOUD003 | HIGH | SSH exposed to `0.0.0.0/0` |

These checks analyze the supplied JSON data. They do not independently verify the live state of cloud resources.

### AWS S3 scanner

| Rule ID | Severity | Description |
|---|---|---|
| AWS-S3-001 | HIGH | S3 bucket-level Block Public Access settings are incomplete or not configured |

The AWS scanner checks these four settings:

- `BlockPublicAcls`
- `IgnorePublicAcls`
- `BlockPublicPolicy`
- `RestrictPublicBuckets`

A finding indicates that the bucket-level protections need review. It does not, by itself, prove that the bucket is publicly accessible.

## Project Structure

```text
cloud-security-scanner/
├── cloud_scanner/
│   ├── __init__.py
│   ├── scanner.py
│   ├── reporting.py
│   └── aws_scanner.py
├── examples/
│   └── cloud_config.json
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   ├── test_reporting.py
│   └── test_aws_scanner.py
├── reports/
├── main.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Requirements

- Python 3.10 or newer recommended.
- Boto3, installed through `requirements.txt`, for AWS API access.
- AWS credentials and appropriate read permissions are required only when running the live AWS scanner.

## Installation

Create and activate a virtual environment.

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Usage

### Scan a local JSON configuration

Run the existing configuration scanner:

```powershell
python main.py
```

Export its findings to CSV:

```powershell
python main.py --csv reports/security_findings.csv
```

### Scan Amazon S3

The AWS scanner module is currently available for programmatic use. Once AWS credentials have been configured through an approved AWS authentication method, it can be called from Python:

```python
from cloud_scanner.aws_scanner import scan_s3

findings = scan_s3()

for finding in findings:
    print(finding)
```

This operation uses AWS API calls to list buckets and retrieve bucket-level public-access settings. It does not create, update, or delete AWS resources.

The AWS module is separate from the existing `main.py` JSON workflow; the current CLI does not yet expose a dedicated AWS scanning command.

## Running the Tests

Run the complete test suite:

```powershell
python -m unittest discover -s tests -v
```

The tests use simulated AWS client responses and do not require a live AWS account.

## Current Limitations

- The local JSON scanner evaluates only the configuration data provided to it.
- The AWS scanner checks bucket-level S3 Block Public Access settings only.
- It does not yet inspect S3 bucket policies, object ACLs, account-level public-access settings, or bucket encryption.
- It does not currently assess other AWS services or other cloud providers.
- The AWS scanner and local JSON scanner have separate workflows.
- A successful scan is not a guarantee that a cloud environment is secure.
- AWS permission errors are reported as scan failures rather than being treated as evidence that a resource is secure or insecure.

## Roadmap

- Add tests for additional AWS API response edge cases.
- Integrate AWS scanning into a dedicated CLI command.
- Inspect bucket policies and account-level public-access settings.
- Add checks for S3 encryption and other relevant security controls.
- Improve structured reporting and remediation guidance.
- Expand supported AWS services after validating each security rule.

## Disclaimer

This project is intended for educational purposes and authorized defensive security analysis. Use it only on cloud accounts and configurations you are authorized to inspect. The scanner is not a substitute for a comprehensive security audit.

## Example: Local Configuration Scan

The local demonstration uses fictional JSON configuration data and may report public storage access, disabled encryption, and SSH exposed to the internet.

These findings come from the supplied example configuration; they are not observations of live AWS resources.