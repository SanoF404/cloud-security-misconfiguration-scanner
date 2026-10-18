# Cloud Security Misconfiguration Scanner

A Python tool that detects common security misconfigurations in example cloud configuration files. It validates JSON input, detects public storage, disabled encryption, and unrestricted SSH access, and exports findings to CSV.

## Usage

```powershell
python main.py
python main.py --csv reports/security_findings.csv
```

## Tests

Run the automated tests with `python -m unittest -v`.

## Limitations

This educational version analyzes local JSON files only. It does not connect to AWS or inspect live cloud resources.
