import argparse
import json
from pathlib import Path

from cloud_scanner.reporting import export_findings_to_csv
from cloud_scanner.scanner import scan_config


def main():
    parser = argparse.ArgumentParser(
        description="Scan cloud configurations for security issues."
    )
    parser.add_argument(
        "config_file",
        nargs="?",
        default="examples/cloud_config.json",
        help="Path to the JSON configuration file.",
    )
    parser.add_argument(
        "--csv",
        dest="csv_path",
        help="Export findings to a CSV file.",
    )
    args = parser.parse_args()

    config_path = Path(args.config_file)

    try:
        with config_path.open("r", encoding="utf-8-sig") as file:
            config = json.load(file)

        findings = scan_config(config)

        if args.csv_path:
            export_findings_to_csv(findings, args.csv_path)

    except FileNotFoundError:
        print(f"Error: file not found: {config_path}")
        return 1
    except json.JSONDecodeError as error:
        print(f"Error: invalid JSON: {error}")
        return 1
    except ValueError as error:
        print(f"Error: invalid configuration: {error}")
        return 1
    except OSError as error:
        print(f"Error: could not read or write a file: {error}")
        return 1

    print("\nCloud Security Scanner")
    print(f"Configuration: {config_path}")
    print(f"Findings detected: {len(findings)}")

    if args.csv_path:
        print(f"CSV report: {args.csv_path}")

    if not findings:
        print("\nNo security issues detected.")
        return 0

    for index, finding in enumerate(findings, start=1):
        print(
            f"\n[{index}] {finding.get('severity', 'UNKNOWN')} - "
            f"{finding.get('title', 'Untitled finding')}"
        )
        print(f"    Rule: {finding.get('rule_id', 'N/A')}")
        print(
            f"    Resource: "
            f"{finding.get('resource_name', 'Unknown')}"
        )
        print(
            f"    Recommendation: "
            f"{finding.get('recommendation', 'No recommendation')}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
