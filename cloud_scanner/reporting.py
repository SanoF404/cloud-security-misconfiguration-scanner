"""CSV reporting utilities for the cloud security scanner."""

import csv
from pathlib import Path


CSV_FIELDS = [
    "rule_id",
    "severity",
    "title",
    "resource_id",
    "resource_name",
    "recommendation",
]


def export_findings_to_csv(
    findings: list[dict],
    output_path: str | Path,
) -> None:
    """Export security findings to a CSV file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=CSV_FIELDS,
            extrasaction="ignore",
        )
        writer.writeheader()

        for finding in findings:
            writer.writerow({
                field: finding.get(field, "")
                for field in CSV_FIELDS
            })
