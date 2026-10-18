import csv
import tempfile
import unittest
from pathlib import Path

from cloud_scanner.reporting import export_findings_to_csv


class TestCSVReporting(unittest.TestCase):

    def test_findings_are_exported_to_csv(self):
        findings = [{
            "rule_id": "CLOUD001",
            "severity": "CRITICAL",
            "title": "Public storage access",
            "resource_id": "storage-001",
            "resource_name": "company-backups",
            "recommendation": "Disable public access.",
        }]

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.csv"

            export_findings_to_csv(findings, output_path)

            with output_path.open(
                "r", encoding="utf-8-sig", newline=""
            ) as file:
                rows = list(csv.DictReader(file))

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["rule_id"], "CLOUD001")
            self.assertEqual(rows[0]["severity"], "CRITICAL")
            self.assertEqual(
                rows[0]["resource_name"], "company-backups"
            )

    def test_empty_findings_create_csv_with_headers(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "empty.csv"

            export_findings_to_csv([], output_path)

            with output_path.open(
                "r", encoding="utf-8-sig", newline=""
            ) as file:
                reader = csv.reader(file)
                rows = list(reader)

            self.assertEqual(len(rows), 1)
            self.assertIn("severity", rows[0])
            self.assertIn("recommendation", rows[0])


if __name__ == "__main__":
    unittest.main()
