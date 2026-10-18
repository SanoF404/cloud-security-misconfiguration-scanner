
import unittest
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from cloud_scanner.aws_scanner import scan_s3


class TestAwsScanner(unittest.TestCase):

    def setUp(self):
        self.client = MagicMock()
        self.client.list_buckets.return_value = {
            "Buckets": [{"Name": "test-bucket"}]
        }

    def test_secure_bucket_has_no_findings(self):
        self.client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

        findings = scan_s3(client=self.client)

        self.assertEqual(findings, [])

    def test_incomplete_protection_is_detected(self):
        self.client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": True,
            }
        }

        findings = scan_s3(client=self.client)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "AWS-S3-001")
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_missing_protection_is_detected(self):
        self.client.get_public_access_block.side_effect = ClientError(
            {
                "Error": {
                    "Code": "NoSuchPublicAccessBlockConfiguration",
                    "Message": "Configuration not found",
                }
            },
            "GetPublicAccessBlock",
        )

        findings = scan_s3(client=self.client)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["resource_id"], "test-bucket")

    def test_access_denied_raises_runtime_error(self):
        self.client.get_public_access_block.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "Access denied",
                }
            },
            "GetPublicAccessBlock",
        )

        with self.assertRaisesRegex(RuntimeError, "AWS S3 scan failed"):
            scan_s3(client=self.client)
    def test_invalid_public_access_response_raises_error(self):
        self.client.get_public_access_block.return_value = {}

        with self.assertRaisesRegex(
            RuntimeError,
            "missing or invalid public access configuration",
        ):
            scan_s3(client=self.client)

if __name__ == "__main__":
    unittest.main()
