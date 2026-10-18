
"""Read-only AWS S3 security scanner."""

import boto3
from botocore.exceptions import BotoCoreError, ClientError


PUBLIC_ACCESS_SETTINGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


def scan_s3(client=None):
    """Inspect S3 Block Public Access settings without changing resources."""
    findings = []

    try:
        if client is None:
            client = boto3.client("s3")

        response = client.list_buckets()
        buckets = response.get("Buckets", [])

        if not isinstance(buckets, list):
            raise RuntimeError(
                "AWS S3 scan failed: invalid ListBuckets response."
            )

        for bucket in buckets:
            if not isinstance(bucket, dict) or not bucket.get("Name"):
                raise RuntimeError(
                    "AWS S3 scan failed: invalid bucket entry."
                )

            bucket_name = bucket["Name"]

            try:
                result = client.get_public_access_block(
                    Bucket=bucket_name
                )

            except ClientError as error:
                code = error.response.get("Error", {}).get("Code", "")

                if code == "NoSuchPublicAccessBlockConfiguration":
                    findings.append({
                        "rule_id": "AWS-S3-001",
                        "severity": "HIGH",
                        "resource_id": bucket_name,
                        "resource_name": bucket_name,
                        "title": "S3 public access protections not configured",
                        "recommendation": (
                            "Review and configure all four S3 Block Public "
                            "Access settings."
                        ),
                    })
                    continue

                raise

            settings = result.get("PublicAccessBlockConfiguration")

            if not isinstance(settings, dict):
                raise RuntimeError(
                    "AWS S3 scan failed: missing or invalid public access "
                    f"configuration response for bucket {bucket_name!r}."
                )

            if not all(
                settings.get(key) is True
                for key in PUBLIC_ACCESS_SETTINGS
            ):
                findings.append({
                    "rule_id": "AWS-S3-001",
                    "severity": "HIGH",
                    "resource_id": bucket_name,
                    "resource_name": bucket_name,
                    "title": "S3 public access protections incomplete",
                    "recommendation": (
                        "Review all four S3 Block Public Access settings."
                    ),
                })

    except (BotoCoreError, ClientError) as error:
        raise RuntimeError(
            f"AWS S3 scan failed: {error}"
        ) from error

    return findings
