import unittest

from cloud_scanner.scanner import scan_config


class TestCloudSecurityScanner(unittest.TestCase):

    def test_public_storage_is_detected(self):
        config = {
            "resources": [{
                "id": "storage-1",
                "type": "storage",
                "name": "public-bucket",
                "public_access": True,
                "encryption_enabled": True,
            }]
        }

        findings = scan_config(config)

        self.assertIn("CLOUD001", [f["rule_id"] for f in findings])

    def test_disabled_encryption_is_detected(self):
        config = {
            "resources": [{
                "id": "storage-2",
                "type": "storage",
                "name": "unencrypted-bucket",
                "public_access": False,
                "encryption_enabled": False,
            }]
        }

        findings = scan_config(config)

        self.assertIn("CLOUD002", [f["rule_id"] for f in findings])

    def test_public_ssh_is_detected(self):
        config = {
            "resources": [{
                "id": "network-1",
                "type": "security_group",
                "name": "open-ssh",
                "inbound_rules": [{
                    "protocol": "tcp",
                    "port": 22,
                    "source": "0.0.0.0/0",
                }],
            }]
        }

        findings = scan_config(config)

        self.assertIn("CLOUD003", [f["rule_id"] for f in findings])

    def test_secure_storage_has_no_findings(self):
        config = {
            "resources": [{
                "id": "storage-3",
                "type": "storage",
                "name": "private-bucket",
                "public_access": False,
                "encryption_enabled": True,
            }]
        }

        self.assertEqual(scan_config(config), [])

    def test_public_https_is_not_flagged_by_ssh_rule(self):
        config = {
            "resources": [{
                "id": "network-2",
                "type": "security_group",
                "name": "https-server",
                "inbound_rules": [{
                    "protocol": "tcp",
                    "port": 443,
                    "source": "0.0.0.0/0",
                }],
            }]
        }

        self.assertEqual(scan_config(config), [])

    def test_ssh_restricted_to_trusted_ip_is_not_flagged(self):
        config = {
            "resources": [{
                "id": "network-3",
                "type": "security_group",
                "name": "restricted-ssh",
                "inbound_rules": [{
                    "protocol": "tcp",
                    "port": 22,
                    "source": "203.0.113.10/32",
                }],
            }]
        }

        self.assertEqual(scan_config(config), [])


if __name__ == "__main__":
    unittest.main()

class TestInvalidConfigurations(unittest.TestCase):

    def test_non_object_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_config([])

    def test_missing_resources_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_config({})

    def test_non_object_resource_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_config({"resources": ["invalid-resource"]})

    def test_invalid_inbound_rules_are_rejected(self):
        config = {
            "resources": [{
                "type": "security_group",
                "inbound_rules": "not-a-list",
            }]
        }

        with self.assertRaises(ValueError):
            scan_config(config)
