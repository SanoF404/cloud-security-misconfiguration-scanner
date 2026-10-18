"""Basic cloud security misconfiguration scanner."""


def scan_config(config: dict) -> list[dict]:
    """Validate and analyze cloud resources."""
    if not isinstance(config, dict):
        raise ValueError("Configuration must be a JSON object.")

    resources = config.get("resources")

    if not isinstance(resources, list):
        raise ValueError("'resources' must be a list.")

    for index, resource in enumerate(resources):
        if not isinstance(resource, dict):
            raise ValueError(
                f"Resource at index {index} must be an object."
            )

        if resource.get("type") == "security_group":
            rules = resource.get("inbound_rules", [])

            if not isinstance(rules, list):
                raise ValueError(
                    f"'inbound_rules' for resource at index {index} "
                    "must be a list."
                )

            for rule_index, rule in enumerate(rules):
                if not isinstance(rule, dict):
                    raise ValueError(
                        f"Inbound rule {rule_index} of resource "
                        f"at index {index} must be an object."
                    )

    findings = []

    for resource in resources:
        resource_id = resource.get("id", "unknown")
        resource_name = resource.get("name", "Unnamed resource")
        resource_type = resource.get("type", "")

        # Rule 1: Public storage
        if (
            resource_type == "storage"
            and resource.get("public_access") is True
        ):
            findings.append({
                "rule_id": "CLOUD001",
                "severity": "CRITICAL",
                "resource_id": resource_id,
                "resource_name": resource_name,
                "title": "Public storage access",
                "description": (
                    "The storage resource is configured for public access."
                ),
                "recommendation": (
                    "Disable public access unless it is explicitly required."
                ),
            })

        # Rule 2: Storage without encryption
        if (
            resource_type == "storage"
            and resource.get("encryption_enabled") is False
        ):
            findings.append({
                "rule_id": "CLOUD002",
                "severity": "HIGH",
                "resource_id": resource_id,
                "resource_name": resource_name,
                "title": "Storage encryption disabled",
                "description": (
                    "Encryption at rest is not enabled in this configuration."
                ),
                "recommendation": (
                    "Enable encryption at rest for stored data."
                ),
            })

        # Rule 3: SSH open to every IPv4 address
        if resource_type == "security_group":
            for rule in resource.get("inbound_rules", []):
                if (
                    rule.get("protocol") == "tcp"
                    and rule.get("port") == 22
                    and rule.get("source") == "0.0.0.0/0"
                ):
                    findings.append({
                        "rule_id": "CLOUD003",
                        "severity": "HIGH",
                        "resource_id": resource_id,
                        "resource_name": resource_name,
                        "title": "SSH accessible from anywhere",
                        "description": (
                            "Inbound SSH traffic is allowed from every "
                            "IPv4 address."
                        ),
                        "recommendation": (
                            "Restrict SSH access to trusted IP addresses "
                            "or a secure administrative network."
                        ),
                    })

    return findings
