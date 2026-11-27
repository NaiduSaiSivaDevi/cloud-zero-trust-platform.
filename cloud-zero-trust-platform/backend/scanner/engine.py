from typing import Dict, List

# Sample cloud configuration datasets for DEMO MODE scanning.
# Real cloud accounts are NOT queried unless authorized credentials are configured.
DEMO_CLOUD_DATASETS: Dict[str, Dict[str, List[dict]]] = {
    "AWS": {
        "production": [
            {
                "resource": "arn:aws:s3:::prod-customer-exports",
                "type": "s3_bucket",
                "public_access_block": False,
                "acl": "public-read",
                "tls_min_version": "1.2",
            },
            {
                "resource": "arn:aws:iam::123456789012:policy/DevOpsAdminAll",
                "type": "iam_policy",
                "actions": ["*"],
                "resources": ["*"],
                "effect": "Allow",
            },
            {
                "resource": "arn:aws:iam::123456789012:user/ops-breakglass",
                "type": "iam_user",
                "mfa_enabled": False,
                "is_privileged": True,
            },
            {
                "resource": "arn:aws:iam::123456789012:role/VendorCrossAccountRole",
                "type": "iam_role",
                "external_id_required": False,
                "assumed_by": "*",
                "role_mismatch": True,
            },
            {
                "resource": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0912ab",
                "type": "security_group",
                "ingress_cidr": "0.0.0.0/0",
                "port": 22,
                "tls_min_version": "1.0",
            },
            {
                "resource": "arn:aws:iam::123456789012:policy/FinanceReadConflict",
                "type": "iam_policy_set",
                "conflicting_statements": True,
                "allow_rule": "s3:GetObject on finance-*",
                "deny_rule": "s3:* on finance-pii",
            },
        ],
        "staging": [
            {
                "resource": "arn:aws:s3:::staging-app-logs",
                "type": "s3_bucket",
                "public_access_block": True,
                "acl": "private",
                "tls_min_version": "1.2",
            },
            {
                "resource": "arn:aws:iam::123456789012:user/qa-deploy",
                "type": "iam_user",
                "mfa_enabled": False,
                "is_privileged": True,
            },
            {
                "resource": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-staging",
                "type": "security_group",
                "ingress_cidr": "0.0.0.0/0",
                "port": 3389,
                "tls_min_version": "1.1",
            },
        ],
    },
    "Azure": {
        "production": [
            {
                "resource": "/subscriptions/sub-01/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/prodfinanceblob",
                "type": "storage_account",
                "public_access_block": False,
                "acl": "blob-public",
                "tls_min_version": "1.2",
            },
            {
                "resource": "/subscriptions/sub-01/providers/Microsoft.Authorization/roleAssignments/owner-all",
                "type": "rbac_assignment",
                "actions": ["*"],
                "resources": ["*"],
                "effect": "Allow",
            },
            {
                "resource": "aad-user://sec-admin@contoso.onmicrosoft.com",
                "type": "aad_user",
                "mfa_enabled": False,
                "is_privileged": True,
            },
            {
                "resource": "/subscriptions/sub-01/providers/Microsoft.Network/networkSecurityGroups/nsg-prod-web",
                "type": "nsg",
                "ingress_cidr": "0.0.0.0/0",
                "port": 22,
                "tls_min_version": "1.0",
            },
        ],
        "staging": [
            {
                "resource": "/subscriptions/sub-01/resourceGroups/rg-stage/providers/Microsoft.Storage/storageAccounts/stageassets",
                "type": "storage_account",
                "public_access_block": True,
                "acl": "private",
                "tls_min_version": "1.0",
            },
            {
                "resource": "/subscriptions/sub-01/providers/Microsoft.Authorization/roleDefinitions/conflict-contributor",
                "type": "iam_policy_set",
                "conflicting_statements": True,
                "allow_rule": "Microsoft.Storage/*",
                "deny_rule": "Microsoft.Storage/storageAccounts/blobServices/containers/write",
            },
        ],
    },
    "GCP": {
        "production": [
            {
                "resource": "projects/cloudguard-prod/buckets/gcp-billing-exports",
                "type": "gcs_bucket",
                "public_access_block": False,
                "acl": "allUsers",
                "tls_min_version": "1.2",
            },
            {
                "resource": "projects/cloudguard-prod/serviceAccounts/ci-runner@iam.gserviceaccount.com",
                "type": "iam_role",
                "external_id_required": False,
                "assumed_by": "allAuthenticatedUsers",
                "role_mismatch": True,
            },
            {
                "resource": "projects/cloudguard-prod/policies/org-iam-conflict",
                "type": "iam_policy_set",
                "conflicting_statements": True,
                "allow_rule": "roles/editor",
                "deny_rule": "storage.objects.delete",
            },
            {
                "resource": "projects/cloudguard-prod/users/gcp-org-admin",
                "type": "iam_user",
                "mfa_enabled": False,
                "is_privileged": True,
            },
        ],
        "staging": [
            {
                "resource": "projects/cloudguard-stage/buckets/stage-artifacts",
                "type": "gcs_bucket",
                "public_access_block": True,
                "acl": "private",
                "tls_min_version": "1.2",
            },
            {
                "resource": "projects/cloudguard-stage/global/firewalls/allow-ssh-all",
                "type": "firewall",
                "ingress_cidr": "0.0.0.0/0",
                "port": 22,
                "tls_min_version": "1.1",
            },
        ],
    },
}


def run_configuration_scan(provider_type: str, environment: str) -> dict:
    """
    Evaluate sample cloud configuration resources against 6 security rules.
    Returns total_resources and a list of finding dicts.
    """
    provider_data = DEMO_CLOUD_DATASETS.get(provider_type, DEMO_CLOUD_DATASETS["AWS"])
    resources = provider_data.get(environment, provider_data.get("production", []))

    findings = []
    for item in resources:
        res_name = item["resource"]

        # Rule 1: Public storage exposure
        if item.get("public_access_block") is False or item.get("acl") in {"public-read", "blob-public", "allUsers"}:
            findings.append({
                "provider": provider_type,
                "resource": res_name,
                "rule_id": "ZT-RULE-001",
                "title": "Public Storage Exposure",
                "description": f"Storage resource '{res_name}' allows public access (ACL={item.get('acl')}).",
                "recommendation": "Enable Block Public Access and restrict bucket/container ACLs to private least-privilege roles.",
                "severity": "Critical",
            })

        # Rule 2: Excessive IAM permissions
        if "*" in item.get("actions", []) and "*" in item.get("resources", []):
            findings.append({
                "provider": provider_type,
                "resource": res_name,
                "rule_id": "ZT-RULE-002",
                "title": "Excessive IAM Permissions (Wildcard *:*)",
                "description": f"Policy '{res_name}' grants wildcard '*' actions on '*' resources.",
                "recommendation": "Scope IAM permissions to explicit actions and specific resource ARNs/IDs.",
                "severity": "Critical",
            })

        # Rule 3: Missing required MFA
        if item.get("is_privileged") and item.get("mfa_enabled") is False:
            findings.append({
                "provider": provider_type,
                "resource": res_name,
                "rule_id": "ZT-RULE-003",
                "title": "Missing Required MFA for Privileged Identity",
                "description": f"Privileged account '{res_name}' does not have Multi-Factor Authentication enforced.",
                "recommendation": "Enforce hardware/TOTP MFA before granting access to any sensitive cloud resource.",
                "severity": "High",
            })

        # Rule 4: Incorrect access roles
        if item.get("role_mismatch") or item.get("assumed_by") in {"*", "allAuthenticatedUsers"}:
            findings.append({
                "provider": provider_type,
                "resource": res_name,
                "rule_id": "ZT-RULE-004",
                "title": "Incorrect / Overly Permissive Access Role",
                "description": f"Role '{res_name}' can be assumed broadly ({item.get('assumed_by')}) without external ID/condition.",
                "recommendation": "Restrict trust policy principals and require ExternalId or strict identity conditions.",
                "severity": "High",
            })

        # Rule 5: Weak security policies (TLS < 1.2 or open admin ports)
        if item.get("ingress_cidr") == "0.0.0.0/0" and item.get("port") in {22, 3389}:
            findings.append({
                "provider": provider_type,
                "resource": res_name,
                "rule_id": "ZT-RULE-005",
                "title": "Weak Network Access Policy (Open Admin Port)",
                "description": f"Resource '{res_name}' exposes administrative port {item.get('port')} to 0.0.0.0/0.",
                "recommendation": "Restrict ingress to bastion/VPN CIDR blocks or use Zero-Trust identity-aware proxy.",
                "severity": "High",
            })
        elif item.get("tls_min_version") in {"1.0", "1.1"}:
            findings.append({
                "provider": provider_type,
                "resource": res_name,
                "rule_id": "ZT-RULE-005B",
                "title": "Weak Cryptographic Policy (Deprecated TLS)",
                "description": f"Resource '{res_name}' permits deprecated TLS {item.get('tls_min_version')}.",
                "recommendation": "Enforce TLS 1.2 or TLS 1.3 minimum policy.",
                "severity": "Medium",
            })

        # Rule 6: Policy conflicts
        if item.get("conflicting_statements"):
            findings.append({
                "provider": provider_type,
                "resource": res_name,
                "rule_id": "ZT-RULE-006",
                "title": "Access Policy Conflict Detected",
                "description": (
                    f"Conflicting statements in '{res_name}': Allow({item.get('allow_rule')}) "
                    f"overlaps with Deny({item.get('deny_rule')})."
                ),
                "recommendation": "Resolve overlapping Allow/Deny statements into deterministic least-privilege rules.",
                "severity": "Medium",
            })

    return {
        "total_resources": len(resources),
        "findings": findings,
    }
