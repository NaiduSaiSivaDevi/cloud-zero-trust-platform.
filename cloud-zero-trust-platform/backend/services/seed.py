from sqlalchemy.orm import Session
from auth import hash_password
from models import User, CloudProvider, ZeroTrustPolicy, AuditLog


def seed_initial_data(db: Session) -> None:
    if db.query(User).count() == 0:
        users = [
            User(
                email="admin@cloudguard.io",
                full_name="Security Administrator",
                hashed_password=hash_password("admin123"),
                role="admin",
                is_active=True,
            ),
            User(
                email="analyst@cloudguard.io",
                full_name="Cloud Security Analyst",
                hashed_password=hash_password("analyst123"),
                role="analyst",
                is_active=True,
            ),
        ]
        db.add_all(users)

    if db.query(CloudProvider).count() == 0:
        providers = [
            CloudProvider(
                name="AWS Enterprise Demo",
                provider_type="AWS",
                account_id="aws-demo-123456789012",
                environment="production",
                status="connected",
                is_demo=True,
                resource_count=6,
            ),
            CloudProvider(
                name="Microsoft Azure Demo",
                provider_type="Azure",
                account_id="azure-demo-sub-01",
                environment="production",
                status="connected",
                is_demo=True,
                resource_count=4,
            ),
            CloudProvider(
                name="Google Cloud Demo",
                provider_type="GCP",
                account_id="gcp-demo-cloudguard-prod",
                environment="production",
                status="disconnected",
                is_demo=True,
                resource_count=4,
            ),
        ]
        db.add_all(providers)

    if db.query(ZeroTrustPolicy).count() == 0:
        policies = [
            ZeroTrustPolicy(
                name="ZT-MFA-Enforcement",
                description="Require MFA verification for confidential/restricted resources and destructive actions.",
                rule_condition="auth_status != mfa_verified AND sensitivity in [confidential, restricted]",
                effect="DENY",
                priority=10,
                is_active=True,
                is_mandatory=True,
                cpu_cost=1.8,
                memory_mb=38.0,
                latency_ms=8.5,
                monthly_est_cost=42.0,
            ),
            ZeroTrustPolicy(
                name="ZT-Restricted-JIT-Review",
                description="Require security review when non-admin roles request restricted resources.",
                rule_condition="sensitivity == restricted AND role != admin",
                effect="REVIEW",
                priority=20,
                is_active=True,
                is_mandatory=True,
                cpu_cost=2.4,
                memory_mb=48.0,
                latency_ms=14.2,
                monthly_est_cost=58.0,
            ),
            ZeroTrustPolicy(
                name="ZT-Confidential-Write-Guard",
                description="Flag confidential write operations for policy compliance review.",
                rule_condition="sensitivity == confidential AND action == write",
                effect="REVIEW",
                priority=30,
                is_active=True,
                is_mandatory=False,
                cpu_cost=1.2,
                memory_mb=24.0,
                latency_ms=6.4,
                monthly_est_cost=29.0,
            ),
            ZeroTrustPolicy(
                name="ZT-Delete-Admin-Only",
                description="Deny delete actions from non-administrator roles.",
                rule_condition="action == delete AND role != admin",
                effect="DENY",
                priority=15,
                is_active=True,
                is_mandatory=True,
                cpu_cost=1.1,
                memory_mb=22.0,
                latency_ms=5.1,
                monthly_est_cost=24.0,
            ),
        ]
        db.add_all(policies)

    if db.query(AuditLog).count() == 0:
        db.add(
            AuditLog(
                actor_email="system@cloudguard.io",
                action="SYSTEM_INITIALIZED",
                resource="sqlite://cloud_zero_trust.db",
                decision="ALLOW",
                severity="Info",
                details="Database initialized with default DEMO MODE providers, policies, and admin/analyst accounts.",
            )
        )

    db.commit()
