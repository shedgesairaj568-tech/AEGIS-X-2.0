"""
Automated database initialization and seeding.
Ensures that when AEGIS-X boots up in cloud environments (Render, Railway, Docker, or local),
the required tables exist and initial admin/analyst credentials and sample alerts are pre-populated.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import select
from app.core.database import Base, engine, AsyncSessionLocal
from app.core.security import hash_password
from app.core.logging import get_logger
from app.models.user import User
from app.models.alert import Alert
from app.models.response_action import ResponseAction

logger = get_logger(__name__)


async def init_db_and_seed() -> None:
    """Initialize database tables and seed baseline accounts and alerts if empty."""
    try:
        # 1. Create tables if they do not exist
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # 2. Seed baseline accounts
        async with AsyncSessionLocal() as session:
            admin_query = await session.execute(select(User).where(User.email == "admin@aegis-x.io"))
            admin_user = admin_query.scalar_one_or_none()
            default_hash = hash_password("changeme123")

            if not admin_user:
                admin_user = User(
                    id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
                    email="admin@aegis-x.io",
                    full_name="Dr. Sarah Connor (Chief Security Officer)",
                    hashed_password=default_hash,
                    role="admin",
                    is_active=True,
                )
                session.add(admin_user)
                logger.info("Seeded administrator account: admin@aegis-x.io")

            analyst_query = await session.execute(select(User).where(User.email == "analyst@aegis-x.io"))
            analyst_user = analyst_query.scalar_one_or_none()
            if not analyst_user:
                analyst_user = User(
                    id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
                    email="analyst@aegis-x.io",
                    full_name="Alex Vance (Lead SOC Analyst)",
                    hashed_password=default_hash,
                    role="analyst",
                    is_active=True,
                )
                session.add(analyst_user)
                logger.info("Seeded analyst account: analyst@aegis-x.io")

            # 3. Seed baseline sample alerts if database has none
            alert_count = await session.execute(select(Alert))
            if not alert_count.scalars().first():
                sample_alert_1 = Alert(
                    id=uuid.UUID("44444444-4444-4444-4444-444444444444"),
                    title="Distributed SSH Brute-Force Velocity Anomaly",
                    description="Multiple failed SSH authentication attempts detected from 91.240.118.172 targeting host gateway port 22.",
                    source="linux_auth",
                    attack_type="brute_force",
                    status="open",
                    severity="high",
                    anomaly_score=0.88,
                    risk_score=86.5,
                    confidence=0.94,
                    source_ip="91.240.118.172",
                    destination_ip="192.168.1.10",
                    source_port=54210,
                    destination_port=22,
                    protocol="TCP",
                    mitre_technique_id="T1110.001",
                    mitre_technique_name="Password Guessing",
                    detected_at=datetime.now(timezone.utc),
                )
                sample_alert_2 = Alert(
                    id=uuid.UUID("55555555-5555-5555-5555-555555555555"),
                    title="Suspicious Remote PowerShell Execution via WMI",
                    description="Process powershell.exe invoked with encoded command line flags attempting LSASS memory dump.",
                    source="windows_events",
                    attack_type="lateral_movement",
                    status="open",
                    severity="critical",
                    anomaly_score=0.96,
                    risk_score=94.2,
                    confidence=0.98,
                    source_ip="10.0.4.15",
                    destination_ip="10.0.4.50",
                    source_port=49152,
                    destination_port=135,
                    protocol="TCP",
                    mitre_technique_id="T1059.001",
                    mitre_technique_name="PowerShell Execution",
                    detected_at=datetime.now(timezone.utc),
                )
                session.add_all([sample_alert_1, sample_alert_2])

                # Seed sample staged containment action
                sample_action = ResponseAction(
                    id=uuid.UUID("66666666-6666-6666-6666-666666666666"),
                    alert_id=sample_alert_1.id,
                    action_type="block_ip",
                    target="91.240.118.172",
                    status="pending_approval",
                    required_role="analyst",
                    blast_radius="MEDIUM",
                    description="Block external adversary source IP 91.240.118.172 on perimeter firewall.",
                    rationale="Mitigates active brute-force password guessing targeting SSH bastion.",
                    rollback_plan="Remove firewall drop rule via iptables -D INPUT -s 91.240.118.172 -j DROP.",
                    created_by="ai_response_agent",
                )
                session.add(sample_action)
                logger.info("Seeded initial baseline security alerts and response proposals.")

            await session.commit()
            logger.info("Database initialization and seed verification complete.")
    except Exception as e:
        logger.error("Error during init_db_and_seed: %s", e)
