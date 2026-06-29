from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, String, Integer, DateTime, Boolean, JSON, ForeignKey, select, text
from datetime import datetime, timezone
import hashlib, os, secrets, uuid

import os
os.makedirs("/data", exist_ok=True)

engine = create_async_engine("sqlite+aiosqlite:////data/cyberready.db", echo=False)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass


class Domain(Base):
    __tablename__ = "domains"
    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname    = Column(String, nullable=False, unique=True)
    added_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    next_scan_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_scan_at      = Column(DateTime, nullable=True)
    alerted_fail_ids  = Column(String, nullable=True)  # JSON list of check_ids at last alert


class Host(Base):
    __tablename__ = "hosts"
    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    ip          = Column(String, nullable=False, unique=True)
    hostname    = Column(String, nullable=True)
    mac         = Column(String, nullable=True)
    vendor      = Column(String, nullable=True)
    os_guess    = Column(String, nullable=True)
    open_ports       = Column(JSON, default=list)
    agent_installed  = Column(Boolean, default=False)
    last_seen        = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    flagged          = Column(Boolean, default=False)
    acknowledged     = Column(Boolean, default=False)
    ack_note         = Column(String, nullable=True)
    ack_at           = Column(DateTime, nullable=True)
    last_alert_at    = Column(DateTime, nullable=True)


class ScanResult(Base):
    __tablename__ = "scan_results"
    id           = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    domain_id    = Column(String, ForeignKey("domains.id"), nullable=False)
    scanned_at   = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    check_id     = Column(String, nullable=False)
    status       = Column(String, nullable=False)  # pass/warn/fail/error
    title        = Column(String, nullable=False)
    detail       = Column(String, nullable=False)
    remediation  = Column(String, nullable=False)
    score_impact = Column(Integer, nullable=False)
    raw          = Column(JSON, default=dict)


class Setting(Base):
    __tablename__ = "settings"
    key   = Column(String, primary_key=True)
    value = Column(String, nullable=False)


class MonitoredEmail(Base):
    __tablename__ = "monitored_emails"
    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email         = Column(String, nullable=False, unique=True)
    added_at      = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_check_at = Column(DateTime, nullable=True)
    status        = Column(String, default="pending")  # pending/clean/breached/no_key/error/rate_limited/invalid_key
    breaches      = Column(String, nullable=True)       # JSON list of breach names
    breach_count  = Column(Integer, default=0)


# ── Password hashing (PBKDF2-SHA256, no extra deps) ────────────────────────────

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key  = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex() + ":" + key.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, key_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        key  = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
        return secrets.compare_digest(key.hex(), key_hex)
    except Exception:
        return False


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # migrate existing hosts table — ignore errors if columns already exist
        for sql in [
            "ALTER TABLE hosts ADD COLUMN acknowledged BOOLEAN DEFAULT FALSE",
            "ALTER TABLE hosts ADD COLUMN ack_note TEXT",
            "ALTER TABLE hosts ADD COLUMN ack_at DATETIME",
            "ALTER TABLE hosts ADD COLUMN last_alert_at DATETIME",
            "ALTER TABLE domains ADD COLUMN alerted_fail_ids TEXT",
        ]:
            try:
                await conn.execute(text(sql))
            except Exception:
                pass


async def seed_defaults():
    """Set admin/admin if no credentials exist in DB yet."""
    async with SessionLocal() as db:
        result = await db.execute(select(Setting).where(Setting.key == "auth_username"))
        if not result.scalar_one_or_none():
            db.add(Setting(key="auth_username", value="admin"))
            db.add(Setting(key="auth_password_hash", value=hash_password("admin")))
            await db.commit()


async def get_setting(db: AsyncSession, key: str) -> str | None:
    result = await db.execute(select(Setting).where(Setting.key == key))
    row = result.scalar_one_or_none()
    return row.value if row else None


async def get_db() -> AsyncSession:
    async with SessionLocal() as session:
        yield session
