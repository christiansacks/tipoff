from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, String, Integer, DateTime, Boolean, JSON, ForeignKey, select, text
from datetime import datetime, timezone
import hashlib, os, secrets, uuid

import os
os.makedirs("/data", exist_ok=True)

engine = create_async_engine("sqlite+aiosqlite:////data/tipoff.db", echo=False)
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
    whois_alert_sent  = Column(String, nullable=True)  # JSON list of day thresholds already emailed
    public_status     = Column(Boolean, default=False)  # show on public /status page
    uptime_alerted    = Column(Boolean, default=False)  # True while domain is currently down
    is_wordpress      = Column(Boolean, default=False)
    wp_version        = Column(String, nullable=True)
    wp_scan_at        = Column(DateTime, nullable=True)
    wp_scan_results   = Column(JSON, nullable=True)


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
    first_seen       = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen        = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    flagged          = Column(Boolean, default=False)
    acknowledged     = Column(Boolean, default=False)
    ack_note         = Column(String, nullable=True)
    ack_at           = Column(DateTime, nullable=True)
    last_alert_at    = Column(DateTime, nullable=True)
    is_wordpress     = Column(Boolean, default=False)
    wp_version       = Column(String, nullable=True)
    wp_url           = Column(String, nullable=True)
    wp_scan_at       = Column(DateTime, nullable=True)
    wp_scan_results  = Column(JSON, nullable=True)


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


class Monitor(Base):
    __tablename__ = "monitors"
    id              = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name            = Column(String, nullable=False)
    host            = Column(String, nullable=False)
    port            = Column(Integer, nullable=False)
    protocol        = Column(String, nullable=False, default="tcp")  # tcp / http / https
    expected_status = Column(String, nullable=True)   # e.g. "200" "200,301" "2xx" — HTTP only
    enabled         = Column(Boolean, default=True)
    public_status   = Column(Boolean, default=False)
    uptime_alerted  = Column(Boolean, default=False)
    added_at        = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class UptimeCheck(Base):
    __tablename__ = "uptime_checks"
    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    domain_id   = Column(String, ForeignKey("domains.id"), nullable=True)
    monitor_id  = Column(String, ForeignKey("monitors.id"), nullable=True)
    checked_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    is_up       = Column(Boolean, nullable=False)
    response_ms = Column(Integer, nullable=True)
    status_code = Column(Integer, nullable=True)


class Webhook(Base):
    __tablename__ = "webhooks"
    id           = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name         = Column(String, nullable=False)
    url          = Column(String, nullable=False)
    events       = Column(String, nullable=False, default="[]")  # JSON list of event names
    webhook_type = Column(String, nullable=False, default="json")  # json / ntfy
    enabled      = Column(Boolean, default=True)
    added_at     = Column(DateTime, default=lambda: datetime.now(timezone.utc))


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
            "ALTER TABLE hosts ADD COLUMN first_seen DATETIME",
            "ALTER TABLE domains ADD COLUMN alerted_fail_ids TEXT",
            "ALTER TABLE domains ADD COLUMN is_wordpress BOOLEAN DEFAULT FALSE",
            "ALTER TABLE domains ADD COLUMN wp_version TEXT",
            "ALTER TABLE domains ADD COLUMN wp_scan_at DATETIME",
            "ALTER TABLE domains ADD COLUMN wp_scan_results TEXT",
            "ALTER TABLE hosts ADD COLUMN is_wordpress BOOLEAN DEFAULT FALSE",
            "ALTER TABLE hosts ADD COLUMN wp_version TEXT",
            "ALTER TABLE hosts ADD COLUMN wp_url TEXT",
            "ALTER TABLE hosts ADD COLUMN wp_scan_at DATETIME",
            "ALTER TABLE hosts ADD COLUMN wp_scan_results TEXT",
            "ALTER TABLE domains ADD COLUMN whois_alert_sent TEXT",
            "ALTER TABLE domains ADD COLUMN public_status BOOLEAN DEFAULT FALSE",
            "ALTER TABLE domains ADD COLUMN uptime_alerted BOOLEAN DEFAULT FALSE",
            "ALTER TABLE uptime_checks ADD COLUMN monitor_id TEXT",
            "ALTER TABLE webhooks ADD COLUMN webhook_type TEXT DEFAULT 'json'",
        ]:
            try:
                await conn.execute(text(sql))
            except Exception:
                pass

        # Rebuild uptime_checks to make domain_id nullable (SQLite can't ALTER COLUMN)
        try:
            row = await conn.execute(text(
                "SELECT 1 FROM pragma_table_info('uptime_checks') "
                "WHERE name='domain_id' AND \"notnull\"=1"
            ))
            if row.fetchone():
                await conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS uptime_checks_new (
                        id          TEXT PRIMARY KEY,
                        domain_id   TEXT REFERENCES domains(id),
                        monitor_id  TEXT REFERENCES monitors(id),
                        checked_at  DATETIME,
                        is_up       BOOLEAN NOT NULL,
                        response_ms INTEGER,
                        status_code INTEGER
                    )
                """))
                await conn.execute(text(
                    "INSERT INTO uptime_checks_new SELECT id, domain_id, monitor_id, "
                    "checked_at, is_up, response_ms, status_code FROM uptime_checks"
                ))
                await conn.execute(text("DROP TABLE uptime_checks"))
                await conn.execute(text("ALTER TABLE uptime_checks_new RENAME TO uptime_checks"))
        except Exception as e:
            print(f"uptime_checks migration warning: {e}")


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
