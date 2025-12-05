"""
Database models for the CyberGrid controller backend.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Generator

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.engine import Engine
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import Mapped, Session, relationship, sessionmaker

DATABASE_URL = os.getenv("CYBERGRID_DB_URL", "sqlite:///cybergrid.db")


class CustomBase:
    """
    Base mixin that injects table naming conventions and primary key.
    """

    @declared_attr.directive
    def __tablename__(cls) -> str:  # type: ignore[misc]
        return cls.__name__.lower()

    id: Mapped[int] = Column(Integer, primary_key=True, autoincrement=True)  # type: ignore[assignment]
    created_at: Mapped[datetime] = Column(DateTime, default=datetime.utcnow, nullable=False)  # type: ignore[assignment]
    updated_at: Mapped[datetime] = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )  # type: ignore[assignment]


Base = declarative_base(cls=CustomBase)


def get_engine(echo: bool = False) -> Engine:
    return create_engine(DATABASE_URL, echo=echo, future=True)


SessionLocal = sessionmaker(bind=get_engine(), autoflush=False, autocommit=False, future=True)


def get_session() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


class User(Base):
    username: Mapped[str] = Column(String(64), unique=True, nullable=False)  # type: ignore[assignment]
    password_hash: Mapped[str] = Column(String(255), nullable=False)  # type: ignore[assignment]
    role: Mapped[str] = Column(String(32), nullable=False, default="operator")  # type: ignore[assignment]
    is_active: Mapped[bool] = Column(Boolean, default=True, nullable=False)  # type: ignore[assignment]

    events: Mapped[list["SecurityEvent"]] = relationship("SecurityEvent", back_populates="actor")


class MicrogridComponent(Base):
    name: Mapped[str] = Column(String(120), unique=True, nullable=False)  # type: ignore[assignment]
    component_type: Mapped[str] = Column(String(64), nullable=False)  # type: ignore[assignment]
    firmware_version: Mapped[str] = Column(String(64), nullable=False)  # type: ignore[assignment]
    ip_address: Mapped[str] = Column(String(45), nullable=False)  # type: ignore[assignment]
    criticality: Mapped[str] = Column(String(32), nullable=False, default="medium")  # type: ignore[assignment]

    telemetry_records: Mapped[list["TelemetryRecord"]] = relationship("TelemetryRecord", back_populates="component")
    patches: Mapped[list["PatchStatus"]] = relationship("PatchStatus", back_populates="component")


class TelemetryRecord(Base):
    component_id: Mapped[int] = Column(Integer, ForeignKey("microgridcomponent.id"), nullable=False)  # type: ignore[assignment]
    payload: Mapped[dict] = Column(JSON, nullable=False)  # type: ignore[assignment]
    severity: Mapped[str] = Column(String(32), default="normal", nullable=False)  # type: ignore[assignment]

    component: Mapped["MicrogridComponent"] = relationship("MicrogridComponent", back_populates="telemetry_records")


class SecurityEvent(Base):
    severity: Mapped[str] = Column(
        Enum("info", "low", "medium", "high", "critical", name="severity_enum"),
        default="info",
        nullable=False,
    )  # type: ignore[assignment]
    category: Mapped[str] = Column(String(64), nullable=False)  # type: ignore[assignment]
    details: Mapped[str] = Column(Text, nullable=False)  # type: ignore[assignment]
    actor_id: Mapped[int | None] = Column(Integer, ForeignKey("user.id"), nullable=True)  # type: ignore[assignment]
    context: Mapped[dict | None] = Column(JSON, nullable=True)  # type: ignore[assignment]

    actor: Mapped["User"] = relationship("User", back_populates="events")


class PatchStatus(Base):
    component_id: Mapped[int] = Column(Integer, ForeignKey("microgridcomponent.id"), nullable=False)  # type: ignore[assignment]
    version: Mapped[str] = Column(String(64), nullable=False)  # type: ignore[assignment]
    status: Mapped[str] = Column(
        Enum("pending", "in_progress", "success", "failed", name="patch_status_enum"),
        default="pending",
        nullable=False,
    )  # type: ignore[assignment]
    requested_by: Mapped[str] = Column(String(64), nullable=False)  # type: ignore[assignment]
    notes: Mapped[str | None] = Column(Text, nullable=True)  # type: ignore[assignment]

    component: Mapped["MicrogridComponent"] = relationship("MicrogridComponent", back_populates="patches")


def init_db(echo: bool = False) -> None:
    engine = get_engine(echo=echo)
    Base.metadata.create_all(engine)


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record) -> None:  # type: ignore[unused-argument]
    """
    Enable foreign key support for SQLite connections.
    """
    if "sqlite" in DATABASE_URL:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

