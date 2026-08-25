from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(200), nullable=False)
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("ScanResult", back_populates="owner")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    severity = Column(String(20), default="medium")   # critical | high | medium | low
    status = Column(String(20), default="open")        # open | in_progress | resolved
    cve_id = Column(String(30), nullable=True)
    affected_component = Column(String(200), nullable=False)
    remediation_notes = Column(Text, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", back_populates="scans")
    share_links = relationship(
        "SharedScanLink",
        back_populates="scan",
        cascade="all, delete-orphan",
    )


class SharedScanLink(Base):
    """A time-limited capability granting read-only access to one scan.

    Only a SHA-256 digest of the high-entropy bearer token is retained. This
    prevents a read-only database compromise from immediately exposing every
    active shared report URL.
    """

    __tablename__ = "shared_scan_links"

    id = Column(Integer, primary_key=True)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(200), nullable=True)
    scan_id = Column(Integer, ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False)
    expires_at = Column(DateTime, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("ScanResult", back_populates="share_links")
