"""
database/models.py
==================
SQLAlchemy Core / ORM table definitions.
These mirror the SQL migrations exactly — one source of truth.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(Text, unique=True, nullable=False)
    hashed_pw = Column(Text)
    api_key = Column(Text, unique=True)
    role = Column(String(20), nullable=False, default="analyst")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_login = Column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("role IN ('admin','analyst','viewer')", name="ck_user_role"),
    )


class Setting(Base):
    __tablename__ = "settings"

    key = Column(Text, primary_key=True)
    value_json = Column(JSONB, nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, onupdate=func.now())
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    detected_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    threat_level = Column(String(20), nullable=False)
    anomaly_score = Column(Numeric(8, 4))
    trigger_type = Column(String(50))
    feature_vector = Column(JSONB)
    top_features = Column(JSONB)
    process_id = Column(UUID(as_uuid=True), ForeignKey("processes_snapshot.id", ondelete="SET NULL"))
    network_id = Column(UUID(as_uuid=True), ForeignKey("network_connections.id", ondelete="SET NULL"))
    ml_model_version = Column(String(50))
    is_resolved = Column(Boolean, nullable=False, default=False)
    resolved_at = Column(DateTime(timezone=True))
    notes = Column(Text)

    process = relationship("ProcessSnapshot", foreign_keys=[process_id], lazy="select")
    network = relationship("NetworkConnection", foreign_keys=[network_id], lazy="select")
    response_actions = relationship("ResponseAction", back_populates="threat_event", lazy="select")

    __table_args__ = (
        CheckConstraint("threat_level IN ('Normal','Suspicious','Critical')", name="ck_threat_level"),
        CheckConstraint("trigger_type IN ('process','network','hash_match','yara_match')", name="ck_trigger_type"),
        Index("idx_threat_detected", "detected_at"),
        Index("idx_threat_level", "threat_level"),
    )


class ProcessSnapshot(Base):
    __tablename__ = "processes_snapshot"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    captured_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    pid = Column(Integer, nullable=False)
    name = Column(String(255), nullable=False)
    exe_path = Column(Text)
    exe_hash = Column(String(64))
    cpu_percent = Column(Numeric(5, 2))
    ram_mb = Column(Numeric(10, 2))
    disk_read_mb = Column(Numeric(10, 2))
    disk_write_mb = Column(Numeric(10, 2))
    net_sent_mb = Column(Numeric(10, 2))
    net_recv_mb = Column(Numeric(10, 2))
    start_time = Column(DateTime(timezone=True))
    parent_pid = Column(Integer)
    is_signed = Column(Boolean)
    signer_name = Column(Text)
    status = Column(String(50))
    threat_event_id = Column(UUID(as_uuid=True), ForeignKey("threat_events.id", ondelete="SET NULL"))

    __table_args__ = (
        Index("idx_proc_captured_at", "captured_at"),
        Index("idx_proc_pid", "pid"),
        Index("idx_proc_name", "name"),
    )


class NetworkConnection(Base):
    __tablename__ = "network_connections"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    captured_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    src_ip = Column(INET, nullable=False)
    dst_ip = Column(INET, nullable=False)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(10))
    bytes_sent = Column(BigInteger, default=0)
    bytes_recv = Column(BigInteger, default=0)
    packet_count = Column(Integer, default=0)
    pid = Column(Integer)
    process_name = Column(String(255))
    status = Column(String(50))
    is_suspicious = Column(Boolean, nullable=False, default=False)
    intel_score = Column(Numeric(5, 2))
    threat_event_id = Column(UUID(as_uuid=True), ForeignKey("threat_events.id", ondelete="SET NULL"))

    __table_args__ = (
        Index("idx_net_captured_at", "captured_at"),
        Index("idx_net_dst_ip", "dst_ip"),
    )


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    executed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    action_type = Column(String(50), nullable=False)
    threat_event_id = Column(UUID(as_uuid=True), ForeignKey("threat_events.id", ondelete="SET NULL"))
    target_pid = Column(Integer)
    target_ip = Column(INET)
    firewall_rule = Column(Text)
    actor = Column(String(255), nullable=False)
    status = Column(String(30), nullable=False)
    failure_reason = Column(Text)
    rolled_back = Column(Boolean, nullable=False, default=False)

    threat_event = relationship("ThreatEvent", back_populates="response_actions")

    __table_args__ = (
        CheckConstraint("action_type IN ('kill_process','block_ip','alert')", name="ck_action_type"),
        CheckConstraint(
            "status IN ('success','failed','skipped_protected','pending_confirmation')",
            name="ck_action_status",
        ),
        Index("idx_resp_executed", "executed_at"),
    )


class ResponseRule(Base):
    __tablename__ = "response_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(Text, nullable=False)
    threat_level = Column(String(20), nullable=False)
    action = Column(String(50), nullable=False)
    auto_execute = Column(Boolean, nullable=False, default=False)
    protected_override = Column(Boolean, nullable=False, default=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, onupdate=func.now())

    __table_args__ = (
        CheckConstraint("threat_level IN ('Suspicious','Critical')", name="ck_rule_level"),
        CheckConstraint("action IN ('kill_process','block_ip','alert')", name="ck_rule_action"),
    )


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    logged_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    actor = Column(Text, nullable=False)
    action = Column(Text, nullable=False)
    resource = Column(Text)
    payload = Column(JSONB)
    ip_address = Column(INET)
    outcome = Column(String(20), nullable=False)

    __table_args__ = (
        CheckConstraint("outcome IN ('success','failed','denied')", name="ck_audit_outcome"),
        Index("idx_audit_logged", "logged_at"),
        Index("idx_audit_actor", "actor"),
    )


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    cache_key = Column(Text, primary_key=True)
    intel_type = Column(String(30), nullable=False)
    data_json = Column(JSONB, nullable=False)
    source = Column(String(50), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("idx_ti_cache_expires", "expires_at"),
    )
