import json
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, Float
from database import Base

def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

class LogModel(Base):
    __tablename__ = "logs"

    id = Column(String, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    source = Column(String, index=True)         # windows-security, firewall, auth-linux, nginx, cloudtrail
    event_id = Column(String, index=True)       # e.g., 4625, 4624, 7045, UFW-BLOCK
    severity = Column(String, default="INFO")   # INFO, LOW, MEDIUM, HIGH, CRITICAL
    source_ip = Column(String, nullable=True, index=True)
    destination_ip = Column(String, nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    user = Column(String, nullable=True, index=True)
    host = Column(String, nullable=True, index=True)
    process_name = Column(String, nullable=True)
    command_line = Column(Text, nullable=True)
    action = Column(String, nullable=True)      # LOGIN_FAILED, SERVICE_CREATED, HTTP_REQUEST
    message = Column(Text, nullable=False)
    raw_json = Column(Text, default="{}")

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "event_id": self.event_id,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "user": self.user,
            "host": self.host,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "action": self.action,
            "message": self.message,
            "raw_json": json.loads(self.raw_json) if self.raw_json else {}
        }


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, default="MEDIUM", index=True) # LOW, MEDIUM, HIGH, CRITICAL
    category = Column(String, index=True)                   # Brute Force, Lateral Movement, etc.
    mitre_tactic = Column(String, nullable=True)            # Credential Access, Lateral Movement
    mitre_technique_id = Column(String, nullable=True)      # T1110, T1021
    mitre_technique_name = Column(String, nullable=True)
    risk_score = Column(Integer, default=50)                # 0-100
    source_ip = Column(String, nullable=True, index=True)
    destination_ip = Column(String, nullable=True, index=True)
    affected_user = Column(String, nullable=True, index=True)
    affected_host = Column(String, nullable=True, index=True)
    status = Column(String, default="NEW", index=True)      # NEW, INVESTIGATING, ESCALATED, FALSE_POSITIVE, SUPPRESSED
    duplicate_count = Column(Integer, default=1)
    dedup_fingerprint = Column(String, index=True)
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    correlated_log_ids = Column(Text, default="[]")        # JSON list of string IDs
    incident_id = Column(String, nullable=True, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "risk_score": self.risk_score,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "affected_user": self.affected_user,
            "affected_host": self.affected_host,
            "status": self.status,
            "duplicate_count": self.duplicate_count,
            "dedup_fingerprint": self.dedup_fingerprint,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "correlated_log_ids": json.loads(self.correlated_log_ids) if self.correlated_log_ids else [],
            "incident_id": self.incident_id
        }


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, index=True)      # e.g., INC-2026-001
    title = Column(String, nullable=False)
    severity = Column(String, default="HIGH", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String, default="NEW", index=True)     # NEW, INVESTIGATING, CONTAINED, CLOSED
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    assigned_analyst = Column(String, default="SentinelAI Agent")
    threat_score = Column(Integer, default=75)             # 0 - 100
    tactics_observed = Column(Text, default="[]")          # JSON list
    techniques_observed = Column(Text, default="[]")       # JSON list
    affected_assets = Column(Text, default="[]")           # JSON list of {type, value}
    alert_ids = Column(Text, default="[]")                 # JSON list of Alert IDs
    summary = Column(Text, nullable=True)
    root_cause = Column(Text, nullable=True)
    blast_radius = Column(Text, nullable=True)
    ai_confidence = Column(Integer, default=90)
    playbook = Column(Text, default="[]")                  # JSON list of actions
    timeline = Column(Text, default="[]")                  # JSON list of timeline events

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "assigned_analyst": self.assigned_analyst,
            "threat_score": self.threat_score,
            "tactics_observed": json.loads(self.tactics_observed) if self.tactics_observed else [],
            "techniques_observed": json.loads(self.techniques_observed) if self.techniques_observed else [],
            "affected_assets": json.loads(self.affected_assets) if self.affected_assets else [],
            "alert_ids": json.loads(self.alert_ids) if self.alert_ids else [],
            "summary": self.summary,
            "root_cause": self.root_cause,
            "blast_radius": self.blast_radius,
            "ai_confidence": self.ai_confidence,
            "playbook": json.loads(self.playbook) if self.playbook else [],
            "timeline": json.loads(self.timeline) if self.timeline else []
        }


class RuleModel(Base):
    __tablename__ = "correlation_rules"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, default="MEDIUM")
    category = Column(String)
    mitre_tactic = Column(String)
    mitre_technique = Column(String)
    threshold = Column(Integer, default=5)
    window_seconds = Column(Integer, default=60)
    enabled = Column(Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "enabled": self.enabled
        }


class SettingModel(Base):
    __tablename__ = "settings"

    key = Column(String, primary_key=True)
    value = Column(Text, nullable=False)

    def to_dict(self):
        return {"key": self.key, "value": self.value}
