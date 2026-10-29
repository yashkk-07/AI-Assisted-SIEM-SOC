"""
SIEM Multi-Event Correlation Engine
Evaluates streaming logs against rules, tracks stateful sequence windows,
deduplicates alerts, calculates threat prioritization, and clusters alerts into Incidents.
"""

import json
import uuid
import re
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Tuple
from sqlalchemy.orm import Session

from models import LogModel, AlertModel, IncidentModel
from correlation.mitre import get_mitre_info
from correlation.prioritizer import calculate_risk_score
from correlation.deduplicator import deduplicator_instance

class CorrelationEngine:
    def __init__(self):
        # In-memory sliding state for sequence & threshold tracking
        # key: (rule_id, entity_key) -> list of (timestamp, log_id)
        self.stateful_windows: Dict[Tuple[str, str], List[Tuple[datetime, str]]] = {}

    def _clean_window(self, key: Tuple[str, str], max_age_seconds: int):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        cutoff = now - timedelta(seconds=max_age_seconds)
        if key in self.stateful_windows:
            cleaned = []
            for ts, lid in self.stateful_windows[key]:
                naive_ts = ts.replace(tzinfo=None) if hasattr(ts, 'tzinfo') and ts.tzinfo is not None else ts
                if naive_ts >= cutoff:
                    cleaned.append((naive_ts, lid))
            self.stateful_windows[key] = cleaned
            if not self.stateful_windows[key]:
                del self.stateful_windows[key]

    def process_log(self, db: Session, log: LogModel) -> List[AlertModel]:
        """
        Evaluates a log entry against correlation rules.
        Returns a list of created/updated alerts.
        """
        alerts_triggered = []

        # -------------------------------------------------------------
        # Rule 1: Brute Force Authentication (T1110)
        # Condition: 5+ failed logins within 60s for the same IP or User
        # -------------------------------------------------------------
        if log.action == "LOGIN_FAILED" or log.event_id in ["4625", "AUTH_FAILURE", "SSH_FAILED"]:
            entity_key = log.source_ip or log.user or "unknown"
            window_key = ("RULE_BRUTE_FORCE", entity_key)
            self._clean_window(window_key, 60)
            
            if window_key not in self.stateful_windows:
                self.stateful_windows[window_key] = []
            self.stateful_windows[window_key].append((log.timestamp, log.id))

            failure_count = len(self.stateful_windows[window_key])
            if failure_count >= 5:
                correlated_ids = [lid for _, lid in self.stateful_windows[window_key]]
                alert = self._trigger_alert(
                    db=db,
                    rule_id="RULE_BRUTE_FORCE",
                    title=f"Brute Force Authentication Campaign ({entity_key})",
                    description=f"Detected {failure_count} rapid authentication failures within 60 seconds from {log.source_ip or 'unknown'} targeting {log.user or 'users'}.",
                    base_severity="HIGH",
                    category="Brute Force",
                    mitre_technique_id="T1110",
                    source_ip=log.source_ip,
                    destination_ip=log.destination_ip,
                    affected_user=log.user,
                    affected_host=log.host,
                    log_ids=correlated_ids,
                    current_log=log
                )
                if alert:
                    alerts_triggered.append(alert)

        # -------------------------------------------------------------
        # Rule 2: Account Takeover Indicator (T1078)
        # Condition: Successful login after multiple recent failures
        # -------------------------------------------------------------
        if log.action in ["LOGIN_SUCCESS", "AUTH_SUCCESS"] or log.event_id in ["4624", "SSH_SUCCESS"]:
            entity_key = log.user or log.source_ip
            if entity_key:
                fail_key = ("RULE_BRUTE_FORCE", entity_key)
                self._clean_window(fail_key, 180)
                if fail_key in self.stateful_windows and len(self.stateful_windows[fail_key]) >= 3:
                    recent_fails = len(self.stateful_windows[fail_key])
                    correlated_ids = [lid for _, lid in self.stateful_windows[fail_key]] + [log.id]
                    alert = self._trigger_alert(
                        db=db,
                        rule_id="RULE_ACCOUNT_TAKEOVER",
                        title=f"Account Compromise After Brute Force ({log.user})",
                        description=f"Successful authentication observed for user '{log.user}' immediately following {recent_fails} failed login attempts from IP {log.source_ip}.",
                        base_severity="CRITICAL",
                        category="Credential Access",
                        mitre_technique_id="T1078",
                        source_ip=log.source_ip,
                        destination_ip=log.destination_ip,
                        affected_user=log.user,
                        affected_host=log.host,
                        log_ids=correlated_ids,
                        current_log=log
                    )
                    if alert:
                        alerts_triggered.append(alert)

        # -------------------------------------------------------------
        # Rule 3: Malicious PowerShell / Encoded Execution (T1059.001)
        # -------------------------------------------------------------
        cmd = (log.command_line or "").lower()
        if log.process_name and "powershell" in log.process_name.lower():
            suspicious_tokens = ["-enc", "-encodedcommand", "downloadstring", "iex", "bypass", "windowstyle hidden", "webclient"]
            if any(token in cmd for token in suspicious_tokens):
                alert = self._trigger_alert(
                    db=db,
                    rule_id="RULE_SUSPICIOUS_POWERSHELL",
                    title=f"Obfuscated PowerShell Execution on {log.host}",
                    description=f"Detected suspicious PowerShell invocation with encoded/bypass execution flags: '{log.command_line[:120]}...'",
                    base_severity="HIGH",
                    category="Execution",
                    mitre_technique_id="T1059",
                    source_ip=log.source_ip,
                    destination_ip=log.destination_ip,
                    affected_user=log.user,
                    affected_host=log.host,
                    log_ids=[log.id],
                    current_log=log
                )
                if alert:
                    alerts_triggered.append(alert)

        # -------------------------------------------------------------
        # Rule 4: Web Application Exploitation (SQLi / XSS / LFI) (T1190)
        # -------------------------------------------------------------
        msg = log.message.lower()
        sqli_patterns = ["' or 1=1", "union select", "information_schema", "exec xp_", "sleep(", "waitfor delay"]
        traversal_patterns = ["../../", "..\\..\\", "/etc/passwd", "win.ini"]
        
        if log.source in ["nginx", "apache", "web-gateway"] or log.event_id in ["HTTP_ATTACK", "WAF_ALERT"]:
            is_sqli = any(p in msg for p in sqli_patterns)
            is_lfi = any(p in msg for p in traversal_patterns)
            if is_sqli or is_lfi:
                vuln_type = "SQL Injection" if is_sqli else "Path Traversal"
                alert = self._trigger_alert(
                    db=db,
                    rule_id="RULE_WEB_EXPLOIT",
                    title=f"{vuln_type} Attack Against Web Service",
                    description=f"Inbound HTTP request contained malicious signature ({vuln_type}) from external IP {log.source_ip}: {log.message[:140]}",
                    base_severity="HIGH",
                    category="Web Attack",
                    mitre_technique_id="T1190",
                    source_ip=log.source_ip,
                    destination_ip=log.destination_ip,
                    affected_user=log.user,
                    affected_host=log.host,
                    log_ids=[log.id],
                    current_log=log
                )
                if alert:
                    alerts_triggered.append(alert)

        # -------------------------------------------------------------
        # Rule 5: Internal Lateral Movement (T1021)
        # -------------------------------------------------------------
        if log.event_id in ["4648", "REMOTE_SERVICE", "SMB_LATERAL", "SSH_INTERNAL"]:
            alert = self._trigger_alert(
                db=db,
                rule_id="RULE_LATERAL_MOVEMENT",
                title=f"Internal Lateral Movement to {log.destination_ip or log.host}",
                description=f"Lateral connection initiated from internal host {log.source_ip} to {log.destination_ip or log.host} using protocol credentials for user '{log.user}'.",
                base_severity="HIGH",
                category="Lateral Movement",
                mitre_technique_id="T1021",
                source_ip=log.source_ip,
                destination_ip=log.destination_ip,
                affected_user=log.user,
                affected_host=log.host,
                log_ids=[log.id],
                current_log=log
            )
            if alert:
                alerts_triggered.append(alert)

        # -------------------------------------------------------------
        # Rule 6: Rogue Service Persistence (T1543.003)
        # -------------------------------------------------------------
        if log.event_id in ["7045", "SERVICE_CREATED"]:
            alert = self._trigger_alert(
                db=db,
                rule_id="RULE_PERSISTENCE_SERVICE",
                title=f"Suspicious System Service Installed on {log.host}",
                description=f"New Windows service installed '{log.process_name or 'RogueSvc'}' with executable path '{log.command_line or 'unknown'}' by user '{log.user}'.",
                base_severity="HIGH",
                category="Persistence",
                mitre_technique_id="T1543",
                source_ip=log.source_ip,
                destination_ip=log.destination_ip,
                affected_user=log.user,
                affected_host=log.host,
                log_ids=[log.id],
                current_log=log
            )
            if alert:
                alerts_triggered.append(alert)

        # -------------------------------------------------------------
        # Rule 7: Ransomware Inhibit Recovery / Shadow Copy Purge (T1490)
        # -------------------------------------------------------------
        if "vssadmin" in cmd and "delete" in cmd and "shadows" in cmd:
            alert = self._trigger_alert(
                db=db,
                rule_id="RULE_RANSOMWARE_RECOVERY",
                title=f"Ransomware Indicator: Volume Shadow Copies Purged on {log.host}",
                description=f"Volume shadow copy deletion command executed: '{log.command_line}'. Common precursor to full ransomware payload deployment.",
                base_severity="CRITICAL",
                category="Ransomware Canary",
                mitre_technique_id="T1490",
                source_ip=log.source_ip,
                destination_ip=log.destination_ip,
                affected_user=log.user,
                affected_host=log.host,
                log_ids=[log.id],
                current_log=log
            )
            if alert:
                alerts_triggered.append(alert)

        # -------------------------------------------------------------
        # Rule 8: Data Exfiltration Over Network (T1048)
        # -------------------------------------------------------------
        if log.event_id in ["DATA_EXFIL", "LARGE_OUTBOUND", "FIREWALL_EXFIL"]:
            alert = self._trigger_alert(
                db=db,
                rule_id="RULE_EXFILTRATION",
                title=f"High Volume Data Exfiltration Detected from {log.source_ip}",
                description=f"Anomalous high-volume outbound data transfer detected targeting external host {log.destination_ip}: {log.message}",
                base_severity="CRITICAL",
                category="Data Exfiltration",
                mitre_technique_id="T1048",
                source_ip=log.source_ip,
                destination_ip=log.destination_ip,
                affected_user=log.user,
                affected_host=log.host,
                log_ids=[log.id],
                current_log=log
            )
            if alert:
                alerts_triggered.append(alert)

        return alerts_triggered

    def _trigger_alert(
        self,
        db: Session,
        rule_id: str,
        title: str,
        description: str,
        base_severity: str,
        category: str,
        mitre_technique_id: str,
        source_ip: Optional[str],
        destination_ip: Optional[str],
        affected_user: Optional[str],
        affected_host: Optional[str],
        log_ids: List[str],
        current_log: LogModel
    ) -> Optional[AlertModel]:
        mitre_info = get_mitre_info(mitre_technique_id)
        
        # Deduplication check
        fingerprint = deduplicator_instance.generate_fingerprint(
            category=category,
            rule_id=rule_id,
            source_ip=source_ip,
            destination_ip=destination_ip,
            affected_user=affected_user,
            affected_host=affected_host
        )

        is_dup, existing_alert = deduplicator_instance.process_candidate(
            db=db,
            fingerprint=fingerprint,
            new_alert_data={"base_severity": base_severity},
            log_id=current_log.id
        )

        if is_dup and existing_alert:
            # Check if existing alert is part of an incident and sync
            if existing_alert.incident_id:
                self._sync_incident(db, existing_alert.incident_id, existing_alert)
            return existing_alert

        # Calculate initial risk score & severity
        risk_score, severity, _ = calculate_risk_score(
            base_severity=base_severity,
            mitre_tactic_id=mitre_info.get("tactic_id"),
            affected_host=affected_host,
            affected_user=affected_user,
            duplicate_count=1
        )

        alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"
        cur_time = datetime.now(timezone.utc).replace(tzinfo=None)
        new_alert = AlertModel(
            id=alert_id,
            timestamp=cur_time,
            title=title,
            description=description,
            severity=severity,
            category=category,
            mitre_tactic=mitre_info.get("tactic"),
            mitre_technique_id=mitre_technique_id,
            mitre_technique_name=mitre_info.get("name"),
            risk_score=risk_score,
            source_ip=source_ip,
            destination_ip=destination_ip,
            affected_user=affected_user,
            affected_host=affected_host,
            status="NEW",
            duplicate_count=1,
            dedup_fingerprint=fingerprint,
            first_seen=cur_time,
            last_seen=cur_time,
            correlated_log_ids=json.dumps(log_ids[-30:])
        )

        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)

        # Correlate alert into an existing or new Incident
        self._correlate_to_incident(db, new_alert)
        db.commit()
        db.refresh(new_alert)

        return new_alert

    def _correlate_to_incident(self, db: Session, alert: AlertModel):
        """
        Groups alerts with shared entities (attacker IP, victim host, user) into unified Incidents.
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        recent_cutoff = now - timedelta(hours=6)

        # Find matching open incident
        candidate_incidents = (
            db.query(IncidentModel)
            .filter(
                IncidentModel.status.in_(["NEW", "INVESTIGATING"]),
                IncidentModel.created_at >= recent_cutoff
            )
            .all()
        )

        matching_incident = None
        for inc in candidate_incidents:
            assets = inc.to_dict()["affected_assets"]
            asset_values = [a.get("value") for a in assets if isinstance(a, dict)]
            
            # Check overlap on IP, user, or host
            if (alert.source_ip and alert.source_ip in asset_values) or \
               (alert.destination_ip and alert.destination_ip in asset_values) or \
               (alert.affected_host and alert.affected_host in asset_values) or \
               (alert.affected_user and alert.affected_user in asset_values):
                matching_incident = inc
                break

        if matching_incident:
            # Correlate into existing incident
            alert.incident_id = matching_incident.id
            self._sync_incident(db, matching_incident.id, alert)
        elif alert.severity in ["HIGH", "CRITICAL"]:
            # Spawn a new incident for significant threat detections
            self._create_new_incident(db, alert)

    def _create_new_incident(self, db: Session, initial_alert: AlertModel):
        incident_id = f"INC-{datetime.now().year}-{uuid.uuid4().hex[:6].upper()}"
        initial_alert.incident_id = incident_id

        assets = []
        if initial_alert.source_ip:
            assets.append({"type": "IP_ATTACKER", "value": initial_alert.source_ip})
        if initial_alert.destination_ip:
            assets.append({"type": "IP_TARGET", "value": initial_alert.destination_ip})
        if initial_alert.affected_host:
            assets.append({"type": "HOST", "value": initial_alert.affected_host})
        if initial_alert.affected_user:
            assets.append({"type": "USER", "value": initial_alert.affected_user})

        tactics = [initial_alert.mitre_tactic] if initial_alert.mitre_tactic else []
        techniques = [f"{initial_alert.mitre_technique_id} ({initial_alert.mitre_technique_name})"] if initial_alert.mitre_technique_id else []

        initial_timeline = [{
            "timestamp": initial_alert.timestamp.isoformat() if initial_alert.timestamp else datetime.now(timezone.utc).isoformat(),
            "stage": initial_alert.mitre_tactic or "Detection",
            "title": initial_alert.title,
            "description": initial_alert.description,
            "severity": initial_alert.severity,
            "alert_id": initial_alert.id
        }]

        # Standard initial containment playbook items
        playbook = [
            {"step": 1, "action": f"Isolate affected host: {initial_alert.affected_host or 'N/A'}", "completed": False, "category": "Containment"},
            {"step": 2, "action": f"Block malicious IP at perimeter firewall: {initial_alert.source_ip or 'N/A'}", "completed": False, "category": "Perimeter"},
            {"step": 3, "action": f"Force password reset and revoke session tokens for: {initial_alert.affected_user or 'affected accounts'}", "completed": False, "category": "Identity"},
            {"step": 4, "action": "Collect volatile memory and system event logs for forensics", "completed": False, "category": "Forensics"},
            {"step": 5, "action": "Verify and restore affected systems from safe offline backups", "completed": False, "category": "Recovery"}
        ]

        now_time = datetime.now(timezone.utc).replace(tzinfo=None)
        incident = IncidentModel(
            id=incident_id,
            title=f"Multi-Stage Security Threat: {initial_alert.category} on {initial_alert.affected_host or initial_alert.affected_user or 'Network'}",
            severity=initial_alert.severity,
            status="NEW",
            created_at=now_time,
            updated_at=now_time,
            assigned_analyst="SentinelAI Autonomous SOC",
            threat_score=initial_alert.risk_score,
            tactics_observed=json.dumps(tactics),
            techniques_observed=json.dumps(techniques),
            affected_assets=json.dumps(assets),
            alert_ids=json.dumps([initial_alert.id]),
            summary=f"Automated alert correlation detected {initial_alert.title}. Initial vector aligns with MITRE technique {initial_alert.mitre_technique_id}.",
            root_cause=f"Potential unauthorized access attempt observed from source {initial_alert.source_ip or 'internal actor'}.",
            blast_radius=f"Target: {initial_alert.affected_host or 'host'}, Account: {initial_alert.affected_user or 'user'}.",
            ai_confidence=88,
            playbook=json.dumps(playbook),
            timeline=json.dumps(initial_timeline)
        )

        db.add(incident)
        db.commit()
        db.refresh(incident)

    def _sync_incident(self, db: Session, incident_id: str, new_alert: AlertModel):
        incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
        if not incident:
            return

        inc_dict = incident.to_dict()
        alert_ids = inc_dict["alert_ids"]
        if new_alert.id not in alert_ids:
            alert_ids.append(new_alert.id)

        # Update tactics & techniques
        tactics = inc_dict["tactics_observed"]
        if new_alert.mitre_tactic and new_alert.mitre_tactic not in tactics:
            tactics.append(new_alert.mitre_tactic)

        techniques = inc_dict["techniques_observed"]
        tech_label = f"{new_alert.mitre_technique_id} ({new_alert.mitre_technique_name})"
        if new_alert.mitre_technique_id and tech_label not in techniques:
            techniques.append(tech_label)

        # Update timeline
        timeline = inc_dict["timeline"]
        timeline.append({
            "timestamp": new_alert.timestamp.isoformat() if new_alert.timestamp else datetime.now(timezone.utc).isoformat(),
            "stage": new_alert.mitre_tactic or "Escalation",
            "title": new_alert.title,
            "description": new_alert.description,
            "severity": new_alert.severity,
            "alert_id": new_alert.id
        })

        # Update assets
        assets = inc_dict["affected_assets"]
        existing_values = [a.get("value") for a in assets if isinstance(a, dict)]
        if new_alert.source_ip and new_alert.source_ip not in existing_values:
            assets.append({"type": "IP_ATTACKER", "value": new_alert.source_ip})
        if new_alert.destination_ip and new_alert.destination_ip not in existing_values:
            assets.append({"type": "IP_TARGET", "value": new_alert.destination_ip})
        if new_alert.affected_host and new_alert.affected_host not in existing_values:
            assets.append({"type": "HOST", "value": new_alert.affected_host})
        if new_alert.affected_user and new_alert.affected_user not in existing_values:
            assets.append({"type": "USER", "value": new_alert.affected_user})

        # Multi-stage attack progression escalates incident threat score
        stage_boost = len(tactics) * 8
        incident.threat_score = min(100, max(incident.threat_score, new_alert.risk_score) + stage_boost)
        if incident.threat_score >= 85:
            incident.severity = "CRITICAL"
        elif incident.threat_score >= 68:
            incident.severity = "HIGH"

        incident.tactics_observed = json.dumps(tactics)
        incident.techniques_observed = json.dumps(techniques)
        incident.timeline = json.dumps(timeline)
        incident.affected_assets = json.dumps(assets)
        incident.alert_ids = json.dumps(alert_ids)
        incident.updated_at = datetime.now(timezone.utc)

        db.commit()

correlation_engine_instance = CorrelationEngine()
