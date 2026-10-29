"""
Intelligent Alert Deduplication and Suppression Engine
Filters noise, prevents alert fatigue, and aggregates repetitive event sequences.
"""

import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, Dict
from sqlalchemy.orm import Session
from models import AlertModel
from correlation.prioritizer import calculate_risk_score

class AlertDeduplicator:
    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        # In-memory cache for ultra-fast lookup: fingerprint -> alert_id
        self._cache: Dict[str, str] = {}
        self.total_candidates = 0
        self.total_suppressed = 0

    def generate_fingerprint(
        self,
        category: str,
        rule_id: str,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        affected_user: Optional[str] = None,
        affected_host: Optional[str] = None
    ) -> str:
        """
        Creates a deterministic hash representing the alert signature.
        """
        raw_key = f"{category}|{rule_id}|{source_ip or ''}|{destination_ip or ''}|{affected_user or ''}|{affected_host or ''}"
        return hashlib.sha256(raw_key.encode('utf-8')).hexdigest()[:16]

    def process_candidate(
        self,
        db: Session,
        fingerprint: str,
        new_alert_data: dict,
        log_id: str
    ) -> Tuple[bool, AlertModel]:
        """
        Checks if an active alert matches the fingerprint within the sliding window.
        Returns (is_duplicate: bool, alert: AlertModel)
        """
        self.total_candidates += 1
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        window_cutoff = now - timedelta(seconds=self.window_seconds)

        # 1. Look up existing active alert with matching fingerprint in DB
        existing_alert = (
            db.query(AlertModel)
            .filter(
                AlertModel.dedup_fingerprint == fingerprint,
                AlertModel.last_seen >= window_cutoff,
                AlertModel.status.in_(["NEW", "INVESTIGATING", "SUPPRESSED"])
            )
            .first()
        )

        if existing_alert:
            self.total_suppressed += 1
            # Update duplicate count and timestamp
            existing_alert.duplicate_count += 1
            existing_alert.last_seen = now

            # Append correlated log id
            current_logs = existing_alert.to_dict()["correlated_log_ids"]
            if log_id not in current_logs:
                current_logs.append(log_id)
                import json
                existing_alert.correlated_log_ids = json.dumps(current_logs[-50:]) # cap at 50 logs for memory

            # Recalculate dynamic risk score with velocity boost
            new_score, new_sev, _ = calculate_risk_score(
                base_severity=new_alert_data.get("base_severity", "MEDIUM"),
                mitre_tactic_id=existing_alert.mitre_tactic,
                affected_host=existing_alert.affected_host,
                affected_user=existing_alert.affected_user,
                duplicate_count=existing_alert.duplicate_count
            )
            existing_alert.risk_score = new_score
            existing_alert.severity = new_sev

            db.commit()
            db.refresh(existing_alert)
            return True, existing_alert

        # 2. Not a duplicate: create new alert
        return False, None

    def get_stats(self) -> dict:
        rate = 0.0
        if self.total_candidates > 0:
            rate = round((self.total_suppressed / self.total_candidates) * 100, 1)
        return {
            "total_candidates": self.total_candidates,
            "total_suppressed": self.total_suppressed,
            "deduplication_rate_percent": rate
        }

deduplicator_instance = AlertDeduplicator(window_seconds=300)
