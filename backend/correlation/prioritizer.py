"""
Threat Prioritization and Risk Scoring Engine
Calculates composite threat scores based on Asset Criticality,
Attack Stage / MITRE Tactic, Frequency Anomalies, and Account Privilege.
"""

from typing import Dict, Any, Tuple
from correlation.mitre import MITRE_TACTICS

CRITICAL_HOST_KEYWORDS = ["dc", "domain", "prod-db", "vault", "auth", "pci", "core", "192.168.1.10", "10.0.0.1"]
PRIVILEGED_USERS = ["administrator", "root", "admin", "system", "svc_sql", "krbtgt", "domain_admin"]

BASE_SEVERITY_SCORES = {
    "INFO": 15,
    "LOW": 30,
    "MEDIUM": 55,
    "HIGH": 78,
    "CRITICAL": 92
}

def calculate_risk_score(
    base_severity: str,
    mitre_tactic_id: str,
    affected_host: str = None,
    affected_user: str = None,
    duplicate_count: int = 1,
    anomaly_factor: float = 1.0
) -> Tuple[int, str, Dict[str, Any]]:
    """
    Returns (score: int, normalized_severity: str, breakdown: dict)
    """
    base_score = BASE_SEVERITY_SCORES.get(base_severity.upper(), 50)
    
    # 1. MITRE ATT&CK progression weight
    tactic_weight = 1.0
    if mitre_tactic_id and mitre_tactic_id in MITRE_TACTICS:
        tactic_weight = MITRE_TACTICS[mitre_tactic_id]["weight"]
    
    # 2. Asset Criticality Factor
    asset_multiplier = 1.0
    host_critical = False
    if affected_host:
        host_lower = affected_host.lower()
        if any(keyword in host_lower for keyword in CRITICAL_HOST_KEYWORDS):
            asset_multiplier += 0.25
            host_critical = True

    # 3. User Privilege Factor
    user_privileged = False
    if affected_user:
        user_lower = affected_user.lower()
        if any(priv in user_lower for priv in PRIVILEGED_USERS):
            asset_multiplier += 0.20
            user_privileged = True

    # 4. Duplicate / Volume Velocity Factor
    # If an attacker sends 50+ attempts, the attack intensity is high
    velocity_boost = 0
    if duplicate_count > 100:
        velocity_boost = 15
    elif duplicate_count > 30:
        velocity_boost = 10
    elif duplicate_count > 5:
        velocity_boost = 5

    # Compute compound score
    raw_score = (base_score * tactic_weight * asset_multiplier) + velocity_boost
    final_score = int(min(100, max(5, raw_score)))

    # Determine final normalized severity
    if final_score >= 85:
        severity = "CRITICAL"
    elif final_score >= 68:
        severity = "HIGH"
    elif final_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    breakdown = {
        "base_score": base_score,
        "tactic_multiplier": round(tactic_weight, 2),
        "asset_multiplier": round(asset_multiplier, 2),
        "is_critical_asset": host_critical,
        "is_privileged_user": user_privileged,
        "velocity_boost": velocity_boost,
        "final_score": final_score
    }

    return final_score, severity, breakdown
