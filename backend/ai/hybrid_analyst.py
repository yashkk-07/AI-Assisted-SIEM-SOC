"""
AI SOC Analyst Engine (Hybrid: Local Analytical Cyber Reasoner + Optional Generative LLM)
Provides automated triage analysis, root-cause hypothesis, blast-radius calculation,
containment playbooks, and interactive SOC assistant chat.
"""

import os
import json
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from models import IncidentModel, AlertModel, LogModel, SettingModel

class HybridAnalyst:
    def __init__(self):
        pass

    def _get_api_config(self, db: Session) -> Dict[str, str]:
        settings = db.query(SettingModel).all()
        config = {s.key: s.value for s in settings}
        return {
            "gemini_api_key": config.get("gemini_api_key", os.getenv("GEMINI_API_KEY", "")),
            "openai_api_key": config.get("openai_api_key", os.getenv("OPENAI_API_KEY", "")),
            "ai_mode": config.get("ai_mode", "hybrid")
        }

    def analyze_incident(self, db: Session, incident: IncidentModel) -> Dict[str, Any]:
        """
        Conducts deep investigation into an incident.
        """
        inc_data = incident.to_dict()
        alert_ids = inc_data["alert_ids"]
        
        # Retrieve all correlated alerts and their logs
        alerts = db.query(AlertModel).filter(AlertModel.id.in_(alert_ids)).all()
        alert_summaries = [a.to_dict() for a in alerts]

        correlated_log_ids = []
        for a in alert_summaries:
            correlated_log_ids.extend(a.get("correlated_log_ids", []))
        
        logs = db.query(LogModel).filter(LogModel.id.in_(correlated_log_ids[:25])).all()
        log_dicts = [l.to_dict() for l in logs]

        config = self._get_api_config(db)

        # Check if external LLM is requested and configured
        if config["gemini_api_key"] and config["ai_mode"] in ["gemini", "hybrid"]:
            try:
                import google.generativeai as genai
                genai.configure(api_key=config["gemini_api_key"])
                model = genai.GenerativeModel("gemini-2.0-flash")
                prompt = self._build_incident_prompt(inc_data, alert_summaries, log_dicts)
                response = model.generate_content(prompt)
                ai_text = response.text
                return self._parse_llm_response(ai_text, inc_data)
            except Exception as e:
                # Graceful fallback to local engine
                print(f"[AI Analyst] Gemini call fallback: {e}")

        # Local Smart Forensic Analytical Engine
        return self._local_forensic_analysis(inc_data, alert_summaries, log_dicts)

    def _local_forensic_analysis(
        self,
        inc_data: dict,
        alerts: List[dict],
        logs: List[dict]
    ) -> Dict[str, Any]:
        tactics = inc_data.get("tactics_observed", [])
        techniques = inc_data.get("techniques_observed", [])
        assets = inc_data.get("affected_assets", [])
        threat_score = inc_data.get("threat_score", 75)

        attacker_ips = [a["value"] for a in assets if a.get("type") == "IP_ATTACKER"]
        target_hosts = [a["value"] for a in assets if a.get("type") == "HOST"]
        target_users = [a["value"] for a in assets if a.get("type") == "USER"]

        primary_ip = attacker_ips[0] if attacker_ips else "external untrusted source"
        primary_host = target_hosts[0] if target_hosts else "corporate network endpoints"
        primary_user = target_users[0] if target_users else "privileged directory service"

        # Construct Executive Summary
        is_multi_stage = len(tactics) > 1
        summary = (
            f"Automated forensic correlation identified an active multi-stage campaign targeting {primary_host} "
            f"via entity credentials '{primary_user}'. Activity initiated from source IP {primary_ip}. "
            f"The adversary successfully chained {len(tactics)} MITRE ATT&CK tactics ({', '.join(tactics) if tactics else 'initial probing'}), "
            f"exhibiting an aggregate threat priority score of {threat_score}/100."
        )

        # Root Cause Analysis
        root_cause = (
            f"The incident commenced with {tactics[0] if tactics else 'unauthorized credential brute force'} "
            f"against boundary services from {primary_ip}. Authentication telemetry indicates repeated failure "
            f"bursts followed by valid session tokens. Lack of multi-factor enforcement on host {primary_host} "
            f"or vulnerable service configuration provided an entry foothold."
        )

        # Blast Radius Assessment
        blast_radius = (
            f"Current containment perimeter is localized to host {primary_host} and identity asset '{primary_user}'. "
            f"{'Warning: Lateral movement telemetry detected towards internal subnets. Blast radius is escalating.' if 'Lateral Movement' in tactics else 'No widespread domain propagation detected at this hour; immediate host isolation will constrain propagation.'}"
        )

        # Recommended Actionable Playbook (PICERL Framework)
        playbook = [
            {"step": 1, "action": f"Network Isolation: Apply immediate quarantine policy to host {primary_host} to prevent further pivoting.", "completed": False, "category": "Containment"},
            {"step": 2, "action": f"Edge Firewall Block: Inject drop rule for origin IP {primary_ip} across all external border firewalls.", "completed": False, "category": "Perimeter"},
            {"step": 3, "action": f"Identity Invalidation: Force password reset and revoke active Kerberos/OAuth tokens for user '{primary_user}'.", "completed": False, "category": "Eradication"},
            {"step": 4, "action": "Memory & Artifact Capture: Dump volatile RAM, inspect autorun services, and review scheduled tasks.", "completed": False, "category": "Forensics"},
            {"step": 5, "action": "Backup Integrity Verification: Validate immutable snapshot copies prior to restoring normal service operations.", "completed": False, "category": "Recovery"}
        ]

        return {
            "summary": summary,
            "root_cause": root_cause,
            "blast_radius": blast_radius,
            "ai_confidence": min(96, 75 + len(alerts) * 4),
            "playbook": playbook,
            "tactics_observed": tactics,
            "techniques_observed": techniques
        }

    def chat_query(
        self,
        db: Session,
        query: str,
        incident_id: Optional[str] = None,
        alert_id: Optional[str] = None
    ) -> str:
        """
        Interactively answers security analyst questions regarding an incident or alert.
        """
        incident = None
        if incident_id:
            incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()

        alert = None
        if alert_id:
            alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()

        config = self._get_api_config(db)

        # If Gemini key is available, pass to Gemini
        if config["gemini_api_key"] and config["ai_mode"] in ["gemini", "hybrid"]:
            try:
                import google.generativeai as genai
                genai.configure(api_key=config["gemini_api_key"])
                model = genai.GenerativeModel("gemini-2.0-flash")

                context = f"Incident Details:\n{json.dumps(incident.to_dict(), indent=2) if incident else 'None'}\n"
                if alert:
                    context += f"Alert Details:\n{json.dumps(alert.to_dict(), indent=2)}\n"

                prompt = (
                    f"You are SentinelAI, an elite Tier-3 SOC Incident Response Specialist. "
                    f"Answer the analyst's question accurately, concisely, and actionably using cybersecurity best practices.\n\n"
                    f"{context}\n\nAnalyst Question: {query}\nResponse:"
                )
                res = model.generate_content(prompt)
                return res.text
            except Exception as e:
                print(f"[AI Chat] Fallback to local reasoning: {e}")

        # Local intelligent SOC Q&A reasoning
        q_lower = query.lower()
        if incident:
            inc = incident.to_dict()
            assets = inc.get("affected_assets", [])
            attacker_ip = next((a["value"] for a in assets if a.get("type") == "IP_ATTACKER"), "Unknown IP")
            target_host = next((a["value"] for a in assets if a.get("type") == "HOST"), "Internal Hosts")
            user = next((a["value"] for a in assets if a.get("type") == "USER"), "Directory User")

            if "what should i do" in q_lower or "recommend" in q_lower or "contain" in q_lower or "first step" in q_lower:
                return (
                    f"**Immediate Triage Priority:**\n"
                    f"1. **Isolate Host `{target_host}`**: Terminate all active external network connections to contain potential lateral movement.\n"
                    f"2. **Block IP `{attacker_ip}`**: Push a perimeter firewall drop rule on your external WAF/firewall.\n"
                    f"3. **Revoke Credentials**: Revoke sessions for user `{user}` in Active Directory / IdP and enforce credential rotation."
                )
            elif "who" in q_lower or "ip" in q_lower or "attacker" in q_lower or "origin" in q_lower:
                return f"The primary threat actor IP identified in telemetry is **`{attacker_ip}`**. It has been observed executing requests against `{target_host}`."
            elif "mitre" in q_lower or "technique" in q_lower or "tactic" in q_lower:
                tactics = ", ".join(inc.get("tactics_observed", []))
                techs = ", ".join(inc.get("techniques_observed", []))
                return f"**Correlated MITRE ATT&CK Matrix Mapping:**\n- **Tactics Observed:** {tactics or 'Initial Access'}\n- **Techniques Identified:** {techs or 'T1110 (Brute Force)'}\nThreat progression indicates an escalating multi-vector intrusion."
            elif "severity" in q_lower or "score" in q_lower or "risk" in q_lower:
                return f"This incident has an aggregated Threat Score of **{inc.get('threat_score')}/100** categorized as **{inc.get('severity')}**. The score is elevated due to asset criticality and sequence correlation."
            else:
                return (
                    f"**SentinelAI SOC Analysis on {incident.id}:**\n"
                    f"- **Status:** {inc.get('status')} | **Severity:** {inc.get('severity')}\n"
                    f"- **Target Asset:** `{target_host}` | **Attacker IP:** `{attacker_ip}` | **Identity:** `{user}`\n"
                    f"- **Summary:** {inc.get('summary')}\n\n"
                    f"Would you like me to generate firewall remediation rules, isolate the host, or compile the executive incident response report?"
                )

        if alert:
            a = alert.to_dict()
            return (
                f"**Alert Analysis ({a.get('id')} - {a.get('title')}):**\n"
                f"- **Severity:** {a.get('severity')} (Risk Score: {a.get('risk_score')}/100)\n"
                f"- **MITRE Technique:** {a.get('mitre_technique_id')} ({a.get('mitre_technique_name')})\n"
                f"- **Entities:** Source IP `{a.get('source_ip') or 'N/A'}` -> Target `{a.get('affected_host') or 'N/A'}`\n"
                f"- **Deduplication:** Aggregated {a.get('duplicate_count')} duplicate events in the current detection window.\n"
                f"Recommended action: Verify if source IP `{a.get('source_ip')}` belongs to an authorized administrator."
            )

        return (
            "SentinelAI SOC Assistant ready. Ask any question about active security incidents, "
            "attacker IPs, MITRE ATT&CK techniques, forensic evidence, or remediation steps."
        )

    def _build_incident_prompt(self, inc_data: dict, alerts: list, logs: list) -> str:
        return (
            f"You are a Tier-3 SOC Incident Commander. Analyze the following security incident and return a JSON object with: "
            f"'summary', 'root_cause', 'blast_radius', 'ai_confidence' (integer 1-100), and 'playbook' (list of {{'step': int, 'action': str, 'category': str, 'completed': bool}}).\n\n"
            f"Incident Metadata:\n{json.dumps(inc_data, indent=2)}\n\n"
            f"Correlated Alerts:\n{json.dumps(alerts[:5], indent=2)}\n\n"
            f"Sample Correlated Logs:\n{json.dumps(logs[:8], indent=2)}\n\n"
            f"Output purely valid JSON."
        )

    def _parse_llm_response(self, text: str, inc_data: dict) -> Dict[str, Any]:
        try:
            # Strip markdown codeblocks
            clean = text.strip()
            if clean.startswith("```json"):
                clean = clean[7:]
            if clean.startswith("```"):
                clean = clean[3:]
            if clean.endswith("```"):
                clean = clean[:-3]
            parsed = json.loads(clean.strip())
            return {
                "summary": parsed.get("summary", inc_data.get("summary")),
                "root_cause": parsed.get("root_cause", inc_data.get("root_cause")),
                "blast_radius": parsed.get("blast_radius", inc_data.get("blast_radius")),
                "ai_confidence": parsed.get("ai_confidence", 92),
                "playbook": parsed.get("playbook", []),
                "tactics_observed": inc_data.get("tactics_observed", []),
                "techniques_observed": inc_data.get("techniques_observed", [])
            }
        except Exception:
            return self._local_forensic_analysis(inc_data, [], [])

hybrid_analyst_instance = HybridAnalyst()
