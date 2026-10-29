"""
Multi-Format Security Log Parser
Parses Windows Events, Syslog, Apache/Nginx, Linux Auth, and JSON records.
"""

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any

class LogParser:
    @staticmethod
    def parse_raw(raw_text: str, default_source: str = "generic") -> Dict[str, Any]:
        text = raw_text.strip()
        
        # 1. Try JSON parsing
        if (text.startswith("{") and text.endswith("}")) or (text.startswith("[") and text.endswith("]")):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return LogParser._normalize_dict(parsed, default_source)
            except Exception:
                pass

        # 2. Try Nginx / Apache Combined Format
        # Format: IP - - [date] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
        web_match = re.match(r'^(\S+) \S+ \S+ \[(.*?)\] "(GET|POST|PUT|DELETE|HEAD) (\S+) \S+" (\d{3}) (\d+)', text)
        if web_match:
            ip, date_str, method, path, status, size = web_match.groups()
            severity = "HIGH" if any(p in path.lower() for p in ["' or 1=1", "union select", "../", "<script>"]) else "INFO"
            return {
                "id": f"LOG-{uuid.uuid4().hex[:10].upper()}",
                "timestamp": datetime.now(timezone.utc),
                "source": "nginx",
                "event_id": f"HTTP_{status}",
                "severity": severity,
                "source_ip": ip,
                "destination_ip": "10.0.0.80",
                "source_port": None,
                "destination_port": 443 if status in ["200", "404"] else 80,
                "user": None,
                "host": "web-gateway-01",
                "action": f"HTTP_{method}",
                "message": f"{method} {path} - Status {status} ({size} bytes)",
                "raw_json": json.dumps({"raw": text, "path": path, "status": status})
            }

        # 3. Try Linux Syslog / Auth log format
        # Format: Oct 22 14:32:01 host sshd[1234]: Failed password for invalid user root from 192.168.1.100 port 54321
        syslog_match = re.search(r'(\w+)\s+(\d+)\s+([\d:]+)\s+(\S+)\s+(\w+)\[?(\d*)\]?:\s+(.*)', text)
        if syslog_match:
            _, _, _, host, daemon, pid, message = syslog_match.groups()
            
            # Extract IP and User from message if present
            ip_match = re.search(r'from\s+([0-9\.]+)', message)
            user_match = re.search(r'user\s+(\w+)', message)
            
            src_ip = ip_match.group(1) if ip_match else None
            user = user_match.group(1) if user_match else None
            is_fail = "failed" in message.lower() or "failure" in message.lower()

            return {
                "id": f"LOG-{uuid.uuid4().hex[:10].upper()}",
                "timestamp": datetime.now(timezone.utc),
                "source": "auth-linux",
                "event_id": "SSH_FAILED" if is_fail else "SSH_EVENT",
                "severity": "MEDIUM" if is_fail else "INFO",
                "source_ip": src_ip,
                "destination_ip": "10.0.0.50",
                "source_port": None,
                "destination_port": 22,
                "user": user,
                "host": host,
                "action": "LOGIN_FAILED" if is_fail else "DAEMON_MSG",
                "message": message,
                "raw_json": json.dumps({"raw": text, "daemon": daemon})
            }

        # 4. Fallback Generic Log Entry
        ip_found = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        return {
            "id": f"LOG-{uuid.uuid4().hex[:10].upper()}",
            "timestamp": datetime.now(timezone.utc),
            "source": default_source,
            "event_id": "RAW_LOG",
            "severity": "INFO",
            "source_ip": ip_found.group(0) if ip_found else None,
            "destination_ip": None,
            "user": None,
            "host": "endpoint",
            "action": "LOG_ENTRY",
            "message": text[:500],
            "raw_json": json.dumps({"raw": text})
        }

    @staticmethod
    def _normalize_dict(d: dict, default_source: str) -> Dict[str, Any]:
        return {
            "id": d.get("id") or f"LOG-{uuid.uuid4().hex[:10].upper()}",
            "timestamp": datetime.now(timezone.utc),
            "source": d.get("source", default_source),
            "event_id": str(d.get("event_id", d.get("EventID", "UNKNOWN"))),
            "severity": d.get("severity", "INFO").upper(),
            "source_ip": d.get("source_ip") or d.get("src_ip") or d.get("IpAddress"),
            "destination_ip": d.get("destination_ip") or d.get("dest_ip"),
            "source_port": d.get("source_port") or d.get("src_port"),
            "destination_port": d.get("destination_port") or d.get("dest_port"),
            "user": d.get("user") or d.get("username") or d.get("TargetUserName"),
            "host": d.get("host") or d.get("hostname") or d.get("ComputerName") or "server-01",
            "process_name": d.get("process_name") or d.get("process") or d.get("ProcessName"),
            "command_line": d.get("command_line") or d.get("cmd") or d.get("CommandLine"),
            "action": d.get("action", "OBSERVED"),
            "message": d.get("message") or d.get("msg") or "Log event recorded",
            "raw_json": json.dumps(d)
        }
