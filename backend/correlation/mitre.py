"""
MITRE ATT&CK Enterprise Matrix Definitions and Helpers
"""

MITRE_TACTICS = {
    "TA0001": {"name": "Initial Access", "weight": 1.1},
    "TA0002": {"name": "Execution", "weight": 1.3},
    "TA0003": {"name": "Persistence", "weight": 1.4},
    "TA0004": {"name": "Privilege Escalation", "weight": 1.6},
    "TA0005": {"name": "Defense Evasion", "weight": 1.4},
    "TA0006": {"name": "Credential Access", "weight": 1.5},
    "TA0007": {"name": "Discovery", "weight": 1.0},
    "TA0008": {"name": "Lateral Movement", "weight": 1.7},
    "TA0009": {"name": "Collection", "weight": 1.5},
    "TA0010": {"name": "Exfiltration", "weight": 1.9},
    "TA0011": {"name": "Command and Control", "weight": 1.8},
    "TA0040": {"name": "Impact", "weight": 2.0},
}

MITRE_TECHNIQUES = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may use brute force techniques to attempt access to accounts.",
        "sub_techniques": ["T1110.001 (Password Guessing)", "T1110.003 (Password Spraying)"]
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.",
        "sub_techniques": ["T1078.002 (Domain Accounts)", "T1078.003 (Local Accounts)"]
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "description": "Adversaries may use Valid Accounts to log into a service that accepts remote connections, such as RDP, SMB, SSH, or WinRM.",
        "sub_techniques": ["T1021.001 (RDP)", "T1021.002 (SMB/Windows Admin Shares)", "T1021.004 (SSH)"]
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "Adversaries may abuse command and script interpreters (PowerShell, Bash, CMD) to execute commands.",
        "sub_techniques": ["T1059.001 (PowerShell)", "T1059.004 (Unix Shell)"]
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries may attempt to exploit a vulnerability in an Internet-facing computer or program (e.g. SQL Injection, Path Traversal).",
        "sub_techniques": []
    },
    "T1543": {
        "id": "T1543",
        "name": "Create or Modify System Process",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "description": "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence.",
        "sub_techniques": ["T1543.003 (Windows Service)"]
    },
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "description": "Adversaries may encrypt data on target systems to interrupt availability to system and network resources (Ransomware).",
        "sub_techniques": []
    },
    "T1490": {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "description": "Adversaries may delete or remove built-in operating system data and turn off services to prevent recovery (e.g. vssadmin delete shadows).",
        "sub_techniques": []
    },
    "T1048": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "description": "Adversaries may steal data by exfiltrating it over an alternative network protocol or high volume outbound stream.",
        "sub_techniques": ["T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol)"]
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversaries may attempt to get a listing of services running on hosts across the network.",
        "sub_techniques": []
    }
}

def get_mitre_info(technique_id: str):
    return MITRE_TECHNIQUES.get(technique_id, {
        "id": technique_id,
        "name": "Unclassified Technique",
        "tactic": "General Defense",
        "tactic_id": "TA0000",
        "description": "Observed activity",
        "sub_techniques": []
    })
