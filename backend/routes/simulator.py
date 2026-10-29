from fastapi import APIRouter, BackgroundTasks, HTTPException
from schemas import SimulationTrigger
from ingestion.simulator import simulator_instance

router = APIRouter(prefix="/api/simulator", tags=["Simulator"])

AVAILABLE_SCENARIOS = [
    {
        "id": "brute_force_lateral",
        "name": "Operation Crimson: Brute Force & Lateral Movement",
        "description": "Simulates external adversary (185.220.101.42) executing password spray against domain endpoints, compromising 'admin_sec', moving laterally to Domain Controller (DC01), and running obfuscated PowerShell.",
        "mitre_tactics": ["Credential Access (T1110)", "Lateral Movement (T1021)", "Execution (T1059)"],
        "severity": "CRITICAL"
    },
    {
        "id": "web_sqli_exfil",
        "name": "Web Breach & Sensitive Data Exfiltration",
        "description": "Simulates external automated scanner testing SQL Injection payloads against web portal, extracting database credentials, and initiating encrypted outbound exfiltration.",
        "mitre_tactics": ["Initial Access (T1190)", "Exfiltration (T1048)"],
        "severity": "HIGH"
    },
    {
        "id": "ransomware_inhibit",
        "name": "Shadow Ransomware: Inhibit Recovery",
        "description": "Simulates phishing payload execution: malicious download cradle executed, shadow copy deletion via vssadmin (T1490), and mass encryption indicators.",
        "mitre_tactics": ["Execution (T1059)", "Impact (T1490)"],
        "severity": "CRITICAL"
    },
    {
        "id": "persistence_privesc",
        "name": "Rogue Windows System Service Installation",
        "description": "Simulates local attacker abusing unquoted service path to install persistent system backdoor service 'svchost_updater.exe' (Event 7045).",
        "mitre_tactics": ["Persistence (T1543.003)", "Privilege Escalation"],
        "severity": "HIGH"
    }
]

@router.get("/scenarios")
def list_scenarios():
    return {"scenarios": AVAILABLE_SCENARIOS}

@router.post("/trigger")
async def trigger_scenario(payload: SimulationTrigger):
    count = await simulator_instance.inject_scenario(payload.scenario)
    return {
        "status": "success",
        "scenario": payload.scenario,
        "events_injected": count,
        "message": f"Successfully injected {count} correlated events into the SIEM pipeline."
    }

@router.post("/toggle")
async def toggle_simulator(enabled: bool):
    if enabled:
        await simulator_instance.start()
    else:
        await simulator_instance.stop()
    return {"status": "success", "is_running": simulator_instance.is_running}

@router.get("/status")
def get_simulator_status():
    return {
        "is_running": simulator_instance.is_running,
        "interval_seconds": simulator_instance.interval_seconds
    }
