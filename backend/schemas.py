from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class LogCreate(BaseModel):
    source: str
    event_id: str
    severity: str = "INFO"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    user: Optional[str] = None
    host: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    action: Optional[str] = None
    message: str
    raw_data: Optional[Dict[str, Any]] = None

class BatchLogUpload(BaseModel):
    logs: List[LogCreate]

class AlertTriageUpdate(BaseModel):
    status: str
    incident_id: Optional[str] = None

class IncidentStatusUpdate(BaseModel):
    status: str
    assigned_analyst: Optional[str] = None

class PlaybookActionUpdate(BaseModel):
    action_index: int
    completed: bool

class AIChatRequest(BaseModel):
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    query: str

class SimulationTrigger(BaseModel):
    scenario: str   # 'brute_force', 'web_exfil', 'ransomware', 'priv_esc', 'normal_burst'
    intensity: Optional[int] = 5

class SettingsUpdate(BaseModel):
    gemini_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    ai_mode: Optional[str] = "hybrid"   # hybrid, local, gemini, openai
    simulator_speed: Optional[float] = 1.0 # logs per sec
