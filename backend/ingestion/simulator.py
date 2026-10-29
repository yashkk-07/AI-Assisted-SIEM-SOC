"""
Background Simulator & Event Stream Controller
Manages background telemetry generation, attack campaign injection, and event dispatch.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import List, Callable, Optional
from database import SessionLocal
from models import LogModel
from correlation.engine import correlation_engine_instance
from ingestion.scenarios import (
    generate_ambient_log,
    generate_brute_force_campaign,
    generate_web_sqli_campaign,
    generate_ransomware_campaign,
    generate_persistence_campaign
)

class EventSimulator:
    def __init__(self):
        self.is_running = True
        self.interval_seconds = 1.5 # default generation interval
        self.broadcast_callback: Optional[Callable] = None
        self._task: Optional[asyncio.Task] = None

    def set_broadcast_callback(self, cb: Callable):
        self.broadcast_callback = cb

    async def start(self):
        self.is_running = True
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._ambient_loop())

    async def stop(self):
        self.is_running = False
        if self._task:
            self._task.cancel()
            self._task = None

    async def _ambient_loop(self):
        while self.is_running:
            try:
                await asyncio.sleep(self.interval_seconds)
                if not self.is_running:
                    break
                raw_log = generate_ambient_log()
                await self.ingest_single_dict(raw_log)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[Simulator Loop Error] {e}")
                await asyncio.sleep(2)

    async def ingest_single_dict(self, d: dict):
        db = SessionLocal()
        try:
            log = LogModel(
                id=d.get("id"),
                timestamp=d.get("timestamp", datetime.now(timezone.utc)),
                source=d.get("source"),
                event_id=str(d.get("event_id")),
                severity=d.get("severity", "INFO"),
                source_ip=d.get("source_ip"),
                destination_ip=d.get("destination_ip"),
                source_port=d.get("source_port"),
                destination_port=d.get("destination_port"),
                user=d.get("user"),
                host=d.get("host"),
                process_name=d.get("process_name"),
                command_line=d.get("command_line"),
                action=d.get("action"),
                message=d.get("message"),
                raw_json=json.dumps(d, default=str)
            )
            db.add(log)
            db.commit()
            db.refresh(log)

            # Process through Correlation & Deduplication Engine
            alerts = correlation_engine_instance.process_log(db, log)

            # Broadcast via WebSocket if listener registered
            if self.broadcast_callback:
                payload = {
                    "type": "NEW_LOG",
                    "log": log.to_dict(),
                    "alerts_triggered": [a.to_dict() for a in alerts]
                }
                await self.broadcast_callback(payload)

        finally:
            db.close()

    async def inject_scenario(self, scenario_name: str) -> int:
        """
        Injects a designated multi-stage cyber campaign into the SIEM pipeline.
        """
        logs = []
        if scenario_name == "brute_force_lateral":
            logs = generate_brute_force_campaign()
        elif scenario_name == "web_sqli_exfil":
            logs = generate_web_sqli_campaign()
        elif scenario_name == "ransomware_inhibit":
            logs = generate_ransomware_campaign()
        elif scenario_name == "persistence_privesc":
            logs = generate_persistence_campaign()
        else:
            # Generic ambient burst
            logs = [generate_ambient_log() for _ in range(5)]

        count = len(logs)
        for log_data in logs:
            await self.ingest_single_dict(log_data)
            await asyncio.sleep(0.3) # small delay for realistic progression

        return count

simulator_instance = EventSimulator()
