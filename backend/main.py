
import json
import asyncio
import os
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from database import engine, Base, SessionLocal
from models import RuleModel, LogModel
from routes import logs, alerts, incidents, simulator, ai, stats
from ingestion.simulator import simulator_instance


# Create database tables
Base.metadata.create_all(bind=engine)


# WebSocket Connection Manager for Real-Time SOC Feed
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        text_data = json.dumps(message)
        to_remove = []

        for connection in self.active_connections:
            try:
                await connection.send_text(text_data)
            except Exception:
                to_remove.append(connection)

        for dead in to_remove:
            self.disconnect(dead)


ws_manager = ConnectionManager()


# Seed default detection rules
def seed_default_rules():
    db = SessionLocal()

    try:
        count = db.query(RuleModel).count()

        if count == 0:
            rules = [
                RuleModel(
                    id="RULE_BRUTE_FORCE",
                    name="Brute Force Authentication",
                    description="Detects 5+ failed authentications within 60 seconds",
                    severity="HIGH",
                    category="Brute Force",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110",
                    threshold=5,
                    window_seconds=60,
                ),
                RuleModel(
                    id="RULE_ACCOUNT_TAKEOVER",
                    name="Account Compromise Indicator",
                    description="Successful logon immediately following rapid failed authentications",
                    severity="CRITICAL",
                    category="Credential Access",
                    mitre_tactic="Initial Access",
                    mitre_technique="T1078",
                    threshold=1,
                    window_seconds=180,
                ),
                RuleModel(
                    id="RULE_SUSPICIOUS_POWERSHELL",
                    name="Obfuscated PowerShell Execution",
                    description="Command line contains encoded or bypass flags (-enc, bypass, iex)",
                    severity="HIGH",
                    category="Execution",
                    mitre_tactic="Execution",
                    mitre_technique="T1059.001",
                    threshold=1,
                    window_seconds=10,
                ),
                RuleModel(
                    id="RULE_WEB_EXPLOIT",
                    name="Web Application Attack Signature",
                    description="SQL injection, path traversal, or remote command execution attempt",
                    severity="HIGH",
                    category="Web Attack",
                    mitre_tactic="Initial Access",
                    mitre_technique="T1190",
                    threshold=1,
                    window_seconds=30,
                ),
                RuleModel(
                    id="RULE_LATERAL_MOVEMENT",
                    name="Internal Lateral Movement",
                    description="Remote service invocation across internal subnets using administrative credentials",
                    severity="HIGH",
                    category="Lateral Movement",
                    mitre_tactic="Lateral Movement",
                    mitre_technique="T1021",
                    threshold=1,
                    window_seconds=60,
                ),
                RuleModel(
                    id="RULE_RANSOMWARE_RECOVERY",
                    name="Ransomware Inhibit System Recovery",
                    description="Volume shadow copies deleted via vssadmin",
                    severity="CRITICAL",
                    category="Ransomware Canary",
                    mitre_tactic="Impact",
                    mitre_technique="T1490",
                    threshold=1,
                    window_seconds=10,
                ),
                RuleModel(
                    id="RULE_EXFILTRATION",
                    name="High Volume Data Exfiltration",
                    description="Abnormal outbound data transfer to external untrusted destination",
                    severity="CRITICAL",
                    category="Data Exfiltration",
                    mitre_tactic="Exfiltration",
                    mitre_technique="T1048",
                    threshold=1,
                    window_seconds=60,
                ),
            ]

            db.add_all(rules)
            db.commit()

    finally:
        db.close()


# Application lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    seed_default_rules()

    simulator_instance.set_broadcast_callback(ws_manager.broadcast)
    await simulator_instance.start()

    # Generate a demonstration scenario for a new database
    db = SessionLocal()

    try:
        if db.query(LogModel).count() == 0:
            asyncio.create_task(
                simulator_instance.inject_scenario("brute_force_lateral")
            )
    finally:
        db.close()

    yield

    await simulator_instance.stop()


# Create FastAPI application
app = FastAPI(
    title="SentinelAI SIEM & Mini-SOC Platform",
    description=(
        "AI-assisted Security Information and Event Management platform "
        "with real-time correlation, deduplication, and incident response assistance."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# Enable CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Frontend build directory
FRONTEND_DIST = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "frontend",
        "dist",
    )
)


# Register API routers
app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(simulator.router)
app.include_router(ai.router)
app.include_router(stats.router)


# Serve the built React frontend, if available
if os.path.isdir(FRONTEND_DIST):
    assets_dir = os.path.join(FRONTEND_DIST, "assets")

    if os.path.isdir(assets_dir):
        app.mount(
            "/assets",
            StaticFiles(directory=assets_dir),
            name="assets",
        )

    @app.get("/")
    async def serve_root():
        return FileResponse(
            os.path.join(FRONTEND_DIST, "index.html")
        )

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        # Do not intercept API, WebSocket, or documentation routes
        reserved_prefixes = (
            "api",
            "ws",
            "docs",
            "redoc",
            "openapi.json",
        )

        if any(
            full_path == prefix or full_path.startswith(prefix + "/")
            for prefix in reserved_prefixes
        ):
            raise StarletteHTTPException(status_code=404)

        requested_file = os.path.abspath(
            os.path.join(FRONTEND_DIST, full_path)
        )

        # Prevent paths from escaping the frontend directory
        if (
            os.path.commonpath([FRONTEND_DIST, requested_file])
            == FRONTEND_DIST
            and os.path.isfile(requested_file)
        ):
            return FileResponse(requested_file)

        return FileResponse(
            os.path.join(FRONTEND_DIST, "index.html")
        )

else:

    @app.get("/")
    def health_check():
        return {
            "status": "online",
            "service": "SentinelAI SIEM Engine",
            "version": "1.0.0",
            "endpoints": {
                "docs": "/docs",
                "stats": "/api/stats",
                "logs": "/api/logs",
                "alerts": "/api/alerts",
                "incidents": "/api/incidents",
            },
        }


# WebSocket endpoint for real-time log updates
@app.websocket("/ws/logs")
async def websocket_logs_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)

    try:
        while True:
            # Keep the connection alive while receiving client messages
            await websocket.receive_text()

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

    except Exception:
        ws_manager.disconnect(websocket)


# Run directly with Python if needed
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
