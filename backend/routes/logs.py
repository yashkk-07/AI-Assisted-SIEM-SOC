from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from database import get_db
from models import LogModel
from schemas import LogCreate, BatchLogUpload
from ingestion.parser import LogParser
from correlation.engine import correlation_engine_instance
import uuid
from datetime import datetime, timezone

router = APIRouter(prefix="/api/logs", tags=["Logs"])

@router.get("")
def list_logs(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    source: Optional[str] = None,
    severity: Optional[str] = None,
    host: Optional[str] = None,
    search: Optional[str] = None
):
    query = db.query(LogModel)
    if source:
        query = query.filter(LogModel.source == source)
    if severity:
        query = query.filter(LogModel.severity == severity.upper())
    if host:
        query = query.filter(LogModel.host == host)
    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            (LogModel.message.ilike(search_filter)) |
            (LogModel.source_ip.ilike(search_filter)) |
            (LogModel.user.ilike(search_filter)) |
            (LogModel.process_name.ilike(search_filter))
        )
    
    total = query.count()
    logs = query.order_by(LogModel.timestamp.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "logs": [l.to_dict() for l in logs]
    }

@router.post("")
def ingest_log(payload: LogCreate, db: Session = Depends(get_db)):
    log_id = f"LOG-{uuid.uuid4().hex[:10].upper()}"
    log = LogModel(
        id=log_id,
        timestamp=datetime.now(timezone.utc),
        source=payload.source,
        event_id=payload.event_id,
        severity=payload.severity,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        source_port=payload.source_port,
        destination_port=payload.destination_port,
        user=payload.user,
        host=payload.host or "endpoint",
        process_name=payload.process_name,
        command_line=payload.command_line,
        action=payload.action,
        message=payload.message,
        raw_json="{}"
    )
    db.add(log)
    db.commit()
    db.refresh(log)

    alerts = correlation_engine_instance.process_log(db, log)
    return {
        "status": "success",
        "log": log.to_dict(),
        "alerts_triggered": [a.to_dict() for a in alerts]
    }

@router.post("/raw")
def ingest_raw_log(raw_text: str, default_source: str = "syslog", db: Session = Depends(get_db)):
    parsed = LogParser.parse_raw(raw_text, default_source)
    log = LogModel(
        id=parsed["id"],
        timestamp=parsed["timestamp"],
        source=parsed["source"],
        event_id=parsed["event_id"],
        severity=parsed["severity"],
        source_ip=parsed["source_ip"],
        destination_ip=parsed["destination_ip"],
        source_port=parsed.get("source_port"),
        destination_port=parsed.get("destination_port"),
        user=parsed.get("user"),
        host=parsed.get("host"),
        process_name=parsed.get("process_name"),
        command_line=parsed.get("command_line"),
        action=parsed.get("action"),
        message=parsed["message"],
        raw_json=parsed["raw_json"]
    )
    db.add(log)
    db.commit()
    db.refresh(log)

    alerts = correlation_engine_instance.process_log(db, log)
    return {
        "status": "success",
        "parsed_log": log.to_dict(),
        "alerts_triggered": [a.to_dict() for a in alerts]
    }
