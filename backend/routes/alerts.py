from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
from database import get_db
from models import AlertModel, LogModel
from schemas import AlertTriageUpdate

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

@router.get("")
def list_alerts(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None
):
    query = db.query(AlertModel)
    if severity:
        query = query.filter(AlertModel.severity == severity.upper())
    if status:
        query = query.filter(AlertModel.status == status.upper())
    if category:
        query = query.filter(AlertModel.category == category)

    total = query.count()
    alerts = query.order_by(AlertModel.last_seen.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "alerts": [a.to_dict() for a in alerts]
    }

@router.get("/{alert_id}")
def get_alert_detail(alert_id: str, db: Session = Depends(get_db)):
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert_dict = alert.to_dict()
    log_ids = alert_dict.get("correlated_log_ids", [])
    logs = db.query(LogModel).filter(LogModel.id.in_(log_ids)).order_by(LogModel.timestamp.desc()).all()

    return {
        "alert": alert_dict,
        "correlated_logs": [l.to_dict() for l in logs]
    }

@router.patch("/{alert_id}/triage")
def triage_alert(alert_id: str, payload: AlertTriageUpdate, db: Session = Depends(get_db)):
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = payload.status.upper()
    if payload.incident_id:
        alert.incident_id = payload.incident_id

    db.commit()
    db.refresh(alert)
    return {"status": "success", "alert": alert.to_dict()}
