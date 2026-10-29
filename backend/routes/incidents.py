import json
from fastapi import APIRouter, Depends, Query, HTTPException, Response
from sqlalchemy.orm import Session
from typing import Optional
from database import get_db
from models import IncidentModel, AlertModel, LogModel
from schemas import IncidentStatusUpdate, PlaybookActionUpdate
from ai.hybrid_analyst import hybrid_analyst_instance
from ai.reporter import report_generator_instance

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])

@router.get("")
def list_incidents(
    db: Session = Depends(get_db),
    status: Optional[str] = None,
    severity: Optional[str] = None
):
    query = db.query(IncidentModel)
    if status:
        query = query.filter(IncidentModel.status == status.upper())
    if severity:
        query = query.filter(IncidentModel.severity == severity.upper())

    incidents = query.order_by(IncidentModel.updated_at.desc()).all()
    return {"incidents": [i.to_dict() for i in incidents]}

@router.get("/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    inc_dict = incident.to_dict()
    alerts = db.query(AlertModel).filter(AlertModel.id.in_(inc_dict["alert_ids"])).all()
    alert_dicts = [a.to_dict() for a in alerts]

    correlated_log_ids = []
    for a in alert_dicts:
        correlated_log_ids.extend(a.get("correlated_log_ids", []))

    logs = db.query(LogModel).filter(LogModel.id.in_(correlated_log_ids[:30])).order_by(LogModel.timestamp.desc()).all()

    return {
        "incident": inc_dict,
        "correlated_alerts": alert_dicts,
        "correlated_logs": [l.to_dict() for l in logs]
    }

@router.patch("/{incident_id}/status")
def update_status(incident_id: str, payload: IncidentStatusUpdate, db: Session = Depends(get_db)):
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = payload.status.upper()
    if payload.assigned_analyst:
        incident.assigned_analyst = payload.assigned_analyst

    db.commit()
    db.refresh(incident)
    return {"status": "success", "incident": incident.to_dict()}

@router.patch("/{incident_id}/playbook")
def update_playbook_step(incident_id: str, payload: PlaybookActionUpdate, db: Session = Depends(get_db)):
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    playbook = incident.to_dict().get("playbook", [])
    if 0 <= payload.action_index < len(playbook):
        playbook[payload.action_index]["completed"] = payload.completed
        incident.playbook = json.dumps(playbook)
        db.commit()
        db.refresh(incident)

    return {"status": "success", "playbook": playbook}

@router.post("/{incident_id}/ai-investigate")
def trigger_ai_investigation(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    ai_result = hybrid_analyst_instance.analyze_incident(db, incident)

    incident.summary = ai_result.get("summary")
    incident.root_cause = ai_result.get("root_cause")
    incident.blast_radius = ai_result.get("blast_radius")
    incident.ai_confidence = ai_result.get("ai_confidence", 92)
    incident.playbook = json.dumps(ai_result.get("playbook", []))

    db.commit()
    db.refresh(incident)

    return {
        "status": "success",
        "ai_investigation": ai_result,
        "incident": incident.to_dict()
    }

@router.get("/{incident_id}/report")
def export_report(incident_id: str, format: str = Query("markdown", regex="^(markdown|html)$"), db: Session = Depends(get_db)):
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if format == "html":
        html_content = report_generator_instance.generate_html(db, incident_id)
        return Response(content=html_content, media_type="text/html")
    else:
        md_content = report_generator_instance.generate_markdown(db, incident_id)
        return Response(content=md_content, media_type="text/markdown")
