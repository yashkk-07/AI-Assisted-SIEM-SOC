import os
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import SettingModel
from schemas import AIChatRequest, SettingsUpdate
from ai.hybrid_analyst import hybrid_analyst_instance

router = APIRouter(prefix="/api/ai", tags=["AI SOC Analyst"])

@router.post("/chat")
def chat_with_analyst(payload: AIChatRequest, db: Session = Depends(get_db)):
    if not payload.query or not payload.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    reply = hybrid_analyst_instance.chat_query(
        db=db,
        query=payload.query,
        incident_id=payload.incident_id,
        alert_id=payload.alert_id
    )

    return {
        "status": "success",
        "response": reply
    }

@router.get("/settings")
def get_ai_settings(db: Session = Depends(get_db)):
    settings = db.query(SettingModel).all()
    config = {s.key: s.value for s in settings}

    has_gemini = bool(config.get("gemini_api_key") or os.getenv("GEMINI_API_KEY"))
    has_openai = bool(config.get("openai_api_key") or os.getenv("OPENAI_API_KEY"))

    return {
        "ai_mode": config.get("ai_mode", "hybrid"),
        "has_gemini_key": has_gemini,
        "has_openai_key": has_openai,
        "active_provider": "Gemini API" if has_gemini and config.get("ai_mode") != "local" else "SentinelAI Built-in Expert Engine"
    }

@router.post("/settings")
def update_ai_settings(payload: SettingsUpdate, db: Session = Depends(get_db)):
    def upsert(key: str, val: str):
        if val is not None:
            item = db.query(SettingModel).filter(SettingModel.key == key).first()
            if not item:
                item = SettingModel(key=key, value=val)
                db.add(item)
            else:
                item.value = val

    if payload.gemini_api_key is not None:
        upsert("gemini_api_key", payload.gemini_api_key.strip())
    if payload.openai_api_key is not None:
        upsert("openai_api_key", payload.openai_api_key.strip())
    if payload.ai_mode is not None:
        upsert("ai_mode", payload.ai_mode)

    db.commit()
    return {"status": "success", "message": "Settings updated successfully."}
