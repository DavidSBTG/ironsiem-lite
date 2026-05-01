from fastapi import FastAPI, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import SessionLocal, SecurityEvent, Alert, init_db
from detection import detect_bruteforce, enrich_ip

app = FastAPI(title="IronSIEM Lite")

init_db()

class EventInput(BaseModel):
    hostname: str
    source_ip: str
    event_id: str
    username: str
    message: str
    severity: str = "Info"

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def root():
    return {"status": "IronSIEM Lite Backend is running"}

@app.post("/events")
def receive_event(event: EventInput, db: Session = Depends(get_db)):
    enrichment = enrich_ip(event.source_ip)

    new_event = SecurityEvent(
        hostname=event.hostname,
        source_ip=event.source_ip,
        event_id=event.event_id,
        username=event.username,
        message=f"{event.message} | Enrichment: {enrichment}",
        severity=event.severity
    )

    db.add(new_event)
    db.commit()

    detect_bruteforce(db, event.source_ip)

    return {
        "status": "event_received",
        "source_ip": event.source_ip,
        "enrichment": enrichment
    }

@app.get("/events")
def get_events(db: Session = Depends(get_db)):
    return db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(100).all()

@app.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):
    return db.query(Alert).order_by(Alert.timestamp.desc()).limit(100).all()