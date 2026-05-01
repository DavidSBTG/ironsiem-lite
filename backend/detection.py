from database import Alert, SecurityEvent
from datetime import datetime, timedelta

def detect_bruteforce(db, source_ip: str):
    time_window = datetime.utcnow() - timedelta(minutes=10)

    failed_logins = db.query(SecurityEvent).filter(
        SecurityEvent.source_ip == source_ip,
        SecurityEvent.event_id == "4625",
        SecurityEvent.timestamp >= time_window
    ).count()

    if failed_logins >= 5:
        alert = Alert(
            title="Possible Brute Force Attack",
            description=f"{failed_logins} failed login attempts detected from {source_ip} within 10 minutes.",
            source_ip=source_ip,
            severity="High"
        )
        db.add(alert)
        db.commit()
        return True

    return False

def enrich_ip(source_ip: str):
    if source_ip.startswith("10.") or source_ip.startswith("192.168.") or source_ip.startswith("172.16."):
        return "Private/Internal IP"

    return "External IP - OSINT enrichment required"