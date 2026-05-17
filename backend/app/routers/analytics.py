from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import CorrelationAlert, Incident, NetworkEvent, NetworkNode
from ..dependencies import get_current_user

router = APIRouter(prefix="/analytics", tags=["Analytics"])


def _risk_distribution(db: Session) -> dict:
    levels = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    rows = db.query(NetworkEvent.risk_level, func.count(NetworkEvent.id)).group_by(NetworkEvent.risk_level).all()
    for risk_level, count in rows:
        levels[risk_level or "low"] = count
    return levels


def _top_source_ips(db: Session, limit: int = 5) -> list[dict]:
    rows = (
        db.query(
            NetworkEvent.source_ip,
            func.count(NetworkEvent.id).label("events_count"),
            func.avg(NetworkEvent.risk_score).label("average_risk_score"),
        )
        .group_by(NetworkEvent.source_ip)
        .order_by(func.count(NetworkEvent.id).desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "source_ip": source_ip,
            "events_count": events_count,
            "average_risk_score": round(float(average_risk_score or 0), 2),
        }
        for source_ip, events_count, average_risk_score in rows
    ]


def _top_event_types(db: Session, limit: int = 5) -> list[dict]:
    rows = (
        db.query(NetworkEvent.event_type, func.count(NetworkEvent.id))
        .group_by(NetworkEvent.event_type)
        .order_by(func.count(NetworkEvent.id).desc())
        .limit(limit)
        .all()
    )
    return [{"event_type": event_type.value if hasattr(event_type, "value") else event_type, "count": count} for event_type, count in rows]


def _top_nodes_by_events(db: Session, limit: int = 5) -> list[dict]:
    rows = (
        db.query(NetworkNode.id, NetworkNode.name, func.count(NetworkEvent.id))
        .join(NetworkEvent, NetworkEvent.node_id == NetworkNode.id)
        .group_by(NetworkNode.id, NetworkNode.name)
        .order_by(func.count(NetworkEvent.id).desc())
        .limit(limit)
        .all()
    )
    return [{"node_id": node_id, "node_name": name, "events_count": count} for node_id, name, count in rows]


@router.get("/summary")
async def get_summary(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    since_24h = now - timedelta(hours=24)
    total_events = db.query(NetworkEvent).count()
    suspicious_events = db.query(NetworkEvent).filter(NetworkEvent.is_suspicious.is_(True)).count()
    total_incidents = db.query(Incident).count()
    active_incidents = db.query(Incident).filter(Incident.status.in_(["new", "in_progress"])).count()
    critical_events = db.query(NetworkEvent).filter(NetworkEvent.risk_level == "critical").count()
    critical_alerts = db.query(CorrelationAlert).filter(CorrelationAlert.risk_level == "critical").count()
    average_risk_score = db.query(func.avg(NetworkEvent.risk_score)).scalar() or 0
    events_last_24h = db.query(NetworkEvent).filter(NetworkEvent.created_at >= since_24h).count()
    alerts_last_24h = db.query(CorrelationAlert).filter(CorrelationAlert.created_at >= since_24h).count()

    return {
        "total_events": total_events,
        "suspicious_events": suspicious_events,
        "total_incidents": total_incidents,
        "active_incidents": active_incidents,
        "critical_events": critical_events,
        "critical_alerts": critical_alerts,
        "average_risk_score": round(float(average_risk_score), 2),
        "events_last_24h": events_last_24h,
        "alerts_last_24h": alerts_last_24h,
        "top_source_ips": _top_source_ips(db),
        "top_event_types": _top_event_types(db),
        "top_nodes_by_events": _top_nodes_by_events(db),
        "risk_distribution": _risk_distribution(db),
    }


@router.get("/timeline")
async def get_timeline(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    buckets: dict[str, dict] = defaultdict(
        lambda: {
            "period": "",
            "events_count": 0,
            "suspicious_count": 0,
            "alerts_count": 0,
            "incidents_count": 0,
        }
    )

    for event in db.query(NetworkEvent).all():
        period = event.created_at.strftime("%Y-%m-%d %H:00")
        buckets[period]["period"] = period
        buckets[period]["events_count"] += 1
        if event.is_suspicious:
            buckets[period]["suspicious_count"] += 1

    for alert in db.query(CorrelationAlert).all():
        period = alert.created_at.strftime("%Y-%m-%d %H:00")
        buckets[period]["period"] = period
        buckets[period]["alerts_count"] += 1

    for incident in db.query(Incident).all():
        period = incident.created_at.strftime("%Y-%m-%d %H:00")
        buckets[period]["period"] = period
        buckets[period]["incidents_count"] += 1

    return sorted(buckets.values(), key=lambda item: item["period"])


@router.get("/top-sources")
async def get_top_sources(
    limit: int = 10,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _top_source_ips(db, limit=limit)


@router.get("/risk-distribution")
async def get_risk_distribution(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _risk_distribution(db)
