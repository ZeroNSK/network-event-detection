from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import CorrelationAlert, CorrelationAlertEvent, Incident, NetworkEvent, NetworkNode
from ..dependencies import get_current_user
from ..access_control import has_global_security_read, readable_events_query, readable_incidents_query

router = APIRouter(prefix="/analytics", tags=["Аналитика"])


def _risk_distribution(events_query) -> dict:
    levels = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    rows = events_query.with_entities(
        NetworkEvent.risk_level,
        func.count(NetworkEvent.id),
    ).group_by(NetworkEvent.risk_level).all()
    for risk_level, count in rows:
        levels[risk_level or "low"] = count
    return levels


def _top_source_ips(events_query, limit: int = 5) -> list[dict]:
    rows = (
        events_query.with_entities(
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


def _top_event_types_from_query(events_query, limit: int = 5) -> list[dict]:
    rows = (
        events_query.with_entities(NetworkEvent.event_type, func.count(NetworkEvent.id))
        .group_by(NetworkEvent.event_type)
        .order_by(func.count(NetworkEvent.id).desc())
        .limit(limit)
        .all()
    )
    return [{"event_type": event_type.value if hasattr(event_type, "value") else event_type, "count": count} for event_type, count in rows]


def _top_nodes_by_events(events_query, limit: int = 5) -> list[dict]:
    rows = (
        events_query.join(NetworkNode, NetworkEvent.node_id == NetworkNode.id)
        .with_entities(NetworkNode.id, NetworkNode.name, func.count(NetworkEvent.id))
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
    events_query = readable_events_query(db, current_user)
    incidents_query = readable_incidents_query(db, current_user)
    total_events = events_query.count()
    suspicious_events = events_query.filter(NetworkEvent.is_suspicious.is_(True)).count()
    total_incidents = incidents_query.count()
    active_incidents = incidents_query.filter(Incident.status.in_(["new", "in_progress"])).count()
    critical_events = events_query.filter(NetworkEvent.risk_level == "critical").count()
    average_risk_score = events_query.with_entities(func.avg(NetworkEvent.risk_score)).scalar() or 0
    events_last_24h = events_query.filter(NetworkEvent.created_at >= since_24h).count()

    if has_global_security_read(current_user):
        critical_alerts = db.query(CorrelationAlert).filter(CorrelationAlert.risk_level == "critical").count()
        alerts_last_24h = db.query(CorrelationAlert).filter(CorrelationAlert.created_at >= since_24h).count()
    else:
        visible_event_ids = events_query.with_entities(NetworkEvent.id)
        visible_alerts = db.query(CorrelationAlert).join(
            CorrelationAlertEvent,
            CorrelationAlertEvent.alert_id == CorrelationAlert.id,
        ).filter(CorrelationAlertEvent.event_id.in_(visible_event_ids)).distinct()
        critical_alerts = visible_alerts.filter(CorrelationAlert.risk_level == "critical").count()
        alerts_last_24h = visible_alerts.filter(CorrelationAlert.created_at >= since_24h).count()

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
        "top_source_ips": _top_source_ips(events_query),
        "top_event_types": _top_event_types_from_query(events_query),
        "top_nodes_by_events": _top_nodes_by_events(events_query),
        "risk_distribution": _risk_distribution(events_query),
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

    events_query = readable_events_query(db, current_user)
    incidents_query = readable_incidents_query(db, current_user)

    for event in events_query.all():
        period = event.created_at.strftime("%Y-%m-%d %H:00")
        buckets[period]["period"] = period
        buckets[period]["events_count"] += 1
        if event.is_suspicious:
            buckets[period]["suspicious_count"] += 1

    if has_global_security_read(current_user):
        alerts = db.query(CorrelationAlert).all()
    else:
        visible_event_ids = events_query.with_entities(NetworkEvent.id)
        alerts = (
            db.query(CorrelationAlert)
            .join(CorrelationAlertEvent, CorrelationAlertEvent.alert_id == CorrelationAlert.id)
            .filter(CorrelationAlertEvent.event_id.in_(visible_event_ids))
            .distinct()
            .all()
        )
    for alert in alerts:
        period = alert.created_at.strftime("%Y-%m-%d %H:00")
        buckets[period]["period"] = period
        buckets[period]["alerts_count"] += 1

    for incident in incidents_query.all():
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
    return _top_source_ips(readable_events_query(db, current_user), limit=limit)


@router.get("/risk-distribution")
async def get_risk_distribution(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _risk_distribution(readable_events_query(db, current_user))
