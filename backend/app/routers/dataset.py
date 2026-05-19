import csv
from datetime import datetime
from io import StringIO

from fastapi import APIRouter, Depends, File, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..analysis import analyze_and_correlate_event, log_action
from ..database import get_db
from ..models import (
    AuditAction,
    EntityType,
    EventType,
    Incident,
    NetworkEvent,
    NetworkNode,
    NodeStatus,
    NodeType,
    Protocol,
    Severity,
)
from ..dependencies import get_current_user, require_role

router = APIRouter(prefix="/dataset", tags=["Набор данных"])

CSV_EVENT_FIELDS = [
    "timestamp",
    "node_name",
    "source_ip",
    "destination_ip",
    "protocol",
    "event_type",
    "event_message",
    "severity",
]


def _enum_or_default(enum_class, value: str | None, default):
    if not value:
        return default
    normalized = value.strip()
    return enum_class.__members__.get(normalized, default)


def _parse_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.utcnow()
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed


def _csv_response(filename: str, content: str) -> StreamingResponse:
    response = StreamingResponse(iter([content]), media_type="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@router.post("/import")
async def import_dataset(
    file: UploadFile = File(...),
    current_user: dict = Depends(require_role(["admin", "security_engineer"])),
    db: Session = Depends(get_db),
):
    raw_content = await file.read()
    decoded = raw_content.decode("utf-8-sig")
    reader = csv.DictReader(StringIO(decoded))

    imported_events: list[NetworkEvent] = []
    rows = sorted(
        list(reader),
        key=lambda row: row.get("timestamp") or "",
    )
    for row in rows:
        node_name = (row.get("node_name") or "Импортированный узел").strip()
        destination_ip = (row.get("destination_ip") or "0.0.0.0").strip()
        node = db.query(NetworkNode).filter(NetworkNode.name == node_name).first()
        if not node:
            node = NetworkNode(
                name=node_name,
                node_type=NodeType.server,
                ip_address=destination_ip,
                location="Импортировано из CSV",
                status=NodeStatus.active,
            )
            db.add(node)
            db.flush()

        event = NetworkEvent(
            node_id=node.id,
            rule_id=None,
            source_ip=(row.get("source_ip") or "").strip(),
            destination_ip=destination_ip,
            protocol=_enum_or_default(Protocol, row.get("protocol"), Protocol.OTHER),
            event_type=_enum_or_default(EventType, row.get("event_type"), EventType.other),
            event_message=(row.get("event_message") or "Импортированное сетевое событие").strip(),
            severity=_enum_or_default(Severity, row.get("severity"), Severity.low),
            is_suspicious=False,
            created_by=current_user["user_id"],
            created_at=_parse_timestamp(row.get("timestamp")),
        )
        db.add(event)
        db.flush()
        analyze_and_correlate_event(db, event, user_id=current_user["user_id"])
        imported_events.append(event)

    log_action(db, current_user["user_id"], AuditAction.import_dataset, EntityType.network_events)
    db.commit()

    return {
        "imported": len(imported_events),
        "events": [
            {
                "id": event.id,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "event_type": event.event_type.value if hasattr(event.event_type, "value") else event.event_type,
                "risk_score": event.risk_score,
                "risk_level": event.risk_level,
            }
            for event in imported_events[-10:]
        ],
    }


@router.get("/export/events")
async def export_events(
    current_user: dict = Depends(require_role(["admin", "security_engineer"])),
    db: Session = Depends(get_db),
):
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=CSV_EVENT_FIELDS + ["risk_score", "risk_level", "is_suspicious"])
    writer.writeheader()
    for event in db.query(NetworkEvent).order_by(NetworkEvent.created_at.asc()).all():
        writer.writerow(
            {
                "timestamp": event.created_at.isoformat(),
                "node_name": event.node.name if event.node else "",
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "protocol": event.protocol.value if hasattr(event.protocol, "value") else event.protocol,
                "event_type": event.event_type.value if hasattr(event.event_type, "value") else event.event_type,
                "event_message": event.event_message,
                "severity": event.severity.value if hasattr(event.severity, "value") else event.severity,
                "risk_score": event.risk_score,
                "risk_level": event.risk_level,
                "is_suspicious": event.is_suspicious,
            }
        )
    log_action(db, current_user["user_id"], AuditAction.export_dataset, EntityType.network_events)
    db.commit()
    return _csv_response("network_events_export.csv", output.getvalue())


@router.get("/export/incidents")
async def export_incidents(
    current_user: dict = Depends(require_role(["admin", "security_engineer"])),
    db: Session = Depends(get_db),
):
    fields = [
        "id",
        "title",
        "description",
        "status",
        "severity",
        "event_id",
        "correlation_alert_id",
        "created_by",
        "created_at",
        "updated_at",
    ]
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for incident in db.query(Incident).order_by(Incident.created_at.asc()).all():
        writer.writerow(
            {
                "id": incident.id,
                "title": incident.title,
                "description": incident.description,
                "status": incident.status.value if hasattr(incident.status, "value") else incident.status,
                "severity": incident.severity.value if hasattr(incident.severity, "value") else incident.severity,
                "event_id": incident.event_id,
                "correlation_alert_id": incident.correlation_alert_id or "",
                "created_by": incident.created_by,
                "created_at": incident.created_at.isoformat(),
                "updated_at": incident.updated_at.isoformat(),
            }
        )
    log_action(db, current_user["user_id"], AuditAction.export_dataset, EntityType.incidents)
    db.commit()
    return _csv_response("incidents_export.csv", output.getvalue())


@router.get("/sample")
async def sample_dataset(
    current_user: dict = Depends(get_current_user),
):
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=CSV_EVENT_FIELDS)
    writer.writeheader()
    rows = [
        {
            "timestamp": "2026-05-17T10:00:00",
            "node_name": "AUTH-RADIUS-01",
            "source_ip": "203.0.113.91",
            "destination_ip": "10.10.5.5",
            "protocol": "UDP",
            "event_type": "auth_failed",
            "event_message": "Неуспешная RADIUS-аутентификация PPPoE-сессии с внешнего IP.",
            "severity": "high",
        },
        {
            "timestamp": "2026-05-17T10:02:00",
            "node_name": "EDGE-FW-01",
            "source_ip": "198.51.100.77",
            "destination_ip": "172.16.0.1",
            "protocol": "TCP",
            "event_type": "port_scan",
            "event_message": "Последовательные SYN-запросы к административным портам межсетевого экрана.",
            "severity": "high",
        },
    ]
    writer.writerows(rows)
    return _csv_response("sample_network_events.csv", output.getvalue())
