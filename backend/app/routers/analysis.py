from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..analysis import log_action, run_full_analysis
from ..database import get_db
from ..email_notifications import notify_dangerous_incident_created
from ..models import (
    AlertStatus,
    AuditAction,
    CorrelationAlert,
    EntityType,
    Incident,
    IncidentStatus,
)
from ..schemas import (
    AnalysisRunResponse,
    CorrelationAlertDetailResponse,
    CorrelationAlertResponse,
    CorrelationAlertUpdate,
    IncidentResponse,
    PaginatedResponse,
)
from ..dependencies import require_role

router = APIRouter(prefix="/analysis", tags=["Анализ"])


@router.post("/run", response_model=AnalysisRunResponse)
async def run_analysis(
    current_user: dict = Depends(require_role(["admin", "security_engineer"])),
    db: Session = Depends(get_db),
):
    result = run_full_analysis(db, user_id=current_user["user_id"])
    db.commit()
    return result


@router.get("/alerts", response_model=PaginatedResponse)
async def get_alerts(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    risk_level: str | None = None,
    source_ip: str | None = None,
    node_id: int | None = None,
    current_user: dict = Depends(require_role(["admin", "security_engineer"])),
    db: Session = Depends(get_db),
):
    query = db.query(CorrelationAlert)
    if status_filter:
        query = query.filter(CorrelationAlert.status == status_filter)
    if risk_level:
        query = query.filter(CorrelationAlert.risk_level == risk_level)
    if source_ip:
        query = query.filter(CorrelationAlert.source_ip == source_ip)
    if node_id:
        query = query.filter(CorrelationAlert.node_id == node_id)

    total = query.count()
    alerts = (
        query.order_by(CorrelationAlert.created_at.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    return {
        "items": [CorrelationAlertResponse.model_validate(alert) for alert in alerts],
        "total": total,
        "page": page,
        "limit": limit,
    }


@router.get("/alerts/{alert_id}", response_model=CorrelationAlertDetailResponse)
async def get_alert(
    alert_id: int,
    current_user: dict = Depends(require_role(["admin", "security_engineer"])),
    db: Session = Depends(get_db),
):
    alert = db.query(CorrelationAlert).filter(CorrelationAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Корреляционное оповещение не найдено")
    return alert


@router.put("/alerts/{alert_id}", response_model=CorrelationAlertResponse)
async def update_alert(
    alert_id: int,
    alert_data: CorrelationAlertUpdate,
    current_user: dict = Depends(require_role(["admin", "security_engineer"])),
    db: Session = Depends(get_db),
):
    alert = db.query(CorrelationAlert).filter(CorrelationAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Корреляционное оповещение не найдено")

    allowed_statuses = {status_item.value for status_item in AlertStatus}
    if alert_data.status not in allowed_statuses:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Недопустимый статус оповещения")

    alert.status = alert_data.status
    log_action(
        db,
        current_user["user_id"],
        AuditAction.update_alert,
        EntityType.correlation_alerts,
        alert.id,
    )
    db.commit()
    db.refresh(alert)
    return alert


@router.delete("/alerts/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert(
    alert_id: int,
    current_user: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db),
):
    alert = db.query(CorrelationAlert).filter(CorrelationAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Корреляционное оповещение не найдено")

    for incident in alert.incidents:
        incident.correlation_alert_id = None

    log_action(
        db,
        current_user["user_id"],
        AuditAction.delete,
        EntityType.correlation_alerts,
        alert.id,
    )
    db.delete(alert)
    db.commit()
    return None


@router.post("/alerts/{alert_id}/create-incident", response_model=IncidentResponse)
async def create_incident_from_alert(
    alert_id: int,
    current_user: dict = Depends(require_role(["admin", "security_engineer"])),
    db: Session = Depends(get_db),
):
    alert = db.query(CorrelationAlert).filter(CorrelationAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Корреляционное оповещение не найдено")

    existing_incident = (
        db.query(Incident).filter(Incident.correlation_alert_id == alert.id).first()
    )
    if existing_incident:
        return existing_incident

    first_event = alert.events[0] if alert.events else None
    if not first_event:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="У корреляционного оповещения нет связанных событий",
        )

    incident = Incident(
        title=alert.title,
        description=alert.description,
        severity=alert.risk_level,
        status=IncidentStatus.new,
        event_id=first_event.id,
        correlation_alert_id=alert.id,
        created_by=current_user["user_id"],
    )
    db.add(incident)
    db.flush()
    log_action(
        db,
        current_user["user_id"],
        AuditAction.create_incident_from_alert,
        EntityType.incidents,
        incident.id,
    )
    db.commit()
    db.refresh(incident)
    notify_dangerous_incident_created(incident)
    return incident
