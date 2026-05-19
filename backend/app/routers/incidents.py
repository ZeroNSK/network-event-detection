from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Optional

from ..database import get_db
from ..models import Incident, NetworkEvent, User, AuditLog, AuditAction, EntityType
from ..schemas import IncidentCreate, IncidentUpdate, IncidentResponse, PaginatedResponse
from ..dependencies import get_current_user, require_role
from ..email_notifications import notify_dangerous_incident_created
from ..access_control import can_read_event, can_read_incident, readable_incidents_query

router = APIRouter(prefix="/incidents", tags=["Инциденты"])


@router.get("", response_model=PaginatedResponse)
async def get_incidents(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Возвращает список инцидентов с пагинацией и дополнительными фильтрами.
    
    - **page**: Page number (default: 1)
    - **limit**: Items per page (default: 10, max: 100)
    - **status**: Filter by incident status (optional)
    - **severity**: Filter by severity level (optional)
    
    Note: operators can only see incidents they created, were assigned to, or were granted access to.
    """
    query = readable_incidents_query(db, current_user)
    
    # Применяем фильтры.
    if status_filter:
        query = query.filter(Incident.status == status_filter)
    if severity:
        query = query.filter(Incident.severity == severity)
    
    # Получаем общее количество.
    total = query.count()
    
    # Применяем пагинацию.
    offset = (page - 1) * limit
    incidents = query.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()
    
    # Преобразуем данные в модели ответа.
    items = [IncidentResponse.model_validate(incident) for incident in incidents]
    
    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit
    }




@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Возвращает один инцидент по ID вместе со связанным событием."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Инцидент не найден"
        )
    
    if not can_read_incident(db, incident, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав"
        )

    return IncidentResponse.model_validate(incident)


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident_data: IncidentCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Создает новый инцидент на основе сетевого события.
    
    - **title**: Incident title
    - **description**: Incident description
    - **severity**: Severity level
    - **event_id**: ID of the related network event
    - **assigned_to**: ID of user to assign incident to (optional)
    """
    # Проверяем, что событие существует.
    event = db.query(NetworkEvent).filter(NetworkEvent.id == incident_data.event_id).first()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Сетевое событие не найдено"
        )
    if not can_read_event(db, event, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав на связанное событие"
        )
    
    # Проверяем назначенного пользователя, если он указан.
    if incident_data.assigned_to:
        assignee = db.query(User).filter(User.id == incident_data.assigned_to).first()
        if not assignee:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Назначенный пользователь не найден"
            )
    
    # Создаем инцидент.
    new_incident = Incident(
        title=incident_data.title,
        description=incident_data.description,
        severity=incident_data.severity,
        event_id=incident_data.event_id,
        assigned_to=incident_data.assigned_to,
        created_by=current_user["user_id"]
    )
    
    db.add(new_incident)
    db.commit()
    db.refresh(new_incident)
    
    # Создаем запись аудита.
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.create,
        entity_type=EntityType.incidents,
        entity_id=new_incident.id
    )
    db.add(audit_log)
    db.commit()

    notify_dangerous_incident_created(new_incident)
    
    return new_incident




@router.put("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: int,
    incident_data: IncidentUpdate,
    current_user: dict = Depends(require_role(["admin", "security_engineer"])),
    db: Session = Depends(get_db)
):
    """Update an incident (admin and security_engineer only)."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Инцидент не найден"
        )
    
    # Обновляем поля.
    update_data = incident_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(incident, field, value)
    
    db.commit()
    db.refresh(incident)
    
    # Создаем запись аудита.
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.update,
        entity_type=EntityType.incidents,
        entity_id=incident.id
    )
    db.add(audit_log)
    db.commit()
    
    return incident


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_incident(
    incident_id: int,
    current_user: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    """Delete an incident (admin only)."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Инцидент не найден"
        )
    
    # Создаем запись аудита перед удалением.
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.delete,
        entity_type=EntityType.incidents,
        entity_id=incident.id
    )
    db.add(audit_log)
    
    db.delete(incident)
    db.commit()
    
    return None
