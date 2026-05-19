from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Optional

from ..database import get_db
from ..models import (
    NetworkEvent, NetworkNode, DetectionRule, AuditLog, 
    AuditAction, EntityType
)
from ..schemas import NetworkEventCreate, NetworkEventUpdate, NetworkEventResponse, PaginatedResponse
from ..dependencies import get_current_user, require_role
from ..analysis import analyze_and_correlate_event
from ..access_control import can_read_event, readable_events_query

router = APIRouter(prefix="/events", tags=["Сетевые события"])


@router.get("", response_model=PaginatedResponse)
async def get_events(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    severity: Optional[str] = None,
    is_suspicious: Optional[bool] = None,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    node_id: Optional[int] = None,
    risk_level: Optional[str] = None,
    min_risk_score: Optional[int] = Query(None, ge=0, le=100),
    max_risk_score: Optional[int] = Query(None, ge=0, le=100),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = readable_events_query(db, current_user)
    
    if severity:
        query = query.filter(NetworkEvent.severity == severity)
    if is_suspicious is not None:
        query = query.filter(NetworkEvent.is_suspicious == is_suspicious)
    if event_type:
        query = query.filter(NetworkEvent.event_type == event_type)
    if source_ip:
        query = query.filter(NetworkEvent.source_ip == source_ip)
    if node_id:
        query = query.filter(NetworkEvent.node_id == node_id)
    if risk_level:
        query = query.filter(NetworkEvent.risk_level == risk_level)
    if min_risk_score is not None:
        query = query.filter(NetworkEvent.risk_score >= min_risk_score)
    if max_risk_score is not None:
        query = query.filter(NetworkEvent.risk_score <= max_risk_score)
    
    total = query.count()
    
    offset = (page - 1) * limit
    events = query.order_by(NetworkEvent.created_at.desc()).offset(offset).limit(limit).all()
    
    items = [NetworkEventResponse.model_validate(event) for event in events]
    
    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit
    }


@router.get("/{event_id}", response_model=NetworkEventResponse)
async def get_event(
    event_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    event = db.query(NetworkEvent).filter(NetworkEvent.id == event_id).first()
    
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Сетевое событие не найдено"
        )
    if not can_read_event(db, event, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав"
        )
    
    return event


@router.post("", response_model=NetworkEventResponse, status_code=status.HTTP_201_CREATED)
async def create_event(
    event_data: NetworkEventCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    node = db.query(NetworkNode).filter(NetworkNode.id == event_data.node_id).first()
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Сетевой узел не найден"
        )
    
    if event_data.rule_id:
        rule = db.query(DetectionRule).filter(DetectionRule.id == event_data.rule_id).first()
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Правило обнаружения не найдено"
            )
    
    new_event = NetworkEvent(
        node_id=event_data.node_id,
        rule_id=event_data.rule_id,
        source_ip=event_data.source_ip,
        destination_ip=event_data.destination_ip,
        protocol=event_data.protocol,
        event_type=event_data.event_type,
        event_message=event_data.event_message,
        severity=event_data.severity,
        is_suspicious=False,
        created_by=current_user["user_id"]
    )
    
    db.add(new_event)
    db.flush()
    analyze_and_correlate_event(db, new_event, user_id=current_user["user_id"])
    
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.create,
        entity_type=EntityType.network_events,
        entity_id=new_event.id
    )
    db.add(audit_log)
    db.commit()
    db.refresh(new_event)
    
    return new_event


@router.put("/{event_id}", response_model=NetworkEventResponse)
async def update_event(
    event_id: int,
    event_data: NetworkEventUpdate,
    current_user: dict = Depends(require_role(["admin", "security_engineer"])),
    db: Session = Depends(get_db)
):
    event = db.query(NetworkEvent).filter(NetworkEvent.id == event_id).first()
    
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Сетевое событие не найдено"
        )
    
    update_data = event_data.model_dump(exclude_unset=True)
    if "node_id" in update_data:
        node = db.query(NetworkNode).filter(NetworkNode.id == update_data["node_id"]).first()
        if not node:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Сетевой узел не найден"
            )
    if update_data.get("rule_id"):
        rule = db.query(DetectionRule).filter(DetectionRule.id == update_data["rule_id"]).first()
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Правило обнаружения не найдено"
            )

    for field, value in update_data.items():
        setattr(event, field, value)
    
    analyze_and_correlate_event(db, event, user_id=current_user["user_id"])
    
    db.commit()
    db.refresh(event)
    
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.update,
        entity_type=EntityType.network_events,
        entity_id=event.id
    )
    db.add(audit_log)
    db.commit()
    
    return event


@router.delete("/{event_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_event(
    event_id: int,
    current_user: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    event = db.query(NetworkEvent).filter(NetworkEvent.id == event_id).first()
    
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Сетевое событие не найдено"
        )
    
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.delete,
        entity_type=EntityType.network_events,
        entity_id=event.id
    )
    db.add(audit_log)
    
    db.delete(event)
    db.commit()
    
    return None
