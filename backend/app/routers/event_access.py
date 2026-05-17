from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from ..database import get_db
from ..models import EventAccess, NetworkEvent, User, AuditLog, AuditAction, EntityType, AccessLevel
from ..schemas import EventAccessCreate, EventAccessUpdate, EventAccessResponse
from ..dependencies import get_current_user

router = APIRouter(prefix="/events/{event_id}/access", tags=["Event Access"])


def check_event_manage_access(event_id: int, user_dict: dict, db: Session) -> bool:
    """Check if user can manage access for an event (admin or has manage level)"""
    if user_dict["role"] == "admin":
        return True
    
    access = db.query(EventAccess).filter(
        EventAccess.event_id == event_id,
        EventAccess.user_id == user_dict["user_id"]
    ).first()
    
    return access and access.access_level == AccessLevel.manage


@router.get("", response_model=List[EventAccessResponse])
async def get_event_access_list(
    event_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    event = db.query(NetworkEvent).filter(NetworkEvent.id == event_id).first()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Событие не найдено"
        )
    
    if not check_event_manage_access(event_id, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ запрещен"
        )
    
    from sqlalchemy.orm import selectinload
    access_list = db.query(EventAccess).options(
        selectinload(EventAccess.user)
    ).filter(EventAccess.event_id == event_id).all()
    
    return access_list


@router.post("", response_model=EventAccessResponse, status_code=status.HTTP_201_CREATED)
async def grant_event_access(
    event_id: int,
    access_data: EventAccessCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    event = db.query(NetworkEvent).filter(NetworkEvent.id == event_id).first()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Событие не найдено"
        )
    
    if not check_event_manage_access(event_id, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ запрещен"
        )
    
    user = db.query(User).filter(User.id == access_data.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )
    
    existing = db.query(EventAccess).filter(
        EventAccess.event_id == event_id,
        EventAccess.user_id == access_data.user_id
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Доступ уже предоставлен"
        )
    
    new_access = EventAccess(
        event_id=event_id,
        user_id=access_data.user_id,
        access_level=AccessLevel[access_data.access_level],
        granted_by=current_user["user_id"]
    )
    
    db.add(new_access)
    
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.grant_access,
        entity_type=EntityType.network_events,
        entity_id=event_id
    )
    db.add(audit_log)
    db.commit()
    db.refresh(new_access)
    
    return new_access


@router.put("/{access_id}", response_model=EventAccessResponse)
async def update_event_access(
    event_id: int,
    access_id: int,
    access_data: EventAccessUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not check_event_manage_access(event_id, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ запрещен"
        )
    
    access = db.query(EventAccess).filter(
        EventAccess.id == access_id,
        EventAccess.event_id == event_id
    ).first()
    
    if not access:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Доступ не найден"
        )
    
    access.access_level = AccessLevel[access_data.access_level]
    
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.update_access,
        entity_type=EntityType.network_events,
        entity_id=event_id
    )
    db.add(audit_log)
    db.commit()
    db.refresh(access)
    
    return access


@router.delete("/{access_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_event_access(
    event_id: int,
    access_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not check_event_manage_access(event_id, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ запрещен"
        )
    
    access = db.query(EventAccess).filter(
        EventAccess.id == access_id,
        EventAccess.event_id == event_id
    ).first()
    
    if not access:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Доступ не найден"
        )
    
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.revoke_access,
        entity_type=EntityType.network_events,
        entity_id=event_id
    )
    db.add(audit_log)
    
    db.delete(access)
    db.commit()
    
    return None
