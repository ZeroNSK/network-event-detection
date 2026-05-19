from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Union

from ..database import get_db
from ..models import User, Incident, IncidentAccess, AccessLevel, AuditLog, AuditAction, EntityType
from ..schemas import IncidentAccessCreate, IncidentAccessUpdate, IncidentAccessResponse
from ..dependencies import get_current_user, require_role


router = APIRouter(prefix="/incidents", tags=["Доступ к инцидентам"])


def check_incident_access(incident_id: int, user: Union[User, dict], required_level: AccessLevel, db: Session) -> bool:
    """
    Проверяет, есть ли у пользователя нужный уровень доступа к инциденту.
    Администратор всегда имеет полный доступ.
    """
    # Поддерживаем и объект User, и словарь из JWT.
    user_id = user.id if hasattr(user, 'id') else user['user_id']
    user_role = user.role.value if hasattr(user, 'role') else user['role']
    
    # Администратор имеет полный доступ ко всем данным.
    if user_role == "admin":
        return True
    
    # Проверяем, выдан ли пользователю явный доступ.
    access = db.query(IncidentAccess).filter(
        IncidentAccess.incident_id == incident_id,
        IncidentAccess.user_id == user_id
    ).first()
    
    if not access:
        return False
    
    # Проверяем иерархию доступа: manage > write > read.
    access_hierarchy = {
        AccessLevel.read: 1,
        AccessLevel.write: 2,
        AccessLevel.manage: 3
    }
    
    return access_hierarchy[access.access_level] >= access_hierarchy[required_level]


@router.get("/{incident_id}/access", response_model=List[IncidentAccessResponse])
async def get_incident_access(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Возвращает все выданные доступы к инциденту; требуется доступ на чтение."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Инцидент не найден")
    
    if not check_incident_access(incident_id, current_user, AccessLevel.read, db):
        raise HTTPException(status_code=403, detail="Доступ запрещен")
    
    access_grants = db.query(IncidentAccess).filter(
        IncidentAccess.incident_id == incident_id
    ).all()
    
    return access_grants


@router.post("/{incident_id}/access", response_model=IncidentAccessResponse, status_code=status.HTTP_201_CREATED)
async def grant_incident_access(
    incident_id: int,
    access_data: IncidentAccessCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Выдает доступ к инциденту; требуется управление доступом или роль администратора."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Инцидент не найден")
    
    if not check_incident_access(incident_id, current_user, AccessLevel.manage, db):
        raise HTTPException(status_code=403, detail="Доступ запрещен")
    
    target_user = db.query(User).filter(User.id == access_data.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    existing_access = db.query(IncidentAccess).filter(
        IncidentAccess.incident_id == incident_id,
        IncidentAccess.user_id == access_data.user_id
    ).first()
    
    if existing_access:
        raise HTTPException(status_code=400, detail="Доступ уже предоставлен")
    
    try:
        access_level = AccessLevel(access_data.access_level)
    except ValueError:
        raise HTTPException(status_code=400, detail="Неверный уровень доступа")
    
    new_access = IncidentAccess(
        incident_id=incident_id,
        user_id=access_data.user_id,
        access_level=access_level,
        granted_by=current_user['user_id']
    )
    db.add(new_access)
    
    audit_log = AuditLog(
        user_id=current_user['user_id'],
        action=AuditAction.grant_access,
        entity_type=EntityType.incidents,
        entity_id=incident_id
    )
    db.add(audit_log)
    
    db.commit()
    db.refresh(new_access)
    
    return new_access


@router.put("/{incident_id}/access/{access_id}", response_model=IncidentAccessResponse)
async def update_incident_access(
    incident_id: int,
    access_id: int,
    access_data: IncidentAccessUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Изменяет уровень доступа к инциденту; требуется управление доступом или роль администратора."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Инцидент не найден")
    
    if not check_incident_access(incident_id, current_user, AccessLevel.manage, db):
        raise HTTPException(status_code=403, detail="Доступ запрещен")
    
    access = db.query(IncidentAccess).filter(
        IncidentAccess.id == access_id,
        IncidentAccess.incident_id == incident_id
    ).first()
    
    if not access:
        raise HTTPException(status_code=404, detail="Доступ не найден")
    
    try:
        access_level = AccessLevel(access_data.access_level)
    except ValueError:
        raise HTTPException(status_code=400, detail="Неверный уровень доступа")
    
    access.access_level = access_level
    
    audit_log = AuditLog(
        user_id=current_user['user_id'],
        action=AuditAction.update_access,
        entity_type=EntityType.incidents,
        entity_id=incident_id
    )
    db.add(audit_log)
    
    db.commit()
    db.refresh(access)
    
    return access


@router.delete("/{incident_id}/access/{access_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_incident_access(
    incident_id: int,
    access_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Отзывает доступ к инциденту; требуется управление доступом или роль администратора."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Инцидент не найден")
    
    if not check_incident_access(incident_id, current_user, AccessLevel.manage, db):
        raise HTTPException(status_code=403, detail="Доступ запрещен")
    
    access = db.query(IncidentAccess).filter(
        IncidentAccess.id == access_id,
        IncidentAccess.incident_id == incident_id
    ).first()
    
    if not access:
        raise HTTPException(status_code=404, detail="Доступ не найден")
    
    db.delete(access)
    
    audit_log = AuditLog(
        user_id=current_user['user_id'],
        action=AuditAction.revoke_access,
        entity_type=EntityType.incidents,
        entity_id=incident_id
    )
    db.add(audit_log)
    
    db.commit()
    
    return None
