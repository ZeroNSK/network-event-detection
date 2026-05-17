from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from ..database import get_db
from ..models import RuleAccess, DetectionRule, User, AuditLog, AuditAction, EntityType, AccessLevel
from ..schemas import RuleAccessCreate, RuleAccessUpdate, RuleAccessResponse
from ..dependencies import get_current_user

router = APIRouter(prefix="/rules/{rule_id}/access", tags=["Rule Access"])


def check_rule_manage_access(rule_id: int, user_dict: dict, db: Session) -> bool:
    """Check if user can manage access for a rule (admin or has manage level)"""
    if user_dict["role"] == "admin":
        return True
    
    access = db.query(RuleAccess).filter(
        RuleAccess.rule_id == rule_id,
        RuleAccess.user_id == user_dict["user_id"]
    ).first()
    
    return access and access.access_level == AccessLevel.manage


@router.get("", response_model=List[RuleAccessResponse])
async def get_rule_access_list(
    rule_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Правило не найдено"
        )
    
    if not check_rule_manage_access(rule_id, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ запрещен"
        )
    
    from sqlalchemy.orm import selectinload
    access_list = db.query(RuleAccess).options(
        selectinload(RuleAccess.user)
    ).filter(RuleAccess.rule_id == rule_id).all()
    
    return access_list


@router.post("", response_model=RuleAccessResponse, status_code=status.HTTP_201_CREATED)
async def grant_rule_access(
    rule_id: int,
    access_data: RuleAccessCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Правило не найдено"
        )
    
    if not check_rule_manage_access(rule_id, current_user, db):
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
    
    existing = db.query(RuleAccess).filter(
        RuleAccess.rule_id == rule_id,
        RuleAccess.user_id == access_data.user_id
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Доступ уже предоставлен"
        )
    
    new_access = RuleAccess(
        rule_id=rule_id,
        user_id=access_data.user_id,
        access_level=AccessLevel[access_data.access_level],
        granted_by=current_user["user_id"]
    )
    
    db.add(new_access)
    
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.grant_access,
        entity_type=EntityType.detection_rules,
        entity_id=rule_id
    )
    db.add(audit_log)
    db.commit()
    db.refresh(new_access)
    
    return new_access


@router.put("/{access_id}", response_model=RuleAccessResponse)
async def update_rule_access(
    rule_id: int,
    access_id: int,
    access_data: RuleAccessUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not check_rule_manage_access(rule_id, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ запрещен"
        )
    
    access = db.query(RuleAccess).filter(
        RuleAccess.id == access_id,
        RuleAccess.rule_id == rule_id
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
        entity_type=EntityType.detection_rules,
        entity_id=rule_id
    )
    db.add(audit_log)
    db.commit()
    db.refresh(access)
    
    return access


@router.delete("/{access_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_rule_access(
    rule_id: int,
    access_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not check_rule_manage_access(rule_id, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ запрещен"
        )
    
    access = db.query(RuleAccess).filter(
        RuleAccess.id == access_id,
        RuleAccess.rule_id == rule_id
    ).first()
    
    if not access:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Доступ не найден"
        )
    
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.revoke_access,
        entity_type=EntityType.detection_rules,
        entity_id=rule_id
    )
    db.add(audit_log)
    
    db.delete(access)
    db.commit()
    
    return None
