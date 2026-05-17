from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Optional

from ..database import get_db
from ..models import DetectionRule, AuditLog, AuditAction, EntityType
from ..schemas import DetectionRuleCreate, DetectionRuleUpdate, DetectionRuleResponse, PaginatedResponse
from ..dependencies import get_current_user, require_role

router = APIRouter(prefix="/rules", tags=["Detection Rules"])


@router.get("", response_model=PaginatedResponse)
async def get_rules(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    event_type: Optional[str] = None,
    is_active: Optional[bool] = None,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get paginated list of detection rules with optional filters.
    
    - **page**: Page number (default: 1)
    - **limit**: Items per page (default: 10, max: 100)
    - **event_type**: Filter by event type (optional)
    - **is_active**: Filter by active status (optional)
    """
    query = db.query(DetectionRule)
    
    # Apply filters
    if event_type:
        query = query.filter(DetectionRule.event_type == event_type)
    if is_active is not None:
        query = query.filter(DetectionRule.is_active == is_active)
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * limit
    rules = query.offset(offset).limit(limit).all()
    
    # Convert to response models
    items = [DetectionRuleResponse.model_validate(rule) for rule in rules]
    
    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit
    }


@router.get("/{rule_id}", response_model=DetectionRuleResponse)
async def get_rule(
    rule_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection rule not found"
        )
    
    return rule


@router.post("", response_model=DetectionRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule_data: DetectionRuleCreate,
    current_user: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    """
    Create a new detection rule (admin only).
    
    - **name**: Rule name
    - **description**: Rule description (optional)
    - **event_type**: Type of event this rule detects
    - **severity_threshold**: Minimum severity level
    - **is_active**: Whether the rule is active
    """
    new_rule = DetectionRule(**rule_data.model_dump())
    
    db.add(new_rule)
    db.commit()
    db.refresh(new_rule)
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.create,
        entity_type=EntityType.detection_rules,
        entity_id=new_rule.id
    )
    db.add(audit_log)
    db.commit()
    
    return new_rule


@router.put("/{rule_id}", response_model=DetectionRuleResponse)
async def update_rule(
    rule_id: int,
    rule_data: DetectionRuleUpdate,
    current_user: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    """Update a detection rule (admin only)."""
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection rule not found"
        )
    
    # Update fields
    update_data = rule_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(rule, field, value)
    
    db.commit()
    db.refresh(rule)
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.update,
        entity_type=EntityType.detection_rules,
        entity_id=rule.id
    )
    db.add(audit_log)
    db.commit()
    
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: int,
    current_user: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    """Delete a detection rule (admin only)."""
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection rule not found"
        )
    
    # Create audit log before deletion
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.delete,
        entity_type=EntityType.detection_rules,
        entity_id=rule.id
    )
    db.add(audit_log)
    
    db.delete(rule)
    db.commit()
    
    return None
