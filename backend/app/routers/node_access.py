from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from ..database import get_db
from ..models import NodeAccess, NetworkNode, User, AuditLog, AuditAction, EntityType, AccessLevel
from ..schemas import NodeAccessCreate, NodeAccessUpdate, NodeAccessResponse
from ..dependencies import get_current_user

router = APIRouter(prefix="/nodes/{node_id}/access", tags=["Доступ к узлам"])


def check_node_manage_access(node_id: int, user_dict: dict, db: Session) -> bool:
    """Проверяет, может ли пользователь управлять доступом к узлу."""
    if user_dict["role"] == "admin":
        return True
    
    access = db.query(NodeAccess).filter(
        NodeAccess.node_id == node_id,
        NodeAccess.user_id == user_dict["user_id"]
    ).first()
    
    return access and access.access_level == AccessLevel.manage


@router.get("", response_model=List[NodeAccessResponse])
async def get_node_access_list(
    node_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    node = db.query(NetworkNode).filter(NetworkNode.id == node_id).first()
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Узел не найден"
        )
    
    if not check_node_manage_access(node_id, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ запрещен"
        )
    
    from sqlalchemy.orm import selectinload
    access_list = db.query(NodeAccess).options(
        selectinload(NodeAccess.user)
    ).filter(NodeAccess.node_id == node_id).all()
    
    return access_list


@router.post("", response_model=NodeAccessResponse, status_code=status.HTTP_201_CREATED)
async def grant_node_access(
    node_id: int,
    access_data: NodeAccessCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    node = db.query(NetworkNode).filter(NetworkNode.id == node_id).first()
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Узел не найден"
        )
    
    if not check_node_manage_access(node_id, current_user, db):
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
    
    existing = db.query(NodeAccess).filter(
        NodeAccess.node_id == node_id,
        NodeAccess.user_id == access_data.user_id
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Доступ уже предоставлен"
        )
    
    new_access = NodeAccess(
        node_id=node_id,
        user_id=access_data.user_id,
        access_level=AccessLevel[access_data.access_level],
        granted_by=current_user["user_id"]
    )
    
    db.add(new_access)
    
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.grant_access,
        entity_type=EntityType.network_nodes,
        entity_id=node_id
    )
    db.add(audit_log)
    db.commit()
    db.refresh(new_access)
    
    return new_access


@router.put("/{access_id}", response_model=NodeAccessResponse)
async def update_node_access(
    node_id: int,
    access_id: int,
    access_data: NodeAccessUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not check_node_manage_access(node_id, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ запрещен"
        )
    
    access = db.query(NodeAccess).filter(
        NodeAccess.id == access_id,
        NodeAccess.node_id == node_id
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
        entity_type=EntityType.network_nodes,
        entity_id=node_id
    )
    db.add(audit_log)
    db.commit()
    db.refresh(access)
    
    return access


@router.delete("/{access_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_node_access(
    node_id: int,
    access_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not check_node_manage_access(node_id, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ запрещен"
        )
    
    access = db.query(NodeAccess).filter(
        NodeAccess.id == access_id,
        NodeAccess.node_id == node_id
    ).first()
    
    if not access:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Доступ не найден"
        )
    
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.revoke_access,
        entity_type=EntityType.network_nodes,
        entity_id=node_id
    )
    db.add(audit_log)
    
    db.delete(access)
    db.commit()
    
    return None
