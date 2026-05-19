from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Optional

from ..database import get_db
from ..models import NetworkNode, AuditLog, AuditAction, EntityType
from ..schemas import NetworkNodeCreate, NetworkNodeUpdate, NetworkNodeResponse, PaginatedResponse
from ..dependencies import get_current_user, require_role

router = APIRouter(prefix="/nodes", tags=["Сетевые узлы"])


@router.get("", response_model=PaginatedResponse)
async def get_nodes(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    status: Optional[str] = None,
    node_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    query = db.query(NetworkNode)
    
    if status:
        query = query.filter(NetworkNode.status == status)
    if node_type:
        query = query.filter(NetworkNode.node_type == node_type)
    
    total = query.count()
    
    offset = (page - 1) * limit
    nodes = query.offset(offset).limit(limit).all()
    
    items = [NetworkNodeResponse.model_validate(node) for node in nodes]
    
    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit
    }


@router.get("/{node_id}", response_model=NetworkNodeResponse)
async def get_node(
    node_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Возвращает один сетевой узел по ID."""
    node = db.query(NetworkNode).filter(NetworkNode.id == node_id).first()
    
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Сетевой узел не найден"
        )
    
    return node




@router.post("", response_model=NetworkNodeResponse, status_code=status.HTTP_201_CREATED)
async def create_node(
    node_data: NetworkNodeCreate,
    current_user: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    new_node = NetworkNode(**node_data.model_dump())
    
    db.add(new_node)
    db.commit()
    db.refresh(new_node)
    
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.create,
        entity_type=EntityType.network_nodes,
        entity_id=new_node.id
    )
    db.add(audit_log)
    db.commit()
    
    return new_node


@router.put("/{node_id}", response_model=NetworkNodeResponse)
async def update_node(
    node_id: int,
    node_data: NetworkNodeUpdate,
    current_user: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    node = db.query(NetworkNode).filter(NetworkNode.id == node_id).first()
    
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Сетевой узел не найден"
        )
    
    update_data = node_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(node, field, value)
    
    db.commit()
    db.refresh(node)
    
    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.update,
        entity_type=EntityType.network_nodes,
        entity_id=node.id
    )
    db.add(audit_log)
    db.commit()
    
    return node


@router.delete("/{node_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_node(
    node_id: int,
    current_user: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    node = db.query(NetworkNode).filter(NetworkNode.id == node_id).first()
    
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Сетевой узел не найден"
        )

    audit_log = AuditLog(
        user_id=current_user["user_id"],
        action=AuditAction.delete,
        entity_type=EntityType.network_nodes,
        entity_id=node.id
    )
    db.add(audit_log)
    
    db.delete(node)
    db.commit()
    
    return None
