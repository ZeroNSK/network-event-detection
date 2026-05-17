from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog
from ..schemas import AuditLogResponse, PaginatedResponse
from ..dependencies import require_role

router = APIRouter(prefix="/logs", tags=["Audit Logs"])


@router.get("", response_model=PaginatedResponse)
async def get_audit_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    current_user: dict = Depends(require_role(["admin", "security_engineer"])),
    db: Session = Depends(get_db)
):
    """
    Get paginated list of audit logs (admin and security_engineer only).
    
    - **page**: Page number (default: 1)
    - **limit**: Items per page (default: 10, max: 100)
    """
    query = db.query(AuditLog)
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * limit
    logs = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    
    # Convert to response models
    items = [AuditLogResponse.model_validate(log) for log in logs]
    
    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit
    }
