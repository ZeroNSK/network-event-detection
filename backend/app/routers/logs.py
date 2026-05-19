from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, LoginAttemptLog
from ..schemas import AuditLogResponse, LoginAttemptLogResponse, PaginatedResponse
from ..dependencies import require_role

router = APIRouter(prefix="/logs", tags=["Журнал аудита"])


@router.get("", response_model=PaginatedResponse)
async def get_audit_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    current_user: dict = Depends(require_role(["admin", "security_engineer"])),
    db: Session = Depends(get_db)
):
    """
    Возвращает журнал аудита с пагинацией; доступно администратору и инженеру ИБ.
    
    - **page**: Page number (default: 1)
    - **limit**: Items per page (default: 10, max: 100)
    """
    query = db.query(AuditLog)
    
    # Получаем общее количество.
    total = query.count()
    
    # Применяем пагинацию.
    offset = (page - 1) * limit
    logs = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    
    # Преобразуем данные в модели ответа.
    items = [AuditLogResponse.model_validate(log) for log in logs]
    
    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit
    }


@router.get("/login-attempts", response_model=PaginatedResponse)
async def get_login_attempt_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    username: str = Query(None, description="Фильтр по имени пользователя"),
    ip_address: str = Query(None, description="Фильтр по IP-адресу"),
    current_user: dict = Depends(require_role(["admin", "security_engineer"])),
    db: Session = Depends(get_db),
):
    """
    Журнал неудачных попыток входа. Доступно администратору и инженеру ИБ.

    - **username**: фильтр по введённому логину
    - **ip_address**: фильтр по IP источника
    """
    query = db.query(LoginAttemptLog)

    if username:
        query = query.filter(LoginAttemptLog.username.ilike(f"%{username}%"))
    if ip_address:
        query = query.filter(LoginAttemptLog.ip_address == ip_address)

    total = query.count()
    offset = (page - 1) * limit
    logs = query.order_by(LoginAttemptLog.created_at.desc()).offset(offset).limit(limit).all()

    items = [LoginAttemptLogResponse.model_validate(log) for log in logs]

    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit,
    }
