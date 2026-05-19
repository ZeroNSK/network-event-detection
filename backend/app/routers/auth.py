from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, UserRole, AuditLog, AuditAction, EntityType
from ..schemas import (
    UserRegister,
    UserLogin,
    UserUpdate,
    Token,
    UserResponse,
    PaginatedResponse,
    LoginLockoutStatus,
)
from ..auth import hash_password, verify_password, create_access_token
from ..dependencies import get_current_user, require_role
from ..login_lockout import (
    LOGIN_LOCKOUT_SECONDS,
    MAX_FAILED_LOGIN_ATTEMPTS,
    ensure_login_not_locked,
    get_login_lockout_state,
    next_failed_login_metadata,
    raise_failed_login_error,
)
from ..security_events import record_failed_login_attempt

router = APIRouter(prefix="/auth", tags=["Аутентификация"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """
    Регистрирует нового пользователя.
    
    - **username**: уникальное имя пользователя
    - **email**: уникальный адрес электронной почты
    - **password**: пароль пользователя, который будет хеширован
    
    Возвращает данные созданного пользователя без пароля.
    """
    # Проверяем, занято ли имя пользователя.
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Имя пользователя уже занято"
        )
    
    # Проверяем, занят ли адрес электронной почты.
    existing_email = db.query(User).filter(User.email == user_data.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Адрес электронной почты уже занят"
        )
    
    # Создаем пользователя с хешированным паролем.
    hashed_pwd = hash_password(user_data.password)
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_pwd,
        role=UserRole.operator,  # Роль по умолчанию
        is_active=True,
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user


@router.get("/login-lockout", response_model=LoginLockoutStatus)
async def get_login_lockout(username: str = Query(..., min_length=1), db: Session = Depends(get_db)):
    """
    Возвращает состояние блокировки входа для указанного имени пользователя.
    """
    return get_login_lockout_state(db, username)


@router.post("/login", response_model=Token)
async def login(
    credentials: UserLogin,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Выполняет вход и возвращает JWT-токен доступа.
    
    - **username**: имя пользователя
    - **password**: пароль пользователя
    
    Возвращает JWT-токен и данные пользователя.
    """
    ensure_login_not_locked(db, credentials.username)

    # Ищем пользователя по имени.
    user = db.query(User).filter(User.username == credentials.username).first()

    if user and not user.is_active:
        record_failed_login_attempt(
            db,
            credentials.username,
            request,
            reason="account_disabled",
            attempt_number=0,
            locked_until=None,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Учетная запись отключена администратором",
        )
    
    if not user or not verify_password(credentials.password, user.hashed_password):
        attempt_number, locked_until, locked = next_failed_login_metadata(db, credentials.username)
        record_failed_login_attempt(
            db,
            credentials.username,
            request,
            reason="account_locked" if locked else "invalid_credentials",
            attempt_number=attempt_number,
            locked_until=locked_until,
        )
        db.commit()
        raise_failed_login_error(
            locked=locked,
            retry_after_seconds=LOGIN_LOCKOUT_SECONDS if locked else 0,
            attempts_remaining=max(0, MAX_FAILED_LOGIN_ATTEMPTS - attempt_number),
        )
    
    # Создаем JWT-токен.
    token_data = {
        "user_id": user.id,
        "role": user.role.value
    }
    access_token = create_access_token(token_data)
    
    # Создаем запись аудита для входа.
    audit_log = AuditLog(
        user_id=user.id,
        action=AuditAction.login
    )
    db.add(audit_log)
    db.commit()
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Возвращает данные текущего аутентифицированного пользователя.
    
    Требует действительный JWT-токен в заголовке Authorization.
    """
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )
    
    return user


@router.get("/users", response_model=PaginatedResponse)
async def get_users(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    current_user: dict = Depends(require_role(["admin", "security_engineer"])),
    db: Session = Depends(get_db)
):
    """
    Возвращает список пользователей для форм назначения и управления доступом.
    """
    query = db.query(User).order_by(User.username.asc())
    total = query.count()
    offset = (page - 1) * limit
    users = query.offset(offset).limit(limit).all()

    return {
        "items": [UserResponse.model_validate(user) for user in users],
        "total": total,
        "page": page,
        "limit": limit
    }


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    current_user: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db),
):
    """
    Обновляет роль, email или состояние учетной записи. Доступно только администратору.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Пользователь не найден")

    update_data = user_data.model_dump(exclude_unset=True)
    if not update_data:
        return user

    if user_id == current_user["user_id"]:
        if update_data.get("is_active") is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Администратор не может отключить собственную учетную запись",
            )
        if update_data.get("role") and update_data["role"] != UserRole.admin.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Администратор не может снять собственную роль администратора",
            )

    if "email" in update_data and update_data["email"] != user.email:
        existing_email = db.query(User).filter(User.email == update_data["email"]).first()
        if existing_email:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Адрес электронной почты уже занят")
        user.email = update_data["email"]

    if "role" in update_data:
        user.role = UserRole(update_data["role"])

    if "is_active" in update_data:
        user.is_active = update_data["is_active"]

    db.add(
        AuditLog(
            user_id=current_user["user_id"],
            action=AuditAction.update,
            entity_type=EntityType.users,
            entity_id=user.id,
        )
    )
    db.commit()
    db.refresh(user)
    return user


@router.delete("/users/{user_id}", response_model=UserResponse)
async def deactivate_user(
    user_id: int,
    current_user: dict = Depends(require_role(["admin"])),
    db: Session = Depends(get_db),
):
    """
    Мягко отключает учетную запись пользователя без удаления связанных событий и журналов.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Пользователь не найден")
    if user_id == current_user["user_id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Администратор не может отключить собственную учетную запись",
        )

    user.is_active = False
    db.add(
        AuditLog(
            user_id=current_user["user_id"],
            action=AuditAction.delete,
            entity_type=EntityType.users,
            entity_id=user.id,
        )
    )
    db.commit()
    db.refresh(user)
    return user
