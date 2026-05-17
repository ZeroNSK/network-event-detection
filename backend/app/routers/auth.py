from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, UserRole, AuditLog, AuditAction
from ..schemas import UserRegister, UserLogin, Token, UserResponse, PaginatedResponse
from ..auth import hash_password, verify_password, create_access_token
from ..dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """
    Register a new user.
    
    - **username**: Unique username
    - **email**: Unique email address
    - **password**: User password (will be hashed)
    
    Returns the created user data (without password).
    """
    # Check if username already exists
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists"
        )
    
    # Check if email already exists
    existing_email = db.query(User).filter(User.email == user_data.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already exists"
        )
    
    # Create new user with hashed password
    hashed_pwd = hash_password(user_data.password)
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_pwd,
        role=UserRole.operator  # Default role
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user


@router.post("/login", response_model=Token)
async def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """
    Login and receive JWT access token.
    
    - **username**: User's username
    - **password**: User's password
    
    Returns JWT token and user data.
    """
    # Find user by username
    user = db.query(User).filter(User.username == credentials.username).first()
    
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Create JWT token
    token_data = {
        "user_id": user.id,
        "role": user.role.value
    }
    access_token = create_access_token(token_data)
    
    # Create audit log for login
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
    Get current authenticated user information.
    
    Requires valid JWT token in Authorization header.
    """
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user


@router.get("/users", response_model=PaginatedResponse)
async def get_users(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get paginated list of users for assignment and access management forms.
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
