from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
from typing import List

from .auth import decode_token

security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:

    token = credentials.credentials
    
    try:
        payload = decode_token(token)
        user_id = payload.get("user_id")
        role = payload.get("role")
        
        if user_id is None or role is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing user_id or role"
            )
        
        return {"user_id": user_id, "role": role}
    
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


def require_role(allowed_roles: List[str]):

    async def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
 
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
    
    return role_checker
