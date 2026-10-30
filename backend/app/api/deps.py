
"""
Shared FastAPI dependencies (dependency injection).
Auth guards, DB session, and role checks.
"""

from typing import Callable, List, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_token
from app.db.session import get_db
from app.models.user import User
from app.schemas.user import TokenPayload


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
    auto_error=False,
)


def get_credentials_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme),
) -> User:
    """Extract and verify the current authenticated user from JWT."""

    credentials_exception = get_credentials_exception()

    if not token:
        raise credentials_exception

    try:
        payload = decode_token(token)

        user_id: Optional[str] = payload.get("sub")
        token_type: Optional[str] = payload.get("type")

        if not user_id or token_type != "access":
            raise credentials_exception

        token_data = TokenPayload(
            sub=user_id,
            type=token_type,
        )

    except JWTError:
        raise credentials_exception from None

    result = await db.execute(
        select(User).where(User.id == token_data.sub)
    )
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account",
        )

    return user


def require_role(allowed_roles: List[str]) -> Callable:
    """Dependency factory that checks the user's role."""

    async def role_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Operation not permitted for role "
                    f"'{current_user.role}'. "
                    f"Required one of: {allowed_roles}"
                ),
            )

        return current_user

    return role_checker


__all__ = [
    "get_db",
    "get_current_user",
    "require_role",
]
