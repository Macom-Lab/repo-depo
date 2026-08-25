import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from jwt import InvalidTokenError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

import models
from config import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, SECRET_KEY
from database import get_db

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
_DUMMY_PASSWORD_HASH = pwd_context.hash(secrets.token_urlsafe(32))
# Share passwords are not subject to bcrypt's 72-byte input limit. PBKDF2 also
# provides a deliberately slow verifier with timing-safe digest comparison.
share_pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    pbkdf2_sha256__default_rounds=600_000,
)
# Handle the missing-credential case ourselves so the API returns the same
# RFC 6750 response across FastAPI/Starlette versions. Older releases returned
# 403 here while newer releases return 401.
security = HTTPBearer(auto_error=False)


def verify_password(plain_password: str, hashed_password: Optional[str]) -> bool:
    try:
        # Unknown users still execute the same expensive KDF, reducing the
        # usefulness of login timing as a username-enumeration oracle.
        return pwd_context.verify(plain_password, hashed_password or _DUMMY_PASSWORD_HASH)
    except (TypeError, ValueError):
        # A malformed hash should fail closed instead of becoming a 500.
        return False


def get_password_hash(password: str) -> str:
    # bcrypt only processes 72 bytes. Reject longer values so two distinct
    # passwords can never authenticate due to silent truncation.
    if not password or len(password.encode("utf-8")) > 72:
        raise ValueError("Password must contain between 1 and 72 UTF-8 bytes")
    return pwd_context.hash(password)


def verify_share_password(plain_password: str, password_hash: str) -> bool:
    try:
        return share_pwd_context.verify(plain_password, password_hash)
    except (TypeError, ValueError):
        return False


def get_share_password_hash(password: str) -> str:
    return share_pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": now, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["exp", "iat", "sub"]},
        )
        if payload.get("type") != "access" or not payload.get("sub"):
            raise InvalidTokenError("Missing required access-token claims")
        return payload
    except InvalidTokenError as exc:
        logger.debug("JWT decode error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> models.User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(credentials.credentials)
    username: Optional[str] = payload.get("sub")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user
