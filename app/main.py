import hashlib
import logging
import secrets
from datetime import datetime, timedelta
from typing import List, Optional

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Path, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

import models
from auth import (
    create_access_token,
    get_current_user,
    get_password_hash,
    get_share_password_hash,
    verify_password,
    verify_share_password,
)
from config import CORS_ALLOWED_ORIGINS, NOTIFY_SERVICE_KEY, NOTIFY_SERVICE_URL, PUBLIC_BASE_URL
from database import engine, get_db, search_scans_by_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VulnTracker API",
    description="Vulnerability tracking and management REST API",
    version="1.0.0",
)


if CORS_ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(CORS_ALLOWED_ORIGINS),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Keep the exception and request query string in server-side logs only. The
    # public response never exposes implementation details or supplied secrets.
    logger.exception("Unhandled exception while processing %s request", request.method)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UserRegister(RequestModel):
    username: str = Field(min_length=1, max_length=50)
    email: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=1, max_length=72)


class UserLogin(RequestModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=72)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    created_at: datetime

class ScanCreate(RequestModel):
    title: str = Field(min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=20_000)
    severity: str = "medium"
    cve_id: Optional[str] = Field(default=None, max_length=30)
    affected_component: str = Field(min_length=1, max_length=200)
    remediation_notes: Optional[str] = Field(default=None, max_length=20_000)


class ScanUpdate(RequestModel):
    status: Optional[str] = None
    remediation_notes: Optional[str] = Field(default=None, max_length=20_000)


class ShareCreate(RequestModel):
    password: Optional[str] = Field(default=None, min_length=1, max_length=128)


class ShareOut(BaseModel):
    share_url: str


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    remediation_notes: Optional[str]
    owner_id: int
    created_at: datetime

class SharedScanOut(BaseModel):
    """Public report fields; internal ownership identifiers are omitted."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    remediation_notes: Optional[str]
    created_at: datetime
    updated_at: datetime

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fire_notify(event: str, payload: dict) -> None:
    if not NOTIFY_SERVICE_KEY:
        logger.warning("Notification skipped: NOTIFY_SERVICE_KEY is not configured")
        return
    try:
        httpx.post(
            f"{NOTIFY_SERVICE_URL}/notify",
            json={"event": event, "payload": payload},
            headers={"X-Service-Key": NOTIFY_SERVICE_KEY},
            timeout=5.0,
        )
    except Exception as exc:
        logger.warning("Notification service unreachable: %s", exc)


def _share_token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    try:
        password_hash = get_password_hash(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=password_hash,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    logger.info("Login attempt for username %s", payload.username)
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    password_valid = verify_password(payload.password, user.hashed_password if user else None)
    if not user or not password_valid:
        logger.warning("Failed login for username %s", payload.username)
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------

@app.get("/scans", response_model=List[ScanOut])
def list_scans(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return (
        db.query(models.ScanResult)
        .filter(models.ScanResult.owner_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


@app.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if payload.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="severity must be critical | high | medium | low")
    scan = models.ScanResult(**payload.model_dump(), owner_id=current_user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.created", {
        "id": scan.id,
        "title": scan.title,
        "severity": scan.severity,
        "owner": current_user.username,
    })
    return scan


@app.get("/scans/search")
def search_scans(
    q: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not q or len(q) < 2:
        raise HTTPException(status_code=400, detail="Search query must be at least 2 characters")
    if len(q) > 200:
        raise HTTPException(status_code=400, detail="Search query must not exceed 200 characters")
    results = search_scans_by_query(db, q, current_user.id)
    return {"results": results, "count": len(results)}


@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.post("/scans/{scan_id}/share", response_model=ShareOut, status_code=201)
def create_share_link(
    scan_id: int,
    response: Response,
    payload: Optional[ShareCreate] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        # The same response for missing and foreign scans avoids an ID oracle.
        raise HTTPException(status_code=404, detail="Scan not found")

    password = payload.password if payload else None
    password_hash = get_share_password_hash(password) if password is not None else None

    # 32 random bytes provide 256 bits of entropy. Only the digest is stored.
    token = secrets.token_urlsafe(32)
    shared_link = models.SharedScanLink(
        token_hash=_share_token_digest(token),
        password_hash=password_hash,
        scan_id=scan.id,
        expires_at=datetime.utcnow() + timedelta(hours=24),
    )
    db.add(shared_link)
    db.commit()

    response.headers["Cache-Control"] = "no-store"
    return {"share_url": f"{PUBLIC_BASE_URL}/share/{token}"}


@app.get("/share/{token}", response_model=SharedScanOut)
def get_shared_scan(
    response: Response,
    token: str = Path(min_length=32, max_length=128, pattern=r"^[A-Za-z0-9_-]+$"),
    password: Optional[str] = Query(default=None, min_length=1, max_length=128),
    db: Session = Depends(get_db),
):
    shared_link = db.query(models.SharedScanLink).filter(
        models.SharedScanLink.token_hash == _share_token_digest(token)
    ).first()
    if not shared_link or shared_link.expires_at <= datetime.utcnow() or not shared_link.scan:
        # Do not reveal whether a well-formed capability once existed.
        raise HTTPException(status_code=404, detail="Share link is invalid or expired")

    if shared_link.password_hash and not verify_share_password(password or "", shared_link.password_hash):
        raise HTTPException(status_code=403, detail="Password required or incorrect")

    # Shared reports and capability URLs must not be retained by browsers,
    # proxies, or referrer headers.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return shared_link.scan


@app.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(
    scan_id: int,
    payload: ScanUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if payload.status is not None:
        if payload.status not in ("open", "in_progress", "resolved"):
            raise HTTPException(status_code=400, detail="status must be open | in_progress | resolved")
        scan.status = payload.status
    if payload.remediation_notes is not None:
        scan.remediation_notes = payload.remediation_notes
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.updated", {
        "id": scan.id,
        "title": scan.title,
        "status": scan.status,
        "owner": current_user.username,
    })
    return scan


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulntracker-api"}
