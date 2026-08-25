"""Runtime configuration.

Development defaults deliberately contain no reusable credentials.  Production
must supply its signing secret from the deployment's secret provider.
"""

import logging
import os
import secrets
from pathlib import Path

logger = logging.getLogger(__name__)


def _read_value(name: str, default: str | None = None) -> str | None:
    """Read configuration directly or from a mounted secret file.

    Kubernetes uses the ``*_FILE`` form so credentials do not appear in the
    pod environment. Defining both forms is rejected to keep precedence
    explicit and prevent a stale inline secret from silently winning.
    """
    inline_value = os.getenv(name)
    file_path = os.getenv(f"{name}_FILE")
    if inline_value is not None and file_path:
        raise RuntimeError(f"Set either {name} or {name}_FILE, not both")
    if not file_path:
        return inline_value if inline_value is not None else default

    try:
        file_value = Path(file_path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"Unable to read {name}_FILE") from exc
    if not file_value:
        raise RuntimeError(f"{name}_FILE must not be empty")
    return file_value

ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
DATABASE_URL = _read_value("DATABASE_URL", "sqlite:///./vulntracker.db")

SECRET_KEY = _read_value("SECRET_KEY")
if not SECRET_KEY:
    if ENVIRONMENT == "production":
        raise RuntimeError("SECRET_KEY must be set in production")
    # A process-local development key avoids committing a credential. Tokens
    # are intentionally invalidated when the development process restarts.
    SECRET_KEY = secrets.token_urlsafe(48)
    logger.warning("SECRET_KEY is unset; using an ephemeral development key")
elif len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY must contain at least 32 characters")

# Keep the accepted algorithm fixed in code to prevent configuration-driven
# algorithm confusion.
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

NOTIFY_SERVICE_URL = os.getenv("NOTIFY_SERVICE_URL", "http://localhost:3001").rstrip("/")
NOTIFY_SERVICE_KEY = _read_value("NOTIFY_SERVICE_KEY")
if NOTIFY_SERVICE_KEY is not None and len(NOTIFY_SERVICE_KEY) < 32:
    raise RuntimeError("NOTIFY_SERVICE_KEY must contain at least 32 characters")
if ENVIRONMENT == "production" and not NOTIFY_SERVICE_KEY:
    raise RuntimeError("NOTIFY_SERVICE_KEY must be set in production")

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")

# Browser access is denied by default. When needed, configure a comma-separated
# allowlist such as https://security.example.com,https://admin.example.com.
CORS_ALLOWED_ORIGINS = tuple(
    origin.strip()
    for origin in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
)
