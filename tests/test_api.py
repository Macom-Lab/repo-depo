import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient
import jwt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from database import Base, get_db  # noqa: E402
import models  # noqa: E402
from config import ALGORITHM, SECRET_KEY, _read_value  # noqa: E402
import main as main_module  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db(monkeypatch):
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def create_scan(token, title="Test finding", **overrides):
    payload = {
        "title": title,
        "severity": "high",
        "affected_component": "api",
        **overrides,
    }
    response = client.post("/scans", json=payload, headers=auth_headers(token))
    assert response.status_code == 201
    return response.json()


def share_token_from(response):
    assert response.status_code == 201
    return urlparse(response.json()["share_url"]).path.rsplit("/", 1)[-1]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["count"] == 1
    assert resp.json()["results"][0]["title"] == "SQL Injection via login"


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Shared reports
# ---------------------------------------------------------------------------

def test_create_and_read_unprotected_share_without_bearer_auth():
    token = register_and_login()
    scan = create_scan(token, title="Externally visible report", remediation_notes="Upgrade now")

    share_response = client.post(f"/scans/{scan['id']}/share", headers=auth_headers(token))
    share_token = share_token_from(share_response)

    assert share_response.json()["share_url"].startswith("http://localhost:8000/share/")
    assert len(share_token) == 43

    response = client.get(f"/share/{share_token}")
    assert response.status_code == 200
    assert response.json()["title"] == "Externally visible report"
    assert response.json()["remediation_notes"] == "Upgrade now"
    assert "owner_id" not in response.json()
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_share_stores_only_token_digest_and_has_24_hour_expiry():
    bearer = register_and_login()
    scan = create_scan(bearer)
    before = datetime.utcnow()

    response = client.post(f"/scans/{scan['id']}/share", json={}, headers=auth_headers(bearer))
    raw_token = share_token_from(response)

    with TestingSessionLocal() as db:
        link = db.query(models.SharedScanLink).one()
        assert link.token_hash == hashlib.sha256(raw_token.encode("ascii")).hexdigest()
        assert raw_token not in link.token_hash
        assert before + timedelta(hours=24) <= link.expires_at
        assert link.expires_at <= datetime.utcnow() + timedelta(hours=24)
        assert link.password_hash is None


def test_share_tokens_are_unique_and_unguessable():
    bearer = register_and_login()
    scan = create_scan(bearer)

    first = share_token_from(
        client.post(f"/scans/{scan['id']}/share", headers=auth_headers(bearer))
    )
    second = share_token_from(
        client.post(f"/scans/{scan['id']}/share", headers=auth_headers(bearer))
    )

    assert first != second
    assert len(set(first)) > 10
    assert len(set(second)) > 10


def test_password_protected_share_uses_slow_hash_and_requires_correct_password():
    bearer = register_and_login()
    scan = create_scan(bearer)
    # This exceeds bcrypt's 72-byte limit and verifies the separate share-link
    # password KDF accepts arbitrary Unicode safely.
    share_password = chr(0x1F512) * 40

    response = client.post(
        f"/scans/{scan['id']}/share",
        json={"password": share_password},
        headers=auth_headers(bearer),
    )
    share_token = share_token_from(response)

    with TestingSessionLocal() as db:
        link = db.query(models.SharedScanLink).one()
        assert link.password_hash.startswith("$pbkdf2-sha256$600000$")
        assert share_password not in link.password_hash

    assert client.get(f"/share/{share_token}").status_code == 403
    assert client.get(f"/share/{share_token}", params={"password": "wrong"}).status_code == 403
    allowed = client.get(f"/share/{share_token}", params={"password": share_password})
    assert allowed.status_code == 200


def test_empty_share_password_is_rejected_instead_of_creating_false_protection():
    bearer = register_and_login()
    scan = create_scan(bearer)
    response = client.post(
        f"/scans/{scan['id']}/share",
        json={"password": ""},
        headers=auth_headers(bearer),
    )
    assert response.status_code == 422


def test_expired_or_unknown_share_is_not_available():
    bearer = register_and_login()
    scan = create_scan(bearer)
    response = client.post(f"/scans/{scan['id']}/share", headers=auth_headers(bearer))
    share_token = share_token_from(response)

    with TestingSessionLocal() as db:
        link = db.query(models.SharedScanLink).one()
        link.expires_at = datetime.utcnow() - timedelta(microseconds=1)
        db.commit()

    assert client.get(f"/share/{share_token}").status_code == 404
    assert client.get(f"/share/{'A' * 43}").status_code == 404


def test_deleting_scan_invalidates_existing_share():
    bearer = register_and_login()
    scan = create_scan(bearer)
    share_token = share_token_from(
        client.post(f"/scans/{scan['id']}/share", headers=auth_headers(bearer))
    )

    assert client.delete(f"/scans/{scan['id']}", headers=auth_headers(bearer)).status_code == 204
    assert client.get(f"/share/{share_token}").status_code == 404


def test_share_creation_requires_authentication_and_scan_ownership():
    alice_token = register_and_login()
    alice_scan = create_scan(alice_token)
    bob_token = register_and_login("bob", "bob@example.com")

    unauthenticated = client.post(f"/scans/{alice_scan['id']}/share")
    assert unauthenticated.status_code == 401
    assert unauthenticated.headers["www-authenticate"] == "Bearer"
    assert client.post(
        f"/scans/{alice_scan['id']}/share", headers=auth_headers(bob_token)
    ).status_code == 404


# ---------------------------------------------------------------------------
# Security regressions in the starter API
# ---------------------------------------------------------------------------

def test_scan_get_and_search_are_tenant_isolated_and_search_is_not_injectable():
    alice_token = register_and_login()
    alice_scan = create_scan(alice_token, title="Alice confidential issue")
    bob_token = register_and_login("bob", "bob@example.com")
    create_scan(bob_token, title="Bob issue")

    assert client.get(
        f"/scans/{alice_scan['id']}", headers=auth_headers(bob_token)
    ).status_code == 404

    injected = client.get(
        "/scans/search",
        params={"q": "' OR 1=1 --"},
        headers=auth_headers(bob_token),
    )
    assert injected.status_code == 200
    assert injected.json()["results"] == []

    bob_search = client.get("/scans/search?q=issue", headers=auth_headers(bob_token))
    assert [result["title"] for result in bob_search.json()["results"]] == ["Bob issue"]


def test_alg_none_jwt_is_rejected_even_with_valid_claims():
    register_and_login()

    def b64url(value):
        encoded = base64.urlsafe_b64encode(json.dumps(value).encode()).decode()
        return encoded.rstrip("=")

    unsigned = ".".join([
        b64url({"alg": "none", "typ": "JWT"}),
        b64url({"sub": "alice", "type": "access", "iat": 1, "exp": 4_102_444_800}),
        "",
    ])
    response = client.get("/scans", headers=auth_headers(unsigned))
    assert response.status_code == 401


def test_failed_login_never_logs_password(caplog):
    password = "unique-secret-that-must-not-appear"
    client.post(
        "/auth/register",
        json={"username": "alice", "email": "alice@example.com", "password": password},
    )
    client.post("/auth/login", json={"username": "alice", "password": password + "-wrong"})
    assert password not in caplog.text


def test_untrusted_origin_is_not_reflected_with_credentials():
    response = client.get("/health", headers={"Origin": "https://attacker.example"})
    assert "access-control-allow-origin" not in response.headers
    assert "access-control-allow-credentials" not in response.headers


def test_internal_error_response_does_not_disclose_exception(monkeypatch):
    bearer = register_and_login()

    def fail_search(*args, **kwargs):
        raise RuntimeError("database-password-and-private-path")

    monkeypatch.setattr(main_module, "search_scans_by_query", fail_search)
    response = client.get("/scans/search?q=test", headers=auth_headers(bearer))
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "database-password" not in response.text


def test_notification_call_uses_service_authentication(monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)

    monkeypatch.setattr(main_module, "NOTIFY_SERVICE_KEY", "n" * 32)
    monkeypatch.setattr(main_module.httpx, "post", fake_post)
    main_module._fire_notify("scan.created", {"id": 1})

    assert captured["headers"] == {"X-Service-Key": "n" * 32}
    assert captured["json"] == {"event": "scan.created", "payload": {"id": 1}}


# ---------------------------------------------------------------------------
# Shared report links
# ---------------------------------------------------------------------------

def test_create_and_open_unprotected_share_link():
    access_token = register_and_login()
    scan = create_scan(access_token, title="Externally shared finding")

    share_response = client.post(
        f"/scans/{scan['id']}/share",
        headers=auth_headers(access_token),
    )
    token = share_token_from(share_response)

    assert share_response.json()["share_url"].startswith("http://localhost:8000/share/")
    assert share_response.headers["cache-control"] == "no-store"
    assert len(token) >= 43

    public_response = client.get(f"/share/{token}")
    assert public_response.status_code == 200
    assert public_response.json()["title"] == "Externally shared finding"
    assert public_response.headers["cache-control"] == "no-store"
    assert public_response.headers["referrer-policy"] == "no-referrer"


def test_password_protected_share_requires_correct_password():
    access_token = register_and_login()
    scan = create_scan(access_token)
    share_response = client.post(
        f"/scans/{scan['id']}/share",
        json={"password": "correct horse battery staple"},
        headers=auth_headers(access_token),
    )
    token = share_token_from(share_response)

    assert client.get(f"/share/{token}").status_code == 403
    assert client.get(f"/share/{token}", params={"password": "wrong"}).status_code == 403

    response = client.get(
        f"/share/{token}",
        params={"password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    assert response.json()["id"] == scan["id"]


def test_share_stores_only_token_digest_and_password_hash():
    access_token = register_and_login()
    scan = create_scan(access_token)
    share_response = client.post(
        f"/scans/{scan['id']}/share",
        json={"password": "audit-secret"},
        headers=auth_headers(access_token),
    )
    token = share_token_from(share_response)

    with TestingSessionLocal() as db:
        shared_link = db.query(models.SharedScanLink).one()
        assert shared_link.token_hash == hashlib.sha256(token.encode("ascii")).hexdigest()
        assert shared_link.token_hash != token
        assert shared_link.password_hash != "audit-secret"


def test_share_link_expires_exactly_after_24_hours():
    before = datetime.utcnow()
    access_token = register_and_login()
    scan = create_scan(access_token)
    token = share_token_from(client.post(
        f"/scans/{scan['id']}/share",
        json={},
        headers=auth_headers(access_token),
    ))

    with TestingSessionLocal() as db:
        shared_link = db.query(models.SharedScanLink).one()
        assert before + timedelta(hours=24) <= shared_link.expires_at
        assert shared_link.expires_at <= datetime.utcnow() + timedelta(hours=24)
        shared_link.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()

    response = client.get(f"/share/{token}")
    assert response.status_code == 404
    assert response.json()["detail"] == "Share link is invalid or expired"


def test_invalid_share_token_is_rejected_without_authentication():
    response = client.get(f"/share/{'A' * 43}")
    assert response.status_code == 404
    assert response.json()["detail"] == "Share link is invalid or expired"


def test_share_creation_requires_authentication_and_ownership():
    alice_token = register_and_login()
    alice_scan = create_scan(alice_token)
    bob_token = register_and_login("bob", "bob@example.com")

    unauthenticated = client.post(f"/scans/{alice_scan['id']}/share")
    assert unauthenticated.status_code == 401
    assert unauthenticated.headers["www-authenticate"] == "Bearer"
    response = client.post(
        f"/scans/{alice_scan['id']}/share",
        json={},
        headers=auth_headers(bob_token),
    )
    assert response.status_code == 404


def test_share_password_enforces_bounds_and_supports_unicode():
    access_token = register_and_login()
    scan = create_scan(access_token)

    empty = client.post(
        f"/scans/{scan['id']}/share",
        json={"password": ""},
        headers=auth_headers(access_token),
    )
    oversized = client.post(
        f"/scans/{scan['id']}/share",
        json={"password": "x" * 129},
        headers=auth_headers(access_token),
    )
    multibyte = client.post(
        f"/scans/{scan['id']}/share",
        json={"password": "ą" * 40},
        headers=auth_headers(access_token),
    )

    assert empty.status_code == 422
    assert oversized.status_code == 422
    token = share_token_from(multibyte)
    assert client.get(f"/share/{token}", params={"password": "ą" * 40}).status_code == 200


# ---------------------------------------------------------------------------
# Security regressions remediated from the starter application
# ---------------------------------------------------------------------------

def test_runtime_secrets_can_be_read_from_files_without_environment_exposure(
    monkeypatch, tmp_path
):
    secret_file = tmp_path / "service-key"
    secret_file.write_text("mounted-secret-value\n", encoding="utf-8")
    monkeypatch.delenv("TEST_SERVICE_KEY", raising=False)
    monkeypatch.setenv("TEST_SERVICE_KEY_FILE", str(secret_file))

    assert _read_value("TEST_SERVICE_KEY") == "mounted-secret-value"

    monkeypatch.setenv("TEST_SERVICE_KEY", "ambiguous-inline-value")
    with pytest.raises(RuntimeError, match="either TEST_SERVICE_KEY or TEST_SERVICE_KEY_FILE"):
        _read_value("TEST_SERVICE_KEY")

def test_users_cannot_read_or_search_other_users_scans():
    alice_token = register_and_login()
    alice_scan = create_scan(alice_token, title="Alice private finding")
    bob_token = register_and_login("bob", "bob@example.com")
    create_scan(bob_token, title="Bob secret finding")

    direct = client.get(f"/scans/{alice_scan['id']}", headers=auth_headers(bob_token))
    search = client.get("/scans/search", params={"q": "Alice"}, headers=auth_headers(bob_token))

    assert direct.status_code == 404
    assert search.status_code == 200
    assert search.json() == {"results": [], "count": 0}


def test_search_query_is_bound_and_like_wildcards_are_literal():
    access_token = register_and_login()
    create_scan(access_token, title="Ordinary finding")

    injection = client.get(
        "/scans/search",
        params={"q": "%' OR 1=1 --"},
        headers=auth_headers(access_token),
    )
    wildcard = client.get(
        "/scans/search",
        params={"q": "%%"},
        headers=auth_headers(access_token),
    )

    assert injection.status_code == 200
    assert injection.json()["count"] == 0
    assert wildcard.status_code == 200
    assert wildcard.json()["count"] == 0


def test_unsigned_jwt_is_rejected():
    register_and_login()
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
    claims = base64.urlsafe_b64encode(json.dumps({
        "sub": "alice",
        "type": "access",
        "iat": 1,
        "exp": 4_102_444_800,
    }).encode()).rstrip(b"=")
    unsigned_token = b".".join((header, claims, b"")).decode()

    response = client.get("/scans", headers=auth_headers(unsigned_token))
    assert response.status_code == 401


def test_access_token_without_expiry_is_rejected():
    register_and_login()
    token = jwt.encode(
        {"sub": "alice", "type": "access", "iat": 1},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    response = client.get("/scans", headers=auth_headers(token))
    assert response.status_code == 401


def test_login_never_logs_password(caplog):
    password = "unique-password-not-for-logs"
    client.post("/auth/register", json={
        "username": "alice",
        "email": "alice@example.com",
        "password": password,
    })

    with caplog.at_level("INFO"):
        client.post("/auth/login", json={"username": "alice", "password": password})
        client.post("/auth/login", json={"username": "alice", "password": f"{password}-wrong"})

    assert password not in caplog.text


def test_arbitrary_origin_does_not_receive_credentialed_cors_headers():
    response = client.get("/health", headers={"Origin": "https://attacker.example"})
    assert "access-control-allow-origin" not in response.headers
    assert "access-control-allow-credentials" not in response.headers


def test_registration_rejects_password_over_bcrypt_byte_limit():
    response = client.post("/auth/register", json={
        "username": "alice",
        "email": "alice@example.com",
        "password": "ą" * 40,
    })
    assert response.status_code == 422
