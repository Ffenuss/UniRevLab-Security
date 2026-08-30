import os
from fastapi.testclient import TestClient
from app.main import app


os.environ["UNIREVLAB_COORDINATOR_API_KEYS"] = "unirevlab-test-token-0001"
client = TestClient(app)
client.headers.update({"Authorization": "Bearer unirevlab-test-token-0001"})


def test_healthz() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_assessment_requires_authority_confirmation() -> None:
    response = client.post(
        "/v1/assessments",
        json={
            "project_name": "Authorized target",
            "organization": "Example Org",
            "purpose": "Pre-release assessment",
            "artifact_sha256": "a" * 64,
            "modes": ["static"],
            "authority_confirmed": False,
        },
    )
    assert response.status_code == 400


def test_assessment_normalizes_hash_and_creates_audit_identity() -> None:
    response = client.post(
        "/v1/assessments",
        json={
            "project_name": "Authorized target",
            "organization": "Example Org",
            "purpose": "Pre-release assessment",
            "artifact_sha256": "AB" * 32,
            "modes": ["static", "reverse"],
            "authority_confirmed": True,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "created"
    assert payload["request"]["artifact_sha256"] == "ab" * 32
    assert payload["id"]
    assert payload["created_at"].endswith("Z")


def test_assessment_rejects_empty_mode_set() -> None:
    response = client.post(
        "/v1/assessments",
        json={
            "project_name": "Authorized target",
            "organization": "Example Org",
            "purpose": "Pre-release assessment",
            "artifact_sha256": "a" * 64,
            "modes": [],
            "authority_confirmed": True,
        },
    )
    assert response.status_code == 422


def test_client_can_register_fixed_assessment_id_and_sync_empty_state() -> None:
    assessment_id = "11111111-2222-3333-4444-555555555555"
    payload = {
        "project_name": "Mobile release",
        "organization": "Example Org",
        "purpose": "Authorized local client sync",
        "artifact_sha256": "c" * 64,
        "modes": ["static", "reverse"],
        "authority_confirmed": True,
        "created_at_epoch_ms": 1700000000000,
    }
    response = client.put(f"/v1/assessments/{assessment_id}", json=payload)
    assert response.status_code == 200
    assert response.json()["id"] == assessment_id
    sync = client.get(f"/v1/assessments/{assessment_id}/sync")
    assert sync.status_code == 200
    body = sync.json()
    assert body["syncSchemaVersion"] == "1.1"
    assert body["ghidraResults"] == []
    assert body["ghidraHistory"] == []


def test_client_upsert_is_idempotent_but_scope_is_immutable() -> None:
    assessment_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    payload = {
        "project_name": "Mobile release",
        "organization": "Example Org",
        "purpose": "Authorized local client sync",
        "artifact_sha256": "d" * 64,
        "modes": ["static", "reverse"],
        "authority_confirmed": True,
        "created_at_epoch_ms": 1700000000000,
    }
    assert client.put(f"/v1/assessments/{assessment_id}", json=payload).status_code == 200
    assert client.put(f"/v1/assessments/{assessment_id}", json=payload).status_code == 200
    changed = dict(payload)
    changed["artifact_sha256"] = "e" * 64
    assert client.put(f"/v1/assessments/{assessment_id}", json=changed).status_code == 409
