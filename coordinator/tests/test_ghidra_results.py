import os
from pathlib import Path

from fastapi.testclient import TestClient
from app.main import app, STORE, SQLiteStore


os.environ["UNIREVLAB_COORDINATOR_API_KEYS"] = "unirevlab-test-token-0001"
client = TestClient(app)
client.headers.update({"Authorization": "Bearer unirevlab-test-token-0001"})


def _create_assessment(*, reverse: bool = True, sha: str = "a" * 64) -> str:
    modes = ["static", "reverse"] if reverse else ["static"]
    response = client.post(
        "/v1/assessments",
        json={
            "project_name": "Authorized target",
            "organization": "Example Org",
            "purpose": "Authorized reverse-engineering regression",
            "artifact_sha256": sha,
            "modes": modes,
            "authority_confirmed": True,
        },
    )
    assert response.status_code == 200
    return response.json()["id"]


def _result(
    assessment_id: str,
    *,
    sha: str = "a" * 64,
    library: str = "lib/arm64-v8a/libapp.so",
    function_size: int = 64,
) -> dict:
    return {
        "schemaVersion": "1.3",
        "assessmentId": assessment_id,
        "artifactSha256": sha,
        "libraryEntry": library,
        "status": "COMPLETE",
        "engine": {
            "name": "Ghidra",
            "version": "12.1.3",
            "pyGhidra": True,
            "analysisProfile": "DEEP",
        },
        "architecture": {"processor": "AARCH64", "pointerSize": 8, "endian": "LITTLE"},
        "coverage": {
            "functionsDiscovered": 2,
            "functionsReported": 2,
            "cfgBlocksReported": 3,
            "xrefsReported": 1,
            "decompilerFunctionsReported": 1,
            "truncated": False,
        },
        "functions": [
            {
                "rva": 4096,
                "name": "JNI_OnLoad",
                "namespace": "",
                "signature": "jint JNI_OnLoad(JavaVM*, void*)",
                "sizeBytes": function_size,
                "isThunk": False,
                "decompilerPreview": "return JNI_VERSION_1_6;",
            }
        ],
        "cfg": [
            {
                "functionRva": 4096,
                "blocks": [{"startRva": 4096, "endRva": 4128, "flowType": "RETURN"}],
                "edges": [],
            }
        ],
        "xrefs": [{"fromRva": 4096, "toRva": 8192, "kind": "CALL"}],
        "jniRegistrations": [
            {
                "source": "STATIC_EXPORT",
                "className": "com.example.Native",
                "methodName": "nativeCheck",
                "signature": "()Z",
                "functionRva": 4096,
                "confidence": "HIGH",
                "tableRva": 16384,
                "registerNativesCallsiteRva": 4352,
                "findClassCallsiteRva": 4320,
                "classEvidence": "FUNCTION_FINDCLASS_STRING_AND_REGISTER_NATIVES",
            }
        ],
        "il2cppRegistrations": [
            {
                "kind": "CODEGEN_REGISTER",
                "rva": 12288,
                "symbolName": "il2cpp_codegen_register",
                "evidence": "DEFINED_SYMBOL",
                "confidence": "HIGH",
            }
        ],
        "il2cppCodegenCalls": [
            {
                "callsiteRva": 13000,
                "codeRegistrationRva": 20000,
                "metadataRegistrationRva": 22000,
                "codegenOptionsRva": None,
                "evidence": "DECOMPILER_PCODE_CALL_ARGUMENTS",
                "confidence": "HIGH",
            }
        ],
        "il2cppPointerTables": [
            {
                "ownerRva": 20000,
                "fieldOffsetBytes": 16,
                "entryCount": 128,
                "tableRva": 24000,
                "sampledEntries": 16,
                "executableEntries": 16,
                "sampleFunctionRvas": [4096, 8192],
                "confidence": "HIGH",
            }
        ],
        "il2cppCodegenModules": [
            {
                "ownerCodeRegistrationRva": 20000,
                "moduleRva": 26000,
                "moduleName": "Assembly-CSharp.dll",
                "methodPointerCount": 4,
                "methodPointersRva": 28000,
                "sampledMethodPointers": [{"slotIndex": 0, "functionRva": 4096}],
                "evidence": "CODE_REGISTRATION_MODULE_ARRAY_STRUCTURAL",
                "confidence": "HIGH",
            }
        ],
        "warnings": [],
    }


def setup_function() -> None:
    STORE.clear_for_tests()


def test_ingest_and_list_ghidra_result() -> None:
    assessment_id = _create_assessment()
    response = client.post(
        f"/v1/assessments/{assessment_id}/ghidra-results",
        json=_result(assessment_id),
    )
    assert response.status_code == 200
    assert response.json()["artifactSha256"] == "a" * 64

    listed = client.get(f"/v1/assessments/{assessment_id}/ghidra-results")
    assert listed.status_code == 200
    payload = listed.json()
    assert len(payload) == 1
    assert payload[0]["functions"][0]["name"] == "JNI_OnLoad"


def test_duplicate_result_is_idempotent_and_history_keeps_one_revision() -> None:
    assessment_id = _create_assessment()
    payload = _result(assessment_id)
    assert client.post(f"/v1/assessments/{assessment_id}/ghidra-results", json=payload).status_code == 200
    assert client.post(f"/v1/assessments/{assessment_id}/ghidra-results", json=payload).status_code == 200
    history = client.get(f"/v1/assessments/{assessment_id}/ghidra-results/history")
    assert history.status_code == 200
    assert len(history.json()) == 1
    assert len(history.json()[0]["resultSha256"]) == 64


def test_history_preserves_revisions_and_latest_endpoint_returns_newest() -> None:
    assessment_id = _create_assessment()
    assert client.post(
        f"/v1/assessments/{assessment_id}/ghidra-results", json=_result(assessment_id, function_size=64)
    ).status_code == 200
    assert client.post(
        f"/v1/assessments/{assessment_id}/ghidra-results", json=_result(assessment_id, function_size=96)
    ).status_code == 200

    history = client.get(f"/v1/assessments/{assessment_id}/ghidra-results/history").json()
    assert [item["revision"] for item in history] == [1, 2]
    latest = client.get(f"/v1/assessments/{assessment_id}/ghidra-results").json()
    assert latest[0]["functions"][0]["sizeBytes"] == 96


def test_assessment_is_readable_after_sqlite_store_reopen() -> None:
    assessment_id = _create_assessment()
    reopened = SQLiteStore(Path(STORE.path))
    assessment = reopened.get_assessment(__import__("uuid").UUID(assessment_id))
    assert assessment is not None
    assert assessment.request.organization == "Example Org"


def test_rejects_hash_mismatch() -> None:
    assessment_id = _create_assessment(sha="a" * 64)
    response = client.post(
        f"/v1/assessments/{assessment_id}/ghidra-results",
        json=_result(assessment_id, sha="b" * 64),
    )
    assert response.status_code == 409


def test_rejects_result_for_non_reverse_assessment() -> None:
    assessment_id = _create_assessment(reverse=False)
    response = client.post(
        f"/v1/assessments/{assessment_id}/ghidra-results",
        json=_result(assessment_id),
    )
    assert response.status_code == 409


def test_rejects_result_assessment_identity_mismatch() -> None:
    assessment_id = _create_assessment()
    response = client.post(
        f"/v1/assessments/{assessment_id}/ghidra-results",
        json=_result("00000000-0000-0000-0000-000000000000"),
    )
    assert response.status_code == 409


def test_legacy_schema_11_remains_importable() -> None:
    assessment_id = _create_assessment()
    payload = _result(assessment_id)
    payload["schemaVersion"] = "1.1"
    payload.pop("architecture", None)
    payload.pop("il2cppCodegenCalls", None)
    payload.pop("il2cppPointerTables", None)
    payload.pop("il2cppCodegenModules", None)
    for item in payload["jniRegistrations"]:
        item.pop("tableRva", None)
        item.pop("registerNativesCallsiteRva", None)
        item.pop("findClassCallsiteRva", None)
        item.pop("classEvidence", None)
    response = client.post(f"/v1/assessments/{assessment_id}/ghidra-results", json=payload)
    assert response.status_code == 200
    assert response.json()["schemaVersion"] == "1.1"


def test_legacy_schema_12_remains_importable() -> None:
    assessment_id = _create_assessment()
    payload = _result(assessment_id)
    payload["schemaVersion"] = "1.2"
    payload.pop("il2cppCodegenModules", None)
    response = client.post(f"/v1/assessments/{assessment_id}/ghidra-results", json=payload)
    assert response.status_code == 200
    assert response.json()["schemaVersion"] == "1.2"


def test_sync_returns_latest_ghidra_results_and_history() -> None:
    assessment_id = _create_assessment()
    assert client.post(f"/v1/assessments/{assessment_id}/ghidra-results", json=_result(assessment_id, function_size=64)).status_code == 200
    assert client.post(f"/v1/assessments/{assessment_id}/ghidra-results", json=_result(assessment_id, function_size=96)).status_code == 200
    response = client.get(f"/v1/assessments/{assessment_id}/sync")
    assert response.status_code == 200
    payload = response.json()
    assert payload["syncSchemaVersion"] == "1.1"
    assert len(payload["ghidraResults"]) == 1
    assert payload["ghidraResults"][0]["functions"][0]["sizeBytes"] == 96
    assert [item["revision"] for item in payload["ghidraHistory"]] == [1, 2]


def test_v1_requires_api_key() -> None:
    unauthenticated = TestClient(app)
    response = unauthenticated.get("/v1/status")
    assert response.status_code == 401


def test_audit_chain_is_hash_linked_and_status_verifies_it() -> None:
    assessment_id = _create_assessment()
    assert client.post(f"/v1/assessments/{assessment_id}/ghidra-results", json=_result(assessment_id)).status_code == 200
    audit = client.get(f"/v1/assessments/{assessment_id}/audit").json()
    assert [item["eventType"] for item in audit] == ["ASSESSMENT_CREATED", "GHIDRA_RESULT_INGESTED"]
    assert audit[0]["previousHash"] is None
    assert audit[1]["previousHash"] == audit[0]["eventHash"]
    assert len(audit[1]["eventHash"]) == 64
    status = client.get("/v1/status")
    assert status.status_code == 200
    assert status.json()["authRequired"] is True
    assert status.json()["auditChainValid"] is True
    assert status.json()["databaseSchemaVersion"] == "3"


def test_sync_schema_11_exposes_audit_tail_hash() -> None:
    assessment_id = _create_assessment()
    response = client.get(f"/v1/assessments/{assessment_id}/sync")
    assert response.status_code == 200
    assert response.json()["syncSchemaVersion"] == "1.1"
    assert len(response.json()["auditTailHash"]) == 64


def test_x_api_key_header_is_supported() -> None:
    alternate = TestClient(app)
    response = alternate.get("/v1/status", headers={"X-API-Key": "unirevlab-test-token-0001"})
    assert response.status_code == 200


def test_auth_configuration_fails_closed_without_key_or_lab_override() -> None:
    previous_keys = os.environ.pop("UNIREVLAB_COORDINATOR_API_KEYS", None)
    previous_lab = os.environ.pop("UNIREVLAB_ALLOW_ANONYMOUS_LAB", None)
    try:
        response = TestClient(app).get("/v1/status")
        assert response.status_code == 503
    finally:
        if previous_keys is not None:
            os.environ["UNIREVLAB_COORDINATOR_API_KEYS"] = previous_keys
        if previous_lab is not None:
            os.environ["UNIREVLAB_ALLOW_ANONYMOUS_LAB"] = previous_lab


def test_rbac_viewer_can_read_but_cannot_write() -> None:
    previous = os.environ.get("UNIREVLAB_COORDINATOR_KEYS_JSON")
    os.environ["UNIREVLAB_COORDINATOR_KEYS_JSON"] = '[{"id":"viewer-1","secret":"viewer-token-0000000001","role":"VIEWER"}]'
    try:
        viewer = TestClient(app)
        headers = {"Authorization": "Bearer viewer-token-0000000001"}
        who = viewer.get("/v1/whoami", headers=headers)
        assert who.status_code == 200
        assert who.json()["role"] == "VIEWER"
        write = viewer.post(
            "/v1/assessments",
            headers=headers,
            json={
                "project_name": "Denied write",
                "organization": "Example Org",
                "purpose": "RBAC regression",
                "artifact_sha256": "f" * 64,
                "modes": ["static"],
                "authority_confirmed": True,
            },
        )
        assert write.status_code == 403
        assert viewer.get("/v1/status", headers=headers).status_code == 200
    finally:
        if previous is None:
            os.environ.pop("UNIREVLAB_COORDINATOR_KEYS_JSON", None)
        else:
            os.environ["UNIREVLAB_COORDINATOR_KEYS_JSON"] = previous


def test_admin_can_read_global_audit_and_analyst_cannot() -> None:
    assessment_id = _create_assessment()
    assert assessment_id
    previous = os.environ.get("UNIREVLAB_COORDINATOR_KEYS_JSON")
    os.environ["UNIREVLAB_COORDINATOR_KEYS_JSON"] = '[{"id":"admin-1","secret":"admin-token-00000000001","role":"ADMIN"},{"id":"analyst-1","secret":"analyst-token-000000001","role":"ANALYST"}]'
    try:
        admin = TestClient(app)
        assert admin.get("/v1/audit", headers={"Authorization": "Bearer admin-token-00000000001"}).status_code == 200
        assert admin.get("/v1/audit", headers={"Authorization": "Bearer analyst-token-000000001"}).status_code == 403
    finally:
        if previous is None:
            os.environ.pop("UNIREVLAB_COORDINATOR_KEYS_JSON", None)
        else:
            os.environ["UNIREVLAB_COORDINATOR_KEYS_JSON"] = previous


def test_key_rotation_windows_reject_expired_and_accept_active_key() -> None:
    previous = os.environ.get("UNIREVLAB_COORDINATOR_KEYS_JSON")
    os.environ["UNIREVLAB_COORDINATOR_KEYS_JSON"] = (
        '[{"id":"old","secret":"old-rotation-token-00001","role":"ANALYST","notAfter":"2020-01-01T00:00:00Z"},'
        '{"id":"new","secret":"new-rotation-token-00001","role":"ANALYST","notBefore":"2020-01-01T00:00:00Z","notAfter":"2099-01-01T00:00:00Z"}]'
    )
    try:
        rotated = TestClient(app)
        assert rotated.get("/v1/status", headers={"Authorization": "Bearer old-rotation-token-00001"}).status_code == 401
        response = rotated.get("/v1/status", headers={"Authorization": "Bearer new-rotation-token-00001"})
        assert response.status_code == 200
        assert response.json()["activeKeyCount"] == 1
    finally:
        if previous is None:
            os.environ.pop("UNIREVLAB_COORDINATOR_KEYS_JSON", None)
        else:
            os.environ["UNIREVLAB_COORDINATOR_KEYS_JSON"] = previous
