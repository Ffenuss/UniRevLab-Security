from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, field_validator

app = FastAPI(title="UniRevLab Coordinator", version="0.22.0-dev-performance-ux")


class AssessmentMode(StrEnum):
    STATIC = "static"
    REVERSE = "reverse"
    DYNAMIC = "dynamic"
    NETWORK = "network"


class CoordinatorRole(StrEnum):
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    ADMIN = "ADMIN"


ROLE_LEVEL = {
    CoordinatorRole.VIEWER: 10,
    CoordinatorRole.ANALYST: 20,
    CoordinatorRole.ADMIN: 30,
}


class AuthPrincipal(BaseModel):
    keyId: str
    role: CoordinatorRole
    fingerprint: str


class CoordinatorKeyRecord(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    secret: str = Field(min_length=16, max_length=512)
    role: CoordinatorRole = CoordinatorRole.ANALYST
    notBefore: datetime | None = None
    notAfter: datetime | None = None

    @field_validator("notAfter")
    @classmethod
    def validate_not_after(cls, value: datetime | None) -> datetime | None:
        return value


class AssessmentCreate(BaseModel):
    project_name: str = Field(min_length=1, max_length=160)
    organization: str = Field(min_length=1, max_length=200)
    purpose: str = Field(min_length=1, max_length=1000)
    artifact_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    modes: set[AssessmentMode] = Field(min_length=1, max_length=4)
    authority_confirmed: bool

    @field_validator("artifact_sha256")
    @classmethod
    def normalize_artifact_hash(cls, value: str) -> str:
        return value.lower()


class Assessment(BaseModel):
    id: UUID
    created_at: datetime
    status: str
    request: AssessmentCreate


class AssessmentUpsert(AssessmentCreate):
    created_at_epoch_ms: int = Field(ge=0)


class GhidraEngine(BaseModel):
    name: str
    version: str = Field(min_length=1, max_length=80)
    pyGhidra: bool
    analysisProfile: str




class GhidraArchitecture(BaseModel):
    processor: str = Field(min_length=1, max_length=128)
    pointerSize: int = Field(ge=4, le=8)
    endian: str

    @field_validator("pointerSize")
    @classmethod
    def validate_pointer_size(cls, value: int) -> int:
        if value not in {4, 8}:
            raise ValueError("Unsupported pointer size")
        return value

    @field_validator("endian")
    @classmethod
    def validate_endian(cls, value: str) -> str:
        if value not in {"LITTLE", "BIG"}:
            raise ValueError("Unsupported endianness")
        return value


class GhidraCoverage(BaseModel):
    functionsDiscovered: int = Field(ge=0)
    functionsReported: int = Field(ge=0)
    cfgBlocksReported: int = Field(ge=0)
    xrefsReported: int = Field(ge=0)
    decompilerFunctionsReported: int = Field(ge=0)
    truncated: bool


class GhidraFunction(BaseModel):
    rva: int = Field(ge=0)
    name: str = Field(max_length=1024)
    namespace: str = Field(max_length=1024)
    signature: str = Field(max_length=4096)
    sizeBytes: int = Field(ge=0)
    isThunk: bool
    decompilerPreview: str | None = Field(default=None, max_length=32768)


class GhidraCfgBlock(BaseModel):
    startRva: int = Field(ge=0)
    endRva: int = Field(ge=0)
    flowType: str = Field(max_length=80)


class GhidraCfgEdge(BaseModel):
    fromRva: int = Field(ge=0)
    toRva: int = Field(ge=0)
    kind: str = Field(max_length=40)


class GhidraFunctionCfg(BaseModel):
    functionRva: int = Field(ge=0)
    blocks: list[GhidraCfgBlock] = Field(max_length=20000)
    edges: list[GhidraCfgEdge] = Field(max_length=50000)


class GhidraXref(BaseModel):
    fromRva: int = Field(ge=0)
    toRva: int = Field(ge=0)
    kind: str = Field(max_length=40)


class GhidraJniRegistration(BaseModel):
    source: str = Field(max_length=80)
    className: str = Field(max_length=2048)
    methodName: str = Field(max_length=1024)
    signature: str = Field(max_length=4096)
    functionRva: int = Field(ge=0)
    confidence: str = Field(max_length=20)
    tableRva: int | None = Field(default=None, ge=0)
    registerNativesCallsiteRva: int | None = Field(default=None, ge=0)
    findClassCallsiteRva: int | None = Field(default=None, ge=0)
    classEvidence: str | None = Field(default=None, max_length=128)


class GhidraIl2CppRegistration(BaseModel):
    kind: str = Field(max_length=80)
    rva: int = Field(ge=0)
    symbolName: str = Field(max_length=2048)
    evidence: str = Field(max_length=80)
    confidence: str = Field(max_length=20)




class GhidraIl2CppCodegenCall(BaseModel):
    callsiteRva: int = Field(ge=0)
    codeRegistrationRva: int | None = Field(default=None, ge=0)
    metadataRegistrationRva: int | None = Field(default=None, ge=0)
    codegenOptionsRva: int | None = Field(default=None, ge=0)
    evidence: str = Field(max_length=80)
    confidence: str = Field(max_length=20)


class GhidraIl2CppPointerTable(BaseModel):
    ownerRva: int = Field(ge=0)
    fieldOffsetBytes: int = Field(ge=0, le=4096)
    entryCount: int = Field(ge=1, le=5_000_000)
    tableRva: int = Field(ge=0)
    sampledEntries: int = Field(ge=1, le=32)
    executableEntries: int = Field(ge=1, le=32)
    sampleFunctionRvas: list[int] = Field(default_factory=list, max_length=16)
    confidence: str = Field(max_length=20)


class GhidraIl2CppMethodPointerSlot(BaseModel):
    slotIndex: int = Field(ge=0, le=5_000_000)
    functionRva: int = Field(ge=0)


class GhidraIl2CppCodegenModule(BaseModel):
    ownerCodeRegistrationRva: int = Field(ge=0)
    moduleRva: int = Field(ge=0)
    moduleName: str = Field(min_length=1, max_length=512)
    methodPointerCount: int = Field(ge=0, le=5_000_000)
    methodPointersRva: int = Field(ge=0)
    sampledMethodPointers: list[GhidraIl2CppMethodPointerSlot] = Field(default_factory=list, max_length=4096)
    evidence: str = Field(max_length=128)
    confidence: str = Field(max_length=20)


class GhidraResult(BaseModel):
    schemaVersion: str
    assessmentId: str = Field(min_length=1, max_length=200)
    artifactSha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    libraryEntry: str = Field(min_length=1, max_length=4096)
    status: str
    engine: GhidraEngine
    architecture: GhidraArchitecture | None = None
    coverage: GhidraCoverage
    functions: list[GhidraFunction] = Field(max_length=100000)
    cfg: list[GhidraFunctionCfg] = Field(max_length=100000)
    xrefs: list[GhidraXref] = Field(max_length=500000)
    jniRegistrations: list[GhidraJniRegistration] = Field(max_length=100000)
    il2cppRegistrations: list[GhidraIl2CppRegistration] = Field(max_length=100000)
    il2cppCodegenCalls: list[GhidraIl2CppCodegenCall] = Field(default_factory=list, max_length=256)
    il2cppPointerTables: list[GhidraIl2CppPointerTable] = Field(default_factory=list, max_length=256)
    il2cppCodegenModules: list[GhidraIl2CppCodegenModule] = Field(default_factory=list, max_length=256)
    warnings: list[str] = Field(max_length=1000)

    @field_validator("schemaVersion")
    @classmethod
    def require_supported_schema(cls, value: str) -> str:
        if value not in {"1.1", "1.2", "1.3"}:
            raise ValueError("Unsupported Ghidra result schema")
        return value

    @field_validator("artifactSha256")
    @classmethod
    def normalize_artifact_hash(cls, value: str) -> str:
        return value.lower()

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        if value not in {"COMPLETE", "PARTIAL", "FAILED"}:
            raise ValueError("Invalid Ghidra result status")
        return value

    @field_validator("engine")
    @classmethod
    def validate_engine(cls, value: GhidraEngine) -> GhidraEngine:
        if value.name != "Ghidra":
            raise ValueError("Unexpected native analysis engine")
        if value.analysisProfile not in {"DEFAULT", "DEEP"}:
            raise ValueError("Invalid Ghidra analysis profile")
        return value


class GhidraResultHistoryItem(BaseModel):
    revision: int
    libraryEntry: str
    ingestedAt: datetime
    resultSha256: str
    status: str
    engineVersion: str


class AuditEvent(BaseModel):
    sequence: int
    createdAt: datetime
    actorFingerprint: str
    eventType: str
    assessmentId: str | None = None
    objectSha256: str | None = None
    previousHash: str | None = None
    eventHash: str


class CoordinatorStatus(BaseModel):
    version: str = "0.22.0-dev-performance-ux"
    databaseSchemaVersion: str = "3"
    authRequired: bool
    activeKeyCount: int
    auditChainValid: bool


class WhoAmIResponse(BaseModel):
    keyId: str
    role: CoordinatorRole
    fingerprint: str


class AssessmentSyncResponse(BaseModel):
    syncSchemaVersion: str = "1.1"
    generatedAt: datetime
    assessment: Assessment
    ghidraResults: list[GhidraResult]
    ghidraHistory: list[GhidraResultHistoryItem]
    auditTailHash: str | None = None


def _configured_api_keys() -> list[str]:
    """Legacy compatibility: every legacy key receives ANALYST privileges."""
    raw = os.environ.get("UNIREVLAB_COORDINATOR_API_KEYS", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _allow_anonymous_lab() -> bool:
    return os.environ.get("UNIREVLAB_ALLOW_ANONYMOUS_LAB", "").strip().lower() in {"1", "true", "yes"}


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def _configured_key_records(now: datetime | None = None) -> list[CoordinatorKeyRecord]:
    now = now or datetime.now(timezone.utc)
    raw_json = os.environ.get("UNIREVLAB_COORDINATOR_KEYS_JSON", "").strip()
    records: list[CoordinatorKeyRecord] = []
    if raw_json:
        try:
            payload = json.loads(raw_json)
            if not isinstance(payload, list) or len(payload) > 128:
                raise ValueError("key set must be an array with at most 128 entries")
            records = [CoordinatorKeyRecord.model_validate(item) for item in payload]
        except Exception as exc:
            raise RuntimeError(f"Invalid UNIREVLAB_COORDINATOR_KEYS_JSON: {exc}") from exc
    else:
        records = [
            CoordinatorKeyRecord(id=f"legacy-{index + 1}", secret=key, role=CoordinatorRole.ANALYST)
            for index, key in enumerate(_configured_api_keys())
        ]
    active: list[CoordinatorKeyRecord] = []
    seen_ids: set[str] = set()
    for record in records:
        if record.id in seen_ids:
            raise RuntimeError(f"Duplicate coordinator key id: {record.id}")
        seen_ids.add(record.id)
        before = record.notBefore
        after = record.notAfter
        if before is not None and before.tzinfo is None:
            before = before.replace(tzinfo=timezone.utc)
        if after is not None and after.tzinfo is None:
            after = after.replace(tzinfo=timezone.utc)
        if before is not None and after is not None and after <= before:
            raise RuntimeError(f"Coordinator key {record.id} has invalid rotation window")
        if before is not None and now < before:
            continue
        if after is not None and now >= after:
            continue
        active.append(record)
    return active


def _authenticate(
    authorization: str | None,
    x_api_key: str | None,
) -> AuthPrincipal:
    try:
        records = _configured_key_records()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not records:
        if _allow_anonymous_lab():
            return AuthPrincipal(keyId="anonymous-lab", role=CoordinatorRole.ADMIN, fingerprint="anonymous-lab")
        raise HTTPException(status_code=503, detail="Coordinator authentication is not configured")

    candidate = None
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer" and value.strip():
            candidate = value.strip()
    if candidate is None and x_api_key:
        candidate = x_api_key.strip()
    if candidate is None or not (16 <= len(candidate) <= 512):
        raise HTTPException(status_code=401, detail="Coordinator API key is required", headers={"WWW-Authenticate": "Bearer"})
    candidate_digest = hashlib.sha256(candidate.encode("utf-8")).digest()
    matched: CoordinatorKeyRecord | None = None
    # Evaluate every active record so comparison cost does not reveal the first matching key position.
    for record in records:
        equal = hmac.compare_digest(candidate_digest, hashlib.sha256(record.secret.encode("utf-8")).digest())
        if equal:
            matched = record
    if matched is None:
        raise HTTPException(status_code=401, detail="Invalid or inactive coordinator API key", headers={"WWW-Authenticate": "Bearer"})
    return AuthPrincipal(keyId=matched.id, role=matched.role, fingerprint=_token_fingerprint(candidate))


def _require_role(
    minimum: CoordinatorRole,
    authorization: str | None,
    x_api_key: str | None,
) -> AuthPrincipal:
    principal = _authenticate(authorization, x_api_key)
    if ROLE_LEVEL[principal.role] < ROLE_LEVEL[minimum]:
        raise HTTPException(status_code=403, detail=f"{minimum.value} role required")
    return principal


def require_viewer(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> AuthPrincipal:
    return _require_role(CoordinatorRole.VIEWER, authorization, x_api_key)


def require_analyst(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> AuthPrincipal:
    return _require_role(CoordinatorRole.ANALYST, authorization, x_api_key)


def require_admin(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> AuthPrincipal:
    return _require_role(CoordinatorRole.ADMIN, authorization, x_api_key)


class SQLiteStore:
    """Deterministic SQLite reference store; PostgreSQL migration DDL/export are versioned alongside it."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _init_schema(self) -> None:
        with self._connect() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS assessments (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    request_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ghidra_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                    library_entry TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    result_sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    UNIQUE(assessment_id, library_entry, result_sha256)
                );
                CREATE INDEX IF NOT EXISTS idx_ghidra_assessment_library_revision
                    ON ghidra_results(assessment_id, library_entry, id DESC);
                CREATE TABLE IF NOT EXISTS coordinator_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    actor_fingerprint TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    assessment_id TEXT,
                    object_sha256 TEXT,
                    event_json TEXT NOT NULL,
                    previous_hash TEXT,
                    event_hash TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS idx_audit_assessment_id
                    ON audit_events(assessment_id, id ASC);
                """
            )
            db.execute("INSERT OR REPLACE INTO coordinator_meta(key, value) VALUES ('schema_version', '3')")

    def clear_for_tests(self) -> None:
        with self._connect() as db:
            db.execute("DELETE FROM audit_events")
            db.execute("DELETE FROM ghidra_results")
            db.execute("DELETE FROM assessments")

    def put_assessment(self, assessment: Assessment) -> None:
        request_json = assessment.request.model_dump_json()
        with self._connect() as db:
            db.execute(
                "INSERT INTO assessments(id, created_at, status, request_json) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO NOTHING",
                (str(assessment.id), assessment.created_at.isoformat(), assessment.status, request_json),
            )

    def get_assessment(self, assessment_id: UUID) -> Assessment | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM assessments WHERE id = ?", (str(assessment_id),)).fetchone()
        if row is None:
            return None
        return Assessment(
            id=UUID(row["id"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            status=row["status"],
            request=AssessmentCreate.model_validate_json(row["request_json"]),
        )

    @staticmethod
    def _canonical_result(result: GhidraResult) -> tuple[str, str]:
        payload = json.dumps(result.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return payload, digest

    def put_ghidra_result(self, assessment_id: UUID, result: GhidraResult) -> tuple[str, bool]:
        payload, digest = self._canonical_result(result)
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as db:
            cursor = db.execute(
                """
                INSERT OR IGNORE INTO ghidra_results(
                    assessment_id, library_entry, ingested_at, result_sha256, payload_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (str(assessment_id), result.libraryEntry, now, digest, payload),
            )
            inserted = cursor.rowcount > 0
        return digest, inserted

    def list_latest_ghidra_results(self, assessment_id: UUID) -> list[GhidraResult]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT g.payload_json
                FROM ghidra_results g
                JOIN (
                    SELECT library_entry, MAX(id) AS latest_id
                    FROM ghidra_results
                    WHERE assessment_id = ?
                    GROUP BY library_entry
                ) latest ON latest.latest_id = g.id
                ORDER BY g.library_entry ASC
                """,
                (str(assessment_id),),
            ).fetchall()
        return [GhidraResult.model_validate_json(row["payload_json"]) for row in rows]

    def ghidra_history(self, assessment_id: UUID) -> list[GhidraResultHistoryItem]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT id, library_entry, ingested_at, result_sha256, payload_json
                FROM ghidra_results
                WHERE assessment_id = ?
                ORDER BY id ASC
                """,
                (str(assessment_id),),
            ).fetchall()
        history: list[GhidraResultHistoryItem] = []
        revisions: dict[str, int] = {}
        for row in rows:
            library = row["library_entry"]
            revisions[library] = revisions.get(library, 0) + 1
            result = GhidraResult.model_validate_json(row["payload_json"])
            history.append(
                GhidraResultHistoryItem(
                    revision=revisions[library],
                    libraryEntry=library,
                    ingestedAt=datetime.fromisoformat(row["ingested_at"]),
                    resultSha256=row["result_sha256"],
                    status=result.status,
                    engineVersion=result.engine.version,
                )
            )
        return history


    def append_audit(
        self,
        *,
        actor_fingerprint: str,
        event_type: str,
        assessment_id: UUID | None = None,
        object_sha256: str | None = None,
        details: dict[str, object] | None = None,
    ) -> AuditEvent:
        now = datetime.now(timezone.utc)
        body = {
            "createdAt": now.isoformat(),
            "actorFingerprint": actor_fingerprint,
            "eventType": event_type,
            "assessmentId": str(assessment_id) if assessment_id else None,
            "objectSha256": object_sha256,
            "details": details or {},
        }
        canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
            previous_hash = previous["event_hash"] if previous else None
            digest = hashlib.sha256(((previous_hash or "") + "\n" + canonical).encode("utf-8")).hexdigest()
            cursor = db.execute(
                """
                INSERT INTO audit_events(
                    created_at, actor_fingerprint, event_type, assessment_id, object_sha256, event_json, previous_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (now.isoformat(), actor_fingerprint, event_type, str(assessment_id) if assessment_id else None, object_sha256, canonical, previous_hash, digest),
            )
            sequence = int(cursor.lastrowid)
        return AuditEvent(
            sequence=sequence,
            createdAt=now,
            actorFingerprint=actor_fingerprint,
            eventType=event_type,
            assessmentId=str(assessment_id) if assessment_id else None,
            objectSha256=object_sha256,
            previousHash=previous_hash,
            eventHash=digest,
        )

    def audit_events(self, assessment_id: UUID | None = None, limit: int = 500) -> list[AuditEvent]:
        limit = max(1, min(limit, 5000))
        with self._connect() as db:
            if assessment_id is None:
                rows = db.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM audit_events WHERE assessment_id = ? ORDER BY id DESC LIMIT ?",
                    (str(assessment_id), limit),
                ).fetchall()
        return [
            AuditEvent(
                sequence=row["id"],
                createdAt=datetime.fromisoformat(row["created_at"]),
                actorFingerprint=row["actor_fingerprint"],
                eventType=row["event_type"],
                assessmentId=row["assessment_id"],
                objectSha256=row["object_sha256"],
                previousHash=row["previous_hash"],
                eventHash=row["event_hash"],
            )
            for row in reversed(rows)
        ]

    def audit_tail_hash(self) -> str | None:
        with self._connect() as db:
            row = db.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        return row["event_hash"] if row else None

    def verify_audit_chain(self) -> bool:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
        previous_hash: str | None = None
        for row in rows:
            if row["previous_hash"] != previous_hash:
                return False
            digest = hashlib.sha256(((previous_hash or "") + "\n" + row["event_json"]).encode("utf-8")).hexdigest()
            if not hmac.compare_digest(digest, row["event_hash"]):
                return False
            previous_hash = row["event_hash"]
        return True

    def quick_check(self) -> bool:
        with self._connect() as db:
            row = db.execute("PRAGMA quick_check").fetchone()
        return bool(row and row[0] == "ok")


DEFAULT_DB = Path(os.environ.get("UNIREVLAB_COORDINATOR_DB", ".unirevlab/coordinator.sqlite3"))
STORE = SQLiteStore(DEFAULT_DB)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/status", response_model=CoordinatorStatus)
def coordinator_status(actor: AuthPrincipal = Depends(require_viewer)) -> CoordinatorStatus:
    if not STORE.quick_check():
        raise HTTPException(status_code=503, detail="Coordinator database integrity check failed")
    return CoordinatorStatus(
        authRequired=not _allow_anonymous_lab(),
        activeKeyCount=len(_configured_key_records()),
        auditChainValid=STORE.verify_audit_chain(),
    )


@app.get("/v1/whoami", response_model=WhoAmIResponse)
def whoami(actor: AuthPrincipal = Depends(require_viewer)) -> WhoAmIResponse:
    return WhoAmIResponse(keyId=actor.keyId, role=actor.role, fingerprint=actor.fingerprint)


@app.get("/v1/audit", response_model=list[AuditEvent])
def global_audit(limit: int = 500, actor: AuthPrincipal = Depends(require_admin)) -> list[AuditEvent]:
    return STORE.audit_events(limit=limit)


@app.get("/v1/assessments/{assessment_id}/audit", response_model=list[AuditEvent])
def assessment_audit(assessment_id: UUID, limit: int = 500, actor: AuthPrincipal = Depends(require_viewer)) -> list[AuditEvent]:
    if STORE.get_assessment(assessment_id) is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return STORE.audit_events(assessment_id, limit=limit)


@app.post("/v1/assessments", response_model=Assessment)
def create_assessment(request: AssessmentCreate, actor: AuthPrincipal = Depends(require_analyst)) -> Assessment:
    if not request.authority_confirmed:
        raise HTTPException(status_code=400, detail="Authorization confirmation is required")
    assessment = Assessment(
        id=uuid4(),
        created_at=datetime.now(timezone.utc),
        status="created",
        request=request,
    )
    STORE.put_assessment(assessment)
    STORE.append_audit(
        actor_fingerprint=actor.fingerprint,
        event_type="ASSESSMENT_CREATED",
        assessment_id=assessment.id,
        object_sha256=request.artifact_sha256,
        details={"keyId": actor.keyId, "role": actor.role.value},
    )
    return assessment


@app.put("/v1/assessments/{assessment_id}", response_model=Assessment)
def upsert_assessment(assessment_id: UUID, request: AssessmentUpsert, actor: AuthPrincipal = Depends(require_analyst)) -> Assessment:
    if not request.authority_confirmed:
        raise HTTPException(status_code=400, detail="Authorization confirmation is required")
    requested = AssessmentCreate(**request.model_dump(exclude={"created_at_epoch_ms"}))
    existing = STORE.get_assessment(assessment_id)
    if existing is not None:
        # Assessment identity/scope is immutable once a coordinator has observed it.
        if existing.request != requested:
            raise HTTPException(status_code=409, detail="Assessment scope or artifact identity mismatch")
        return existing
    created_at = datetime.fromtimestamp(request.created_at_epoch_ms / 1000.0, tz=timezone.utc)
    assessment = Assessment(id=assessment_id, created_at=created_at, status="created", request=requested)
    STORE.put_assessment(assessment)
    STORE.append_audit(
        actor_fingerprint=actor.fingerprint,
        event_type="ASSESSMENT_IMPORTED",
        assessment_id=assessment.id,
        object_sha256=requested.artifact_sha256,
        details={"keyId": actor.keyId, "role": actor.role.value},
    )
    return assessment


@app.get("/v1/assessments/{assessment_id}", response_model=Assessment)
def get_assessment(assessment_id: UUID, actor: AuthPrincipal = Depends(require_viewer)) -> Assessment:
    assessment = STORE.get_assessment(assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment


@app.post("/v1/assessments/{assessment_id}/ghidra-results", response_model=GhidraResult)
def ingest_ghidra_result(assessment_id: UUID, result: GhidraResult, actor: AuthPrincipal = Depends(require_analyst)) -> GhidraResult:
    assessment = STORE.get_assessment(assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    if AssessmentMode.REVERSE not in assessment.request.modes:
        raise HTTPException(status_code=409, detail="Assessment does not authorize reverse-engineering mode")
    if result.assessmentId != str(assessment_id):
        raise HTTPException(status_code=409, detail="Ghidra result assessment identity mismatch")
    if result.artifactSha256 != assessment.request.artifact_sha256:
        raise HTTPException(status_code=409, detail="Ghidra result artifact hash mismatch")

    digest, inserted = STORE.put_ghidra_result(assessment_id, result)
    if inserted:
        STORE.append_audit(
            actor_fingerprint=actor.fingerprint,
            event_type="GHIDRA_RESULT_INGESTED",
            assessment_id=assessment_id,
            object_sha256=digest,
            details={"libraryEntry": result.libraryEntry, "schemaVersion": result.schemaVersion, "keyId": actor.keyId, "role": actor.role.value},
        )
    return result


@app.get("/v1/assessments/{assessment_id}/ghidra-results", response_model=list[GhidraResult])
def list_ghidra_results(assessment_id: UUID, actor: AuthPrincipal = Depends(require_viewer)) -> list[GhidraResult]:
    if STORE.get_assessment(assessment_id) is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return STORE.list_latest_ghidra_results(assessment_id)


@app.get("/v1/assessments/{assessment_id}/ghidra-results/history", response_model=list[GhidraResultHistoryItem])
def list_ghidra_result_history(assessment_id: UUID, actor: AuthPrincipal = Depends(require_viewer)) -> list[GhidraResultHistoryItem]:
    if STORE.get_assessment(assessment_id) is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return STORE.ghidra_history(assessment_id)


@app.get("/v1/assessments/{assessment_id}/sync", response_model=AssessmentSyncResponse)
def sync_assessment(assessment_id: UUID, actor: AuthPrincipal = Depends(require_viewer)) -> AssessmentSyncResponse:
    assessment = STORE.get_assessment(assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return AssessmentSyncResponse(
        generatedAt=datetime.now(timezone.utc),
        assessment=assessment,
        ghidraResults=STORE.list_latest_ghidra_results(assessment_id),
        ghidraHistory=STORE.ghidra_history(assessment_id),
        auditTailHash=STORE.audit_tail_hash(),
    )
