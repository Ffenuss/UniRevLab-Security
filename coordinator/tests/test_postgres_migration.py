from pathlib import Path
import json

from app.main import Assessment, AssessmentCreate, AssessmentMode, SQLiteStore
from app.migration_export import export
from datetime import datetime, timezone
from uuid import UUID


def test_postgres_ddl_tracks_sqlite_schema_v3() -> None:
    ddl = Path("migrations/postgresql/001_initial.sql").read_text()
    for table in ("assessments", "ghidra_results", "coordinator_meta", "audit_events"):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in ddl
    assert "schema_version', '3'" in ddl
    assert "JSONB" in ddl


def test_sqlite_export_is_deterministic_and_hashes_every_table(tmp_path: Path) -> None:
    db = tmp_path / "coordinator.sqlite3"
    store = SQLiteStore(db)
    assessment = Assessment(
        id=UUID("11111111-2222-3333-4444-555555555555"),
        created_at=datetime(2026, 8, 30, tzinfo=timezone.utc),
        status="created",
        request=AssessmentCreate(
            project_name="migration-fixture",
            organization="Example",
            purpose="migration regression",
            artifact_sha256="a" * 64,
            modes={AssessmentMode.STATIC},
            authority_confirmed=True,
        ),
    )
    store.put_assessment(assessment)
    store.append_audit(actor_fingerprint="fixture", event_type="ASSESSMENT_IMPORTED", assessment_id=assessment.id, object_sha256="a" * 64)
    first = export(db, tmp_path / "first")
    second = export(db, tmp_path / "second")
    assert first["tables"] == second["tables"]
    assert [item["name"] for item in first["tables"]] == ["assessments", "ghidra_results", "coordinator_meta", "audit_events"]
    assert json.loads((tmp_path / "first" / "migration-manifest.json").read_text())["schemaVersion"] == "1.0"
