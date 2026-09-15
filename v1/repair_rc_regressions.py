from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
V1 = ROOT / "v1"
TOUCHED: list[str] = []


def replace(rel: str, old: str, new: str, expected: int = 1) -> None:
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != expected:
        raise RuntimeError(f"{rel}: expected {expected} occurrence(s), found {count}: {old[:100]!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")
    if rel not in TOUCHED:
        TOUCHED.append(rel)
    print(f"patched: {rel}")


def run(*args: str, cwd: Path = ROOT, check: bool = True) -> subprocess.CompletedProcess:
    print("+", " ".join(args), flush=True)
    return subprocess.run(args, cwd=cwd, check=check)


def restore() -> None:
    if TOUCHED:
        subprocess.run(["git", "restore", "--", *TOUCHED], cwd=ROOT, check=False)


def main() -> int:
    if run("git", "rev-parse", "--abbrev-ref", "HEAD", check=False).returncode != 0:
        return 2
    branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=ROOT, text=True).strip()
    if branch != "Modkit1":
        print(f"ERROR: expected Modkit1, got {branch}", file=sys.stderr)
        return 2
    if subprocess.run(["git", "diff", "--quiet"], cwd=ROOT).returncode != 0 or subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT).returncode != 0:
        print("ERROR: tracked workspace is not clean", file=sys.stderr)
        return 2

    try:
        # Real correctness fix: a metadata-token conflict must suppress every
        # qualified confirmation path, even when Class::Method independently exists.
        replace(
            "v1/modkit/mobile/il2cpp_metadata_identity.py",
            "            qualified_confirmed = bool(pair_confirmed or (token_confirmed and token_class))",
            "            qualified_confirmed = bool(not token_conflict and (pair_confirmed or (token_confirmed and token_class)))",
        )

        # Keep the private streaming reader callable without an Android cancel gate.
        replace(
            "v1/modkit/mobile/connected_report_streaming.py",
            "def _filtered_reader(workdir: str | Path, gate: _Gate) -> tuple[Callable[[Path], Iterator[dict[str, Any]]], dict[str, int]]:",
            "def _filtered_reader(workdir: str | Path, gate: _Gate | None = None) -> tuple[Callable[[Path], Iterator[dict[str, Any]]], dict[str, int]]:",
        )

        # RC regression contracts: update stale assertions to the hardened release architecture.
        replace(
            "v1/tests/test_dev35_app_ux.py",
            "    assert 'mod.setEnabled(!app.busy.get()&&(ready>0||actionable>0||important>0))' in auto\n",
            "    assert 'autoModAllowedForRun(run,current)' in auto\n    assert 'mod.setEnabled(!app.busy.get()&&autoModAllowedForRun(run,current)&&(ready>0||actionable>0||important>0))' in auto\n",
        )
        replace(
            "v1/tests/test_dev35_app_ux.py",
            "    assert '\"menu_smart_prepare\"' in automod\n    assert '\"menu_preflight\"' in automod\n    assert '\"menu_smart_build_apk\"' in automod\n",
            "    assert \"AutoModPrepareService.class\" in automod\n    assert '\"menu_preflight\"' in automod\n    assert '\"menu_build_apk\"' in automod\n    assert '\"menu_smart_prepare\"' not in automod\n    assert '\"menu_smart_build_apk\"' not in automod\n",
        )

        replace(
            "v1/tests/test_v1_apktool_cache_freshness.py",
            "    assert 'expectedCount == current.optInt(\"fileCount\", -2)' in text\n",
            "    assert 'expectedCount != current.optInt(\"fileCount\", -2)' in text\n",
        )
        replace(
            "v1/tests/test_v1_apktool_cache_freshness.py",
            "    assert 'expectedBytes == current.optLong(\"bytes\", -2L)' in text\n",
            "    assert 'expectedBytes != current.optLong(\"bytes\", -2L)' in text\n",
        )

        for old, new in (
            ("    assert 'getModule(\"modkit.mobile.automod\")' in activity\n", "    assert 'getModule(\"modkit.mobile.automod_cancellable\")' in activity\n"),
            ("    assert 'build.setEnabled(idle&&prepareCount>0&&preflightReady)' in activity\n", "    assert 'build.setEnabled(idle&&prepareCount>0&&preflightReady&&exactPrepareAuditReady())' in activity\n"),
            ("    assert 'runtime VA observed' in activity\n", "    assert 'runtime VA ' in activity\n"),
            ("    assert 'runtimeVaHex' in activity\n", "    assert 'runtimeObservation' in activity\n"),
            ("    assert 'metadata identity/no-RVA' in activity\n", "    assert 'metadata/no-RVA' in activity\n"),
            ("    assert 'getModule(\"modkit.mobile.automod\")' in evidence\n", "    assert 'getModule(\"modkit.mobile.automod_cancellable\")' in evidence\n"),
            ("    assert 'getModule(\"modkit.mobile.il2cpp_no_rva_native\")' in evidence\n", "    assert 'getModule(\"modkit.mobile.il2cpp_no_rva_native_release\")' in evidence\n"),
        ):
            replace("v1/tests/test_v1_automod.py", old, new)

        replace(
            "v1/tests/test_v1_automod_compact_ui.py",
            "    assert '!audit.optBoolean(\"promotesBuildability\")' in source\n    assert '!audit.optBoolean(\"addressRecoveryPromotesBuildability\")' in source\n",
            "    verifier = Path(\"android/app/src/main/java/dev/modkit/mobile/AutoModAuditVerifier.java\").read_text(encoding=\"utf-8\")\n    assert 'audit.optBoolean(\"promotesBuildability\")||audit.optBoolean(\"addressRecoveryPromotesBuildability\")' in verifier\n    assert '\"EXACT_INPUT_SHA256\".equals(audit.optString(\"freshnessPolicy\"))' in verifier\n",
        )

        replace(
            "v1/tests/test_v1_automod_preflight_freshness_android.py",
            "    assert \"invalidatePreparedState();\" in activity\n",
            "    assert \"if(!invalidatePreparedState())\" in activity\n",
        )

        replace(
            "v1/tests/test_v1_connected_report_native_recovery.py",
            "    assert \"exact CodeGenModule\" in activity\n",
            "    assert \"exact recovery\" in activity\n",
        )

        replace(
            "v1/tests/test_v1_connected_report_v12.py",
            "getModule(\"modkit.mobile.connected_report_v12\")",
            "getModule(\"modkit.mobile.connected_report_streaming\")",
            expected=2,
        )

        replace(
            "v1/tests/test_v1_deep_output_cleanup.py",
            "    assert \"lua_deep.scan_workspace\" in pipeline\n",
            "    assert \"lua_deep_cancellable.scan_workspace\" in pipeline\n",
        )

        replace(
            "v1/tests/test_v1_embedded_cancel_flow.py",
            "    def artifact_scan(_root):\n",
            "    def artifact_scan(*_args, **_kwargs):\n",
        )
        replace(
            "v1/tests/test_v1_embedded_cancel_flow.py",
            "    monkeypatch.setattr(embedded_pipeline.lua_deep, \"scan_workspace\", lua_scan)\n",
            "    monkeypatch.setattr(embedded_pipeline.lua_deep_cancellable, \"scan_workspace\", lua_scan)\n",
        )

        replace(
            "v1/tests/test_v1_full_progress_surface.py",
            "    assert 'app.file(\"simple-progress.json\")' in source\n",
            "    assert 'writeAtomicJson(\"simple-progress.json\",row)' in source\n",
        )

        # AutoMod audit policy moved into the shared SHA verifier; tests follow the security boundary.
        replace(
            "v1/tests/test_v1_menu_native_recovery_audit.py",
            "    assert 'readRequiredAudit()' in source\n    assert 'app.file(\"menu-native-recovery.json\")' in source\n    assert 'if(!audit.optBoolean(\"completed\"))' in source\n    assert 'if(!audit.optBoolean(\"normalBindingRequired\")||!audit.optBoolean(\"preflightRequired\"))' in source\n    assert 'if(audit.optBoolean(\"promotesBuildability\")||audit.optBoolean(\"addressRecoveryPromotesBuildability\"))' in source\n",
            "    verifier = (ROOT / \"android/app/src/main/java/dev/modkit/mobile/AutoModAuditVerifier.java\").read_text(encoding=\"utf-8\")\n    assert 'AutoModAuditVerifier.verifyCurrent' in source\n    assert 'app.file(\"menu-native-recovery.json\")' in verifier\n    assert 'if(!audit.optBoolean(\"completed\"))' in verifier\n    assert 'if(!audit.optBoolean(\"normalBindingRequired\")||!audit.optBoolean(\"preflightRequired\"))' in verifier\n    assert 'if(audit.optBoolean(\"promotesBuildability\")||audit.optBoolean(\"addressRecoveryPromotesBuildability\"))' in verifier\n    assert '\"EXACT_INPUT_SHA256\".equals(audit.optString(\"freshnessPolicy\"))' in verifier\n",
        )
        replace(
            "v1/tests/test_v1_menu_native_recovery_audit.py",
            "    assert 'private boolean exactPrepareAuditReady()' in source\n    assert 'audit.optBoolean(\"completed\")' in source\n    assert 'audit.optBoolean(\"normalBindingRequired\")' in source\n    assert 'audit.optBoolean(\"preflightRequired\")' in source\n    assert '!audit.optBoolean(\"promotesBuildability\")' in source\n",
            "    verifier = (ROOT / \"android/app/src/main/java/dev/modkit/mobile/AutoModAuditVerifier.java\").read_text(encoding=\"utf-8\")\n    assert 'private boolean exactPrepareAuditReady()' in source\n    assert 'AutoModAuditVerifier.structurallyReady' in source\n    assert 'audit.optBoolean(\"completed\")' in verifier\n    assert 'audit.optBoolean(\"normalBindingRequired\")' in verifier\n    assert 'audit.optBoolean(\"preflightRequired\")' in verifier\n    assert 'audit.optBoolean(\"promotesBuildability\")||audit.optBoolean(\"addressRecoveryPromotesBuildability\")' in verifier\n",
        )

        replace(
            "v1/tests/test_v1_pipeline_lifecycle.py",
            "    assert \"if(wasRunning||targetPreparing||pipelineInterrupted)\" in on_create\n",
            "    assert \"boolean interruptedState=wasRunning||targetPreparing||pipelineInterrupted;\" in on_create\n    assert \"if(interruptedState)\" in on_create\n",
        )

        replace(
            "v1/tests/test_v1_release_architecture.py",
            "    for source in (prep, full, evidence):\n        compact = \"\".join(source.split())\n        assert 'putBoolean(\"running\",true)' in compact\n        assert 'putBoolean(\"running\",false)' in compact\n",
            "    prep_compact = \"\".join(prep.split())\n    assert 'persistPreparationState(true)' in prep_compact\n    assert 'persistPreparationState(false)' in prep_compact\n    assert '.commit()' in prep_compact\n    for source in (full, evidence):\n        compact = \"\".join(source.split())\n        assert 'putBoolean(\"running\",true)' in compact\n        assert 'putBoolean(\"running\",false)' in compact\n",
        )

        replace(
            "v1/tests/test_v1_report_surface.py",
            "    assert \"потоково\" in center\n",
            "    assert \"ExportProgress\" in center\n",
        )

        replace(
            "v1/tests/test_v1_simple_cache_freshness.py",
            "    _write(tmp_path / \"analysis.json\", b'{\"schema\":\"analysis\"}')\n    _write(tmp_path / \"analysis.methods.jsonl\", b'{\"id\":1,\"name\":\"A\"}\\n')\n",
            "    _write(tmp_path / \"analysis.json\", b'{\"schema\":\"analysis\"}')\n    _write(tmp_path / \"analysis.summary.json\", b'{\"schema\":\"summary\"}')\n    _write(tmp_path / \"analysis.methods.jsonl\", b'{\"id\":1,\"name\":\"A\"}\\n')\n    _write(tmp_path / \"analysis.gameplay-coverage.json\", b'{\"schema\":\"coverage\"}')\n    _write(tmp_path / \"analysis.evidence-graph.jsonl\", b'{\"id\":1}\\n')\n",
        )

        replace(
            "v1/tests/test_v1_target_atomic_cleanup.py",
            "    running_false = source.index('putBoolean(\"running\",false)', release)\n    busy_false = source.index(\"app.busy.set(false)\", running_false)\n    assert acquire < release < running_false < busy_false\n",
            "    preparation_clear = source.index(\"persistPreparationState(false)\", release)\n    busy_false = source.index(\"app.busy.set(false)\", preparation_clear)\n    assert acquire < release < preparation_clear < busy_false\n",
        )

    except Exception as exc:
        print(f"PATCH ERROR: {exc}", file=sys.stderr)
        restore()
        return 3

    result = run(sys.executable, "-m", "pytest", "tests", "-q", cwd=V1, check=False)
    if result.returncode != 0:
        print("Regression suite still has failures; restoring repair changes so the Codespace stays clean.", file=sys.stderr)
        restore()
        return result.returncode

    # Commit only the files intentionally touched. Do not stage build caches or other untracked output.
    script_rel = str(Path(__file__).resolve().relative_to(ROOT))
    Path(__file__).unlink()
    run("git", "add", "--", *TOUCHED)
    run("git", "add", "-u", "--", script_rel)
    if subprocess.run(["git", "config", "user.email"], cwd=ROOT, stdout=subprocess.DEVNULL).returncode != 0:
        run("git", "config", "user.email", "78445717+Ffenuss@users.noreply.github.com")
    if subprocess.run(["git", "config", "user.name"], cwd=ROOT, stdout=subprocess.DEVNULL).returncode != 0:
        run("git", "config", "user.name", "Ffenuss")
    run("git", "commit", "-m", "fix: align RC regressions with hardened pipeline")
    run("git", "push", "origin", "Modkit1")

    print("Tests are green; continuing canonical Codespaces validation/build...", flush=True)
    os.execv("/bin/bash", ["bash", str(V1 / "build-codespace-release.sh")])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
