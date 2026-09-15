# ModKit 1.1 — Implementation Plan

Branch: `Modkit1`

This document fixes the implementation order agreed after the 2026-09-15 device acceptance run. Work proceeds in this order; later phases must not bypass earlier acceptance gates.

## Phase 1 — P0 stability and observability

Goal: a failed heavyweight backend must never silently return the user to Home, lose the run state, freeze elapsed time, or make diagnostics impossible to export.

### 1.1 Memory/OOM hardening
- Request a larger Android heap as a safety margin, but do not rely on it as the primary fix.
- Replace monolithic JADX work with a bounded-memory strategy: process target inputs in deterministic batches and persist results to disk; close/unload each batch before opening the next.
- Catch `OutOfMemoryError` / fatal backend `Throwable` at backend boundaries, convert them into explicit PARTIAL/FAILED evidence, and continue independent backends when safe.
- Record heap max/used/free at backend start/failure.
- Never mark a decompiler output complete unless the exported artifact exists and its SHA-256/size match the manifest.

### 1.2 Run lifecycle
- A run publishes a durable RUNNING manifest before any heavyweight work.
- Every terminal exit publishes SUCCESS, PARTIAL, FAILED, or CANCELLED.
- A process/device interruption is recovered as SYSTEM_INTERRUPTED on next launch; stale results are not presented as current.
- Full-analysis cancellation remains fail-closed and visible.

### 1.3 Live progress
- UI elapsed time is computed from the run start timestamp, not from a stage snapshot.
- Add heartbeat timestamps while long stages are running.
- Show stage, substage, elapsed time, last heartbeat, completed/remaining stages, and cancellation state.

### 1.4 Diagnostic journal/export
- Append bounded session events for target selection, activity transitions, operation start/stop, stages, cancellation, exceptions, OOM, artifact creation/removal, and export/build result.
- A diagnostic bundle must be exportable even when the main pipeline failed before producing a successful analysis manifest.
- Export UI must clearly report saved filename, size, timestamp, and failure reason when no file was saved.

### Phase 1 acceptance gate
- Large split APK does not silently return to Home when JADX OOMs.
- Timer advances continuously during a >10 minute backend.
- OOM produces a terminal/partial manifest plus diagnostic event.
- Failed/cancelled/interrupted run can export a diagnostic bundle.
- No stale previous-run catalog is presented as current.

## Phase 2 — Target subsystem

Goal: one deterministic target abstraction for installed apps, single APKs, and packaged APK sets.

- Make installed-app picker asynchronous and single-instance; debounce/ignore duplicate taps.
- Whole app row is one hit target with immediate pressed/selected feedback.
- Background-load labels/icons/classification; never block the main thread with the entire inventory.
- Classify games using multiple signals: Android category, launcher category, Unity/Unreal/Cocos/native markers and package evidence.
- Support `.apk`, `.apk+`, `.apks`, `.xapk`, `.apkm`, and ZIP-based APK sets by inspecting container contents, not extension alone.
- Persist exact target manifest with every member APK, SHA-256, ABI/asset-pack role, package identity, and preparation status.

### Phase 2 acceptance gate
- Repeated tap cannot open duplicate pickers.
- Mobile Legends-class targets classify as games even without `CATEGORY_GAME` when engine evidence exists.
- APK+ backup with base + splits imports as one target and survives verification/reopen.

## Phase 3 — Unified APK-set resolver

Goal: every workspace sees the same canonical target.

- Introduce one `TargetResolver`/target manifest API.
- Full Analysis, RE Workspace, Decompiler, Native Workspace, File Workspace, AutoMod, reports and builders consume it.
- Resolve ownership of global-metadata.dat, libil2cpp.so, native ABI split, assets and patch target across all splits.
- Bind every generated artifact to target digest.

### Phase 3 acceptance gate
- An IL2CPP library stored only in `split_config.arm64_v8a.apk` is visible to Full Analysis and RE Workspace identically.
- No workspace silently falls back to base.apk when a multi-APK target exists.

## Phase 4 — Decompiler 2.0

Goal: useful Java/Smali/resources on large APK sets without exhausting Java heap.

- Bounded/incremental JADX sessions.
- Disk-backed class/resource index.
- On-demand single-class/single-DEX decode.
- Separate full export from interactive browsing.
- Explicit partial state for undecodable members.

### Phase 4 acceptance gate
- Large target browses classes without loading every split into one long-lived JADX object.
- Search/export cancellation remains responsive.

## Phase 5 — File Workspace 2.0

Goal: format-aware engineering workspace instead of UTF-8-vs-HEX guessing.

- Magic/path based detectors for DEX, ELF, APK/ZIP, AXML, ARSC, JSON/XML/YAML/TOML/INI/properties, SQLite, images, Unity bundles/assets/lpak, IL2CPP metadata, and unknown binary.
- Route specialized formats to specialized viewers/workspaces while retaining exact byte editing where appropriate.
- Never render DEX/ELF/Unity binary as ordinary UTF-8 merely because some bytes are printable.

## Phase 6 — Evidence quality

Goal: reduce false-important/review noise and improve actionable evidence.

- Deduplicate normalized endpoints/strings/candidates.
- Separate raw semantic hints from method-bound evidence.
- Do not count raw strings as control candidates without owning class/method/context.
- Normalize framework/CDN/noise findings.
- Distinguish discovered surface, potential trust boundary, correlated evidence, confirmed issue.

## Phase 7 — AutoMod and Menu Builder correctness

Goal: UI counts and controls reflect executable evidence, not review hints.

- Executable controls only from exact/buildable/preflight-ready evidence.
- Runtime probes/read-only observations in a separate section.
- Review evidence in a separate non-control section.
- Preserve fail-closed RVA/token/ABI/context rules.

## Phase 8 — Reports/export UX

- Human-readable connected report and Evidence Bundle.
- Clear post-save confirmation, filename, size, time, open/share actions and recent exports.
- Diagnostic-only export for FAILED/CANCELLED/SYSTEM_INTERRUPTED runs.

## Phase 9 — RU/EN localization

- In-app language setting: Russian / English.
- Move all hardcoded Activity/dialog/notification/error/export labels into resources.
- Localize report filenames and AI UI while keeping machine-readable schema keys stable.

## Phase 10 — Dynamic Runtime Lab

- Separate explicit dynamic mode for authorized targets.
- Memory map/value observation, runtime RVA/VA, tracing/hook telemetry and controlled writes behind explicit user actions.
- Keep default Process Lab read-only.
- Bind runtime evidence to process/module/target identity and never promote runtime observations to buildable static evidence automatically.

## Phase 11 — Dynamic Network Lab

- Explicit local capture/replay workspace for authorized targets.
- Local VPN/proxy capture, HTTP/WebSocket history, request/response inspection, controlled replay/override, TLS/pinning observations and static↔runtime endpoint correlation.
- No automatic network interception in ordinary static/full analysis.

## Phase 12 — Offline floating AI Agent

- Local-model runtime with importable compatible models.
- Floating draggable entry point over ModKit screens.
- Agent tool API uses internal ModKit commands rather than coordinate taps.
- Workspace exposes current target, stage, logs, artifacts, diffs, build status and undo.
- Continuous bounded ModKit session telemetry feeds diagnostics; no unrelated device-wide collection.
- Mutating/build actions require the same preflight/authorization gates as manual UI.

## Release gate

Automated tests are necessary but not sufficient. Every test release must pass a device acceptance matrix:

1. small single APK;
2. large split APK;
3. Unity IL2CPP target;
4. ordinary non-game app;
5. APK+/APKS-style archive;
6. failed/OOM/cancelled diagnostic export;
7. report export;
8. patch/build preflight and signed test output where applicable.

No phase is considered complete solely because its buttons exist or unit tests pass; it must meet its device acceptance criteria.
