"""README-level checks: the documented commands and layout must exist."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_readme_documents_every_subcommand():
    from modkit.cli import build_parser
    subs = [a for a in build_parser()._subparsers._group_actions[0].choices]  # noqa: SLF001
    for cmd in subs:
        assert re.search(rf"modkit {cmd}\b", README), f"`modkit {cmd}` is not documented"


def test_readme_pipeline_section_exists():
    assert "## Как это работает" in README or "## How it works" in README


def test_repo_layout_matches_the_readme():
    for rel in ("modkit/cli.py", "modkit/metadata/reader.py", "modkit/dumper/dumpcs.py",
                "modkit/elf/reader.py", "modkit/analyze/features.py", "modkit/codegen/gen.py",
                "modkit/codegen/runtime_src.py", "modkit/selftest/fixtures.py",
                "rules/default.json", "pyproject.toml"):
        assert (ROOT / rel).exists(), rel


def test_runtime_sources_have_no_unresolved_placeholders():
    from modkit.codegen import runtime_src, templates
    for name in dir(runtime_src):
        if name.isupper():
            body = getattr(runtime_src, name)
            assert "###PKG_JNI###" not in body or name == "JNI_MAIN", name
    for name in dir(templates):
        if name.isupper() and isinstance(getattr(templates, name), str):
            leftovers = re.findall(r"\{\{(\w+)\}\}", getattr(templates, name))
            assert set(leftovers) <= {"app_name", "package", "abi", "count", "project", "target_so",
                                      "overlay", "imgui", "dobby", "autoload", "tag", "app", "lib", "keys",
                                      "version", "source", "nfeat", "nhooks", "rows", "notes",
                                      "classes", "methods", "so"}, (name, leftovers)


def test_android_menu_builder_does_not_invent_slider_range():
    src = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/MenuBuilderActivity.java').read_text(encoding='utf-8')
    assert 'Min и Max явно' in src
    assert 'Slider Min (обязательно для slider)' in src
    assert 'c.put("min_value",0)' not in src
    assert 'c.put("max_value",100)' not in src


def test_android_auto_apk_uses_strict_ready_gate():
    worker = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/WorkerService.java').read_text(encoding='utf-8')
    menu = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/MenuBuilderActivity.java').read_text(encoding='utf-8')
    assert 'readyForAutoBuild' in worker
    assert 'actionableReview' in menu
    assert 'autoAPK:' in menu


def test_re_workspace_surfaces_native_relationship_counts():
    ui = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/ReWorkspaceActivity.java').read_text(encoding='utf-8')
    engine = (ROOT / 'modkit/mobile/engine.py').read_text(encoding='utf-8')
    for token in ('nativeRelations', 'relationshipGraph', 'completeChains', 'partialLoaderChains', 'gaps', 'dependencyEdges', 'dexNativeLinks', 'embeddedLibraryStringEdges', 'symbolEdges', 'dynamicSymbolEdges', 'jniSurfaces', 'jniDirectCallRefs', 'il2cppDirectCallRefs', 'dynamicLoadingSurfaces', 'renderInputSurfaces'):
        assert token in engine
    assert 'relationshipLines' in ui and 'graphLines' in ui and 'summaryText' in ui


def test_native_workspace_surfaces_static_xrefs():
    src = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/NativeWorkspaceActivity.java').read_text(encoding='utf-8')
    worker = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/WorkerService.java').read_text(encoding='utf-8')
    assert 'native_xrefs' in src
    assert 'native-xrefs.json' in src
    assert 'native_workspace_xrefs' in worker


def test_android_surfaces_semantic_xref_verification():
    re_ui = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/ReWorkspaceActivity.java').read_text(encoding='utf-8')
    menu = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/MenuBuilderActivity.java').read_text(encoding='utf-8')
    worker = (ROOT / 'modkit/mobile/engine.py').read_text(encoding='utf-8')
    assert 'controlCandidateLines' in re_ui
    assert 'semanticVerification' in worker
    assert 'semantic_verified' in menu
    assert 'augment_control_semantics' in worker


def test_android_surfaces_dev15_method_context_verification():
    re_ui = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/ReWorkspaceActivity.java').read_text(encoding='utf-8')
    menu = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/MenuBuilderActivity.java').read_text(encoding='utf-8')
    worker = (ROOT / 'modkit/mobile/engine.py').read_text(encoding='utf-8')
    correlate = (ROOT / 'modkit/reworkspace/correlate.py').read_text(encoding='utf-8')
    assert 'relationshipLines' in re_ui
    assert 'methodContextVerification' in worker
    assert 'il2cppMethodContext' in worker
    assert 'context_verified' in menu
    assert 'selected_method_rvas' in worker
    assert 'technical-rendering-or-quality-surface' in correlate


def test_android_re_workspace_reuses_selected_split_il2cpp_pair():
    worker = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/WorkerService.java').read_text(encoding='utf-8')
    engine = (ROOT / 'modkit/mobile/engine.py').read_text(encoding='utf-8')
    main = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/MainActivity.java').read_text(encoding='utf-8')
    re_ui = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/ReWorkspaceActivity.java').read_text(encoding='utf-8')
    strings = (ROOT / 'android/app/src/main/res/values/strings.xml').read_text(encoding='utf-8')
    assert 'selected-external-pair+reused-rodroid' in worker
    assert 'mainAnalysis.isFile()&&mainSummary.isFile()&&mainRod.isDirectory()' in worker
    assert 'pipelineDiagnostics' in engine and 'inputSources' in engine
    assert 'matchRank' in main and 'точное слово в имени/классе' in strings
    assert 'IL2CPP input:' in engine and 'IL2CPP control shortlist' in re_ui
    assert 're-analysis.ui.json' in re_ui and '_atomic_stream_json' in engine


def test_dev20_checkpoint_documents_native_only_and_compact_menu_seed():
    root = Path(__file__).resolve().parents[1]
    release = (root / 'RELEASE-0.9.0-DEV20-RU.md').read_text(encoding='utf-8')
    correlate = (root / 'modkit/reworkspace/correlate.py').read_text(encoding='utf-8')
    engine = (root / 'modkit/mobile/engine.py').read_text(encoding='utf-8')
    assert 'unique-managed-interval' in correlate
    assert 'nativeOnlyChains' in correlate
    assert 'gameplayRelevance' in correlate
    assert 're-analysis.menu.json' in release
    assert 'modkit-re-menu-seed-1.0' in engine


def test_dev23_android_surfaces_deep_resolver_and_fail_closed_menu_seed():
    main = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/MainActivity.java').read_text(encoding='utf-8')
    worker = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/WorkerService.java').read_text(encoding='utf-8')
    menu = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/MenuBuilderActivity.java').read_text(encoding='utf-8')
    engine = (ROOT / 'modkit/mobile/engine.py').read_text(encoding='utf-8')
    assert 'deep_method' in main and 'deep_method' in worker
    assert 'deep_resolve_method' in worker and 'analysis-deep' in worker
    assert 'Создать review-список из Deep Resolver' in menu
    assert 'menu_seed_from_deep' in engine
    assert 'semanticVerified + contextVerified' in engine
    assert "runtimeTruth" in engine and "not-observed" in engine


def test_dev23_production_resolver_has_no_test_application_rules():
    banned = ('Drova', 'AFK', 'MotionPlayer', 'Just2D', 'SetFxSpeedLifeTime')
    roots = [ROOT / 'modkit', ROOT / 'android/app/src/main/java']
    for base in roots:
        for path in base.rglob('*'):
            if not path.is_file() or '__pycache__' in path.parts:
                continue
            if path.suffix not in {'.py', '.java', '.kt', '.cpp', '.h', '.hpp', '.c'}:
                continue
            text = path.read_text(encoding='utf-8', errors='ignore')
            for token in banned:
                assert token not in text, f'{token} leaked into production logic: {path.relative_to(ROOT)}'


def test_dev24_surfaces_indirect_thunk_virtual_and_deep_menu_pipeline():
    flow = (ROOT / 'modkit/reworkspace/arm64_flow.py').read_text(encoding='utf-8')
    engine = (ROOT / 'modkit/mobile/engine.py').read_text(encoding='utf-8')
    main = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/MainActivity.java').read_text(encoding='utf-8')
    worker = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/WorkerService.java').read_text(encoding='utf-8')
    menu = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/MenuBuilderActivity.java').read_text(encoding='utf-8')
    assert 'canonicalize_thunk' in flow and 'scan_blr_calls' in flow
    assert 'virtualCandidates' in flow and 'function_pointer_slots' in flow
    assert "_DEEP_RESOLVER_SCHEMA = 'modkit-deep-method-resolution-1.2'" in engine
    assert '_deep_cache_identity' in engine and '_deep_cached_result' in engine
    assert 'menu_auto_prepare_from_deep' in engine
    assert 'menu_auto_prepare_deep' in worker and 'menu_auto_build_apk_deep' in worker
    assert 'Создать review-список из Deep Resolver' in menu
    assert 'menu_smart_build_apk' in menu
    assert 'incomingThunkCalls' in main and 'incomingIndirectCalls' in main
    assert 'incomingVirtualCandidates' in main and 'functionPointerSlots' in main


def test_dev24_indirect_resolution_remains_fail_closed_for_virtual_dispatch():
    flow = (ROOT / 'modkit/reworkspace/arm64_flow.py').read_text(encoding='utf-8')
    engine = (ROOT / 'modkit/mobile/engine.py').read_text(encoding='utf-8')
    assert 'candidate-only-no-static-receiver-type' in flow
    assert "'confirmedExactTarget': bool(virtual_exact_count)" in engine
    assert 'review-ambiguous-vtable-base' in engine
    assert "'status': 'not-observed'" in engine and "'confirmed': False" in engine


def test_dev25_receiver_vtable_proof_is_generic_and_menu_linked():
    engine = (ROOT / 'modkit/mobile/engine.py').read_text(encoding='utf-8')
    main = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/MainActivity.java').read_text(encoding='utf-8')
    assert 'vtable_entries_for_type' in engine
    assert '_resolve_virtual_dispatch_for_target' in engine
    assert 'confirmed-unique-slot-domain-intersection' in engine
    assert 'generic-methodref-requires-methodspec-proof' in engine
    assert 'incomingVirtualCalls' in main
    assert 'virtual exact' in main


def test_dev32_home_uses_recycler_navigation_and_resource_localization():
    import re
    main = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/MainActivity.java').read_text(encoding='utf-8')
    gradle = (ROOT / 'android/app/build.gradle').read_text(encoding='utf-8')
    manifest = (ROOT / 'android/app/src/main/AndroidManifest.xml').read_text(encoding='utf-8')
    ru = (ROOT / 'android/app/src/main/res/values/strings.xml').read_text(encoding='utf-8')
    en = (ROOT / 'android/app/src/main/res/values-en/strings.xml').read_text(encoding='utf-8')
    assert 'RecyclerView listView' in main and 'new ListView' not in main
    assert 'androidx.recyclerview:recyclerview:1.3.2' in gradle
    for key in ('nav_discovery', 'nav_probe', 'nav_menu', 'nav_reports'):
        assert f'R.string.{key}' in main
        assert f'name="{key}"' in ru and f'name="{key}"' in en
    assert 'android:label="@string/app_name"' in manifest
    assert not re.search(r'[А-Яа-яЁё]', main)


def test_dev32_ru_en_resource_key_sets_match():
    import xml.etree.ElementTree as ET
    ru_root = ET.parse(ROOT / 'android/app/src/main/res/values/strings.xml').getroot()
    en_root = ET.parse(ROOT / 'android/app/src/main/res/values-en/strings.xml').getroot()
    ru = {node.attrib['name'] for node in ru_root.findall('string')}
    en = {node.attrib['name'] for node in en_root.findall('string')}
    assert ru == en
    assert {'installed_apps_games', 'search_application', 'step_probe', 'build_apk_set'} <= ru


def test_dev33_architecture_checkpoint_is_versioned_and_fail_closed():
    engine = (ROOT / 'modkit/mobile/engine.py').read_text(encoding='utf-8')
    correlate = (ROOT / 'modkit/reworkspace/correlate.py').read_text(encoding='utf-8')
    native = (ROOT / 'modkit/reworkspace/native.py').read_text(encoding='utf-8')
    validation = (ROOT / 'VALIDATION-DEV33.json').read_text(encoding='utf-8')
    assert 'CorrelationCache' in engine and 'genericCorrelationCacheHit' in engine
    assert 'SpooledTemporaryFile' in correlate and 'mmap.mmap' in correlate
    assert 'memoryview(elf.blob)' in native
    assert 'cacheDoesNotPromoteRuntimeTruth' in validation


def test_dev34_parallel_index_checkpoint_is_versioned_and_fail_closed():
    validation = json.loads((ROOT / 'VALIDATION-DEV34.json').read_text(encoding='utf-8'))
    gradle = (ROOT / 'android/app/build.gradle').read_text(encoding='utf-8')
    pyproject = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
    main = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/MainActivity.java').read_text(encoding='utf-8')
    correlate = (ROOT / 'modkit/reworkspace/correlate.py').read_text(encoding='utf-8')
    assert validation['version'] == '0.9.0-dev34'
    assert 'versionCode 45' in gradle and "versionName '0.9.0-dev40'" in gradle
    assert 'version = "0.9.0.dev40"' in pyproject
    assert '_scan_items_bounded' in correlate and 'nativeSynchronous' in correlate
    assert 'analysis.methods.jsonl.search.idx' in main and 'searchDebounce' in main
    assert validation['invariants']['largeElfRemainsSequential'] is True
    assert validation['invariants']['searchIndexDoesNotPromoteRuntimeTruth'] is True



def test_dev36_decompiler_is_upstream_jadx_apkset_workspace():
    gradle = (ROOT / 'android/app/build.gradle').read_text(encoding='utf-8')
    manifest = (ROOT / 'android/app/src/main/AndroidManifest.xml').read_text(encoding='utf-8')
    main = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/MainActivity.java').read_text(encoding='utf-8')
    engine = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/DecompilerEngine.java').read_text(encoding='utf-8')
    assert "io.github.skylot:jadx-core:1.5.6" in gradle
    assert "io.github.skylot:jadx-dex-input:1.5.6" in gradle
    assert 'DecompilerActivity' in manifest and 'workspace_decompiler' in main
    assert 'installed-target.json' in engine and 'optJSONArray("splits")' in engine
    assert 'game.apk' in engine


def test_dev36_decompiler_is_lazy_bounded_and_smali_capable():
    engine = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/DecompilerEngine.java').read_text(encoding='utf-8')
    activity = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/DecompilerActivity.java').read_text(encoding='utf-8')
    assert 'setThreadsCount(1)' in engine and 'NoOpCodeCache.INSTANCE' in engine
    assert 'getCode()' in engine and 'getSmali()' in engine
    assert 'MAX_SEARCH_HITS = 100' in engine and 'AtomicBoolean cancel' in engine
    assert 'cls.unload()' in engine
    assert 'Mode { JAVA, SMALI, RESOURCES }' in activity


def test_dev36_decompiler_keeps_runtime_offline_and_native_claims_honest():
    manifest = (ROOT / 'android/app/src/main/AndroidManifest.xml').read_text(encoding='utf-8')
    ru = (ROOT / 'android/app/src/main/res/values/strings.xml').read_text(encoding='utf-8')
    engine = (ROOT / 'android/app/src/main/java/dev/modkit/mobile/DecompilerEngine.java').read_text(encoding='utf-8')
    assert 'android.permission.INTERNET' not in manifest
    assert 'libil2cpp' not in engine.lower() and 'metadata.bin' not in engine
    assert 'дизассемблирование' in ru.lower() and 'фиктивный c-псевдокод' in ru.lower()


def test_dev36_research_covers_competing_decompiler_classes_and_validation():
    research = (ROOT / 'DECOMPILER-RESEARCH-DEV36.md').read_text(encoding='utf-8')
    validation = json.loads((ROOT / 'VALIDATION-DEV36.json').read_text(encoding='utf-8'))
    for name in ('JADX 1.5.6', 'Apktool 3.0.3', 'smali', 'Vineflower', 'Ghidra', 'RetDec', 'dex2jar'):
        assert name.lower() in research.lower()
    assert validation['version'] == '0.9.0-dev36'
    assert validation['versionCode'] == 41
    assert validation['invariants']['noInternetPermission'] is True
    assert validation['invariants']['il2cppNotRequired'] is True
