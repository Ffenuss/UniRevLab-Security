import json
from pathlib import Path

from modkit.mobile.automod import build_plan, build_workspace_plan

ROOT = Path(__file__).resolve().parents[1]


def card(card_id, title, stage, *, ownership="APP_OR_GAME", buildable=False, actionable=False,
         server=False, external=False, locator=None, status="FOUND_STATIC", domain="health"):
    return {"id":card_id,"title":title,"category":"Gameplay","source":"test","verificationStage":stage,"ownership":ownership,"buildable":buildable,"actionable":actionable,"serverAudit":server,"externalCorroborating":external,"locator":locator,"status":status,"gameplayDomain":domain,"priority":80}


def test_automod_planner_is_fail_closed_and_never_promotes_static_keyword_to_build():
    catalog={"cards":[card("ready","SetHealth","PATCH_READY",buildable=True,actionable=True,locator={"rva":0x1000}),card("locator","GetRunSpeed","LOCATOR_CONFIRMED",actionable=True,locator={"rva":0x2000},domain="speed"),card("flow","ApplyDamage","FLOW_CONFIRMED",domain="damage"),card("static","Coins","APP_OWNED",domain="currency"),card("server","Premium entitlement server","SERVER_AUDIT",server=True,domain="currency"),card("external","External HP","LOCATOR_CONFIRMED",external=True,actionable=True,locator={"rva":0x3000}),card("framework","UnityEngine Health helper","FOUND_STATIC",ownership="FRAMEWORK")]}
    plan=build_plan(catalog);by_id={row["id"]:row for row in plan["candidates"]}
    assert by_id["ready"]["stage"]=="READY_TO_BUILD";assert by_id["locator"]["stage"]=="READY_FOR_PREFLIGHT";assert by_id["flow"]["stage"]=="RUNTIME_NEEDED";assert by_id["static"]["stage"]=="REVIEW";assert by_id["server"]["stage"]=="AUDIT_ONLY";assert by_id["external"]["stage"]=="EXCLUDED";assert by_id["framework"]["stage"]=="EXCLUDED"
    assert plan["readyToBuildCount"]==1;assert plan["failClosed"] is True;assert plan["modifiesTarget"] is False;assert plan["runtimeEvidencePromotesBuildability"] is False;assert plan["il2cppCrosscheckPromotesBuildability"] is False;assert plan["metadataIdentityPromotesBuildability"] is False;assert plan["nativeRecoveryPromotesBuildability"] is False;assert plan["autoBuildRequiresValidatedExecutableBinding"] is True;assert plan["serverBypassGenerated"] is False


def test_runtime_va_observation_is_attached_but_never_promotes_candidate_to_build():
    catalog={"cards":[card("hp","SetHealth","LOCATOR_CONFIRMED",actionable=True,locator={"rva":0x1234,"library":"libil2cpp.so"})]};runtime={"schema":"modkit-runtime-correlation-1.0","correlations":[{"id":"hp","runtimeEvidence":"PROCFS_MODULE_LAYOUT","modulePath":"/data/app/game/lib/arm64/libil2cpp.so","moduleBasename":"libil2cpp.so","loadBaseHex":"0x70000000","rvaHex":"0x1234","runtimeVaHex":"0x70001234","mapped":True,"mappingPerms":"r-xp","matchMode":"EXACT_LIBRARY_BASENAME","promotesBuildability":False}]}
    plan=build_plan(catalog,runtime);row=plan["candidates"][0]
    assert row["stage"]=="READY_FOR_PREFLIGHT";assert row["buildable"] is False;assert row["runtimeObserved"] is True;assert row["runtimeObservation"]["runtimeVaHex"]=="0x70001234";assert row["runtimeObservation"]["promotesBuildability"] is False;assert plan["runtimeObservedCount"]==1;assert plan["readyToBuildCount"]==0;assert plan["runtimeEvidencePromotesBuildability"] is False


def test_il2cpp_structural_crosscheck_is_attached_by_rva_without_promoting_build():
    catalog={"cards":[card("hp","SetHealth","LOCATOR_CONFIRMED",actionable=True,locator={"rva":0x1234,"library":"libil2cpp.so"})]};rows=[{"id":"method-row-8","methodName":"SetHealth","rva":0x1234,"rvaHex":"0x1234","metadataMethodNamePresent":True,"executableElfRangePresent":True,"elfRangeMode":"DIRECT_ELF_VADDR","segmentIndex":2,"status":"STRUCTURAL_BOTH_PRESENT","associationConfirmed":False,"promotesBuildability":False}]
    plan=build_plan(catalog,None,rows);row=plan["candidates"][0]
    assert row["stage"]=="READY_FOR_PREFLIGHT";assert row["buildable"] is False;assert row["il2cppStructuralObserved"] is True;assert row["il2cppStructural"]["status"]=="STRUCTURAL_BOTH_PRESENT";assert row["il2cppStructural"]["associationConfirmed"] is False;assert row["il2cppStructural"]["promotesBuildability"] is False;assert plan["il2cppStructuralObservedCount"]==1;assert plan["il2cppStructuralBothCount"]==1;assert plan["readyToBuildCount"]==0


def test_no_rva_metadata_identity_is_attached_without_inventing_address_or_buildability():
    catalog={"cards":[card("hp-no-rva","SetHealth","APP_OWNED",actionable=False,locator={"methodId":77,"class":"Game.Player","method":"SetHealth","rva":None})]};identity_rows=[{"id":77,"class":"Game.Player","methodName":"SetHealth","status":"METADATA_QUALIFIED_METHOD_CONFIRMED_NO_RVA","metadataMethodNamePresent":True,"metadataQualifiedMethodPresent":True,"addressConfirmed":False,"rva":None,"actionable":False,"buildable":False,"promotesBuildability":False}]
    plan=build_plan(catalog,None,None,identity_rows);row=plan["candidates"][0]
    assert row["stage"]=="REVIEW";assert row["metadataIdentityObserved"] is True;assert row["metadataIdentity"]["metadataQualifiedMethodPresent"] is True;assert row["metadataIdentity"]["addressConfirmed"] is False;assert row["metadataIdentity"]["rva"] is None;assert row["metadataIdentity"]["actionable"] is False;assert row["metadataIdentity"]["buildable"] is False;assert row["buildable"] is False;assert row["actionable"] is False;assert plan["metadataIdentityObservedCount"]==1;assert plan["metadataQualifiedNoRvaCount"]==1;assert plan["exactLocatorCount"]==0;assert plan["nativeRecoveredLocatorCount"]==0;assert plan["readyToBuildCount"]==0;assert plan["readyForPreflightCount"]==0


def test_exact_native_no_rva_recovery_enters_preflight_but_never_buildability():
    catalog={"cards":[card("hp-native","SetHealth","APP_OWNED",locator={"methodId":77,"class":"Game.Player","method":"SetHealth","rva":None})]}
    recovery=[{"id":77,"metadataMethodId":77,"metadataToken":"0x0600002a","image":"Assembly-CSharp.dll","class":"Game.Player","methodName":"SetHealth","status":"NATIVE_RVA_RECOVERED_EXACT_CODEGENMODULE","rva":0x345678,"rvaHex":"0x345678","addressConfirmed":True,"associationConfirmed":True,"uniqueExecutablePointer":True,"moduleResolution":"EXACT_EXPECTED_METHOD_COUNT","identityProof":"metadataMethodId+token+image+declaringType+methodName","actionable":False,"buildable":False,"promotesBuildability":False}]
    plan=build_plan(catalog,None,None,None,recovery);row=plan["candidates"][0]
    assert row["stage"]=="READY_FOR_PREFLIGHT";assert row["nativeRvaRecovered"] is True;assert row["nativeRvaRecovery"]["rva"]==0x345678;assert row["resolvedLocator"]["source"]=="EXACT_CODEGENMODULE_RECOVERY";assert row["resolvedLocator"]["addressConfirmed"] is True;assert row["actionable"] is False;assert row["buildable"] is False;assert plan["nativeRecoveredLocatorCount"]==1;assert plan["readyForPreflightCount"]==1;assert plan["readyToBuildCount"]==0;assert plan["nativeRecoveryPromotesBuildability"] is False;assert plan["nativeRecoveryMayEnterPreflight"] is True


def test_ambiguous_or_non_unique_native_recovery_is_rejected():
    catalog={"cards":[card("hp-native","SetHealth","APP_OWNED",locator={"methodId":77,"class":"Game.Player","method":"SetHealth","rva":None})]};recovery=[{"id":77,"metadataMethodId":77,"class":"Game.Player","methodName":"SetHealth","status":"NATIVE_RVA_RECOVERED_EXACT_CODEGENMODULE","rva":0x345678,"addressConfirmed":True,"associationConfirmed":True,"uniqueExecutablePointer":False,"promotesBuildability":False}]
    plan=build_plan(catalog,None,None,None,recovery);row=plan["candidates"][0]
    assert row["stage"]=="REVIEW";assert row["nativeRvaRecovered"] is False;assert row["resolvedLocator"] is None;assert plan["nativeRecoveredLocatorCount"]==0;assert plan["readyForPreflightCount"]==0


def test_ambiguous_name_only_metadata_identity_is_not_attached_by_guess():
    catalog={"cards":[card("ambiguous","SetHealth","APP_OWNED",locator={"rva":None})]};identity_rows=[{"id":1,"class":"A.Player","methodName":"SetHealth","status":"METADATA_METHOD_NAME_PRESENT_NO_RVA","addressConfirmed":False,"promotesBuildability":False},{"id":2,"class":"B.Player","methodName":"SetHealth","status":"METADATA_METHOD_NAME_PRESENT_NO_RVA","addressConfirmed":False,"promotesBuildability":False}]
    plan=build_plan(catalog,None,None,identity_rows);row=plan["candidates"][0];assert row["metadataIdentityObserved"] is False;assert row["metadataIdentity"] is None;assert plan["metadataIdentityObservedCount"]==0


def test_short_class_metadata_identity_is_not_duplicated_in_pair_index():
    catalog={"cards":[card("short","SetHealth","APP_OWNED",locator={"class":"Player","method":"SetHealth","rva":None})]};identity_rows=[{"id":9,"class":"Player","methodName":"SetHealth","status":"METADATA_QUALIFIED_METHOD_CONFIRMED_NO_RVA","metadataMethodNamePresent":True,"metadataQualifiedMethodPresent":True,"addressConfirmed":False,"actionable":False,"buildable":False,"promotesBuildability":False}]
    plan=build_plan(catalog,None,None,identity_rows);assert plan["candidates"][0]["metadataIdentityObserved"] is True;assert plan["metadataQualifiedNoRvaCount"]==1


def test_workspace_plan_writes_schema_and_uses_existing_catalog(tmp_path):
    catalog={"cards":[card("x","MaxHP","LOCATOR_CONFIRMED",actionable=True,locator={"rva":4096})]};(tmp_path/"simple-catalog.json").write_text(json.dumps(catalog),encoding="utf-8");(tmp_path/"runtime-correlation.json").write_text(json.dumps({"correlations":[{"id":"x","runtimeEvidence":"PROCFS_MODULE_LAYOUT","mapped":True,"loadBaseHex":"0x50000000","rvaHex":"0x1000","runtimeVaHex":"0x50001000","promotesBuildability":False}]}),encoding="utf-8");output=tmp_path/"automod-plan.json";plan=build_workspace_plan(tmp_path,output);stored=json.loads(output.read_text(encoding="utf-8"));assert plan["schema"]=="modkit-automod-plan-1.4";assert stored["readyForPreflightCount"]==1;assert stored["readyToBuildCount"]==0;assert stored["runtimeObservedCount"]==1;assert stored["runtimeSource"]=="runtime-correlation.json"


def test_automod_android_surface_uses_existing_fail_closed_build_pipeline():
    manifest=(ROOT/"android/app/src/main/AndroidManifest.xml").read_text(encoding="utf-8");activity=(ROOT/"android/app/src/main/java/dev/modkit/mobile/AutoModActivity.java").read_text(encoding="utf-8");auto=(ROOT/"android/app/src/main/java/dev/modkit/mobile/AutoAnalysisActivity.java").read_text(encoding="utf-8");full=(ROOT/"android/app/src/main/java/dev/modkit/mobile/FullModeActivity.java").read_text(encoding="utf-8");storage=(ROOT/"android/app/src/main/java/dev/modkit/mobile/AnalysisStorageActivity.java").read_text(encoding="utf-8");prep=(ROOT/"android/app/src/main/java/dev/modkit/mobile/TargetPreparationService.java").read_text(encoding="utf-8");evidence=(ROOT/"android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java").read_text(encoding="utf-8")
    assert '.AutoModActivity" android:exported="false"' in manifest;assert 'getModule("modkit.mobile.automod")' in activity;assert '"menu_smart_prepare"' in activity;assert '"menu_preflight"' in activity;assert '"menu_smart_build_apk"' in activity;assert 'pf==null||!pf.optBoolean("readyForAutoBuild")' in activity;assert 'build.setEnabled(idle&&prepareCount>0&&preflightReady)' in activity;assert 'runtime VA observed' in activity;assert 'runtimeVaHex' in activity;assert 'metadata identity/no-RVA' in activity;assert 'metadataIdentityObservedCount' in activity;assert 'metadataQualifiedNoRvaCount' in activity;assert 'metadataIdentity' in activity;assert 'RVA unresolved' in activity;assert "ProcessLabActivity.class" in activity;assert "AutoModActivity.class" in auto;assert "AutoModActivity.class" in full;assert "AutoModActivity.class" in storage;assert 'getModule("modkit.mobile.automod")' in evidence;assert 'getModule("modkit.mobile.il2cpp_no_rva_native")' in evidence;assert '"automod-plan.json"' in evidence;assert '"automod-plan.json"' in prep;assert '"automod-plan.json"' in storage;assert '"runtime-correlation.json"' in prep;assert '"runtime-correlation.json"' in storage;assert '"il2cpp-metadata-identity.json"' in prep;assert '"il2cpp-metadata-identity.json"' in storage;assert '"il2cpp-no-rva-native.json"' in prep;assert '"il2cpp-no-rva-native.json"' in storage;assert '"deep-gameplay.json"' in storage
