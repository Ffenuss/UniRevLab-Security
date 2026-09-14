#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: apply-dev40.py <reconstructed-source-root>")
root = Path(sys.argv[1]).resolve()
here = Path(__file__).resolve().parent
if not (root / "modkit/mobile").is_dir():
    raise SystemExit(f"not a ModKit source root: {root}")


def read(rel: str) -> str:
    return (root / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str, label: str) -> None:
    text = read(rel)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{rel}: {label}: expected exactly one marker, found {count}")
    write(rel, text.replace(old, new, 1))


def replace_function(rel: str, start_marker: str, next_marker: str, replacement: str) -> None:
    text = read(rel)
    start = text.find(start_marker)
    if start < 0:
        raise SystemExit(f"{rel}: function marker missing: {start_marker}")
    end = text.find(next_marker, start + len(start_marker))
    if end < 0:
        raise SystemExit(f"{rel}: next function marker missing: {next_marker}")
    write(rel, text[:start] + replacement.rstrip() + "\n" + text[end:])


# First incremental cache layer.  It proves unchanged target bytes and never relaxes validation.
shutil.copyfile(here / "simple_cache.py", root / "modkit/mobile/simple_cache.py")

# Version bump.
replace_once("android/app/build.gradle", "versionCode 44", "versionCode 45", "versionCode")
replace_once("android/app/build.gradle", "versionName '0.9.0-dev39'", "versionName '0.9.0-dev40'", "versionName")
replace_once("pyproject.toml", 'version = "0.9.0.dev39"', 'version = "0.9.0.dev40"', "pyproject version")
replace_once("modkit/__init__.py", '__version__ = "0.9.0-dev39"', '__version__ = "0.9.0-dev40"', "package version")

# ---------------------------------------------------------------------------
# Human confirmation ladder + semantic gameplay domains.
# Keep locator status (READY_DEX/NATIVE/SCRIPT/RESOURCE) separate from evidence stage.
# ---------------------------------------------------------------------------
replace_once(
    "modkit/mobile/simple_mode.py",
    "import json\nfrom pathlib import Path",
    "import json\nimport re\nfrom pathlib import Path",
    "regex import",
)
replace_once(
    "modkit/mobile/simple_mode.py",
    'SCHEMA = "modkit-simple-mode-1.2"',
    'SCHEMA = "modkit-simple-mode-1.3"',
    "catalog schema",
)

helpers = r'''
_GAMEPLAY_DOMAIN_RULES = (
    ("health", ("health", "maxhealth", "max_health", "hitpoints", "hit_points", "hp", "life", "lifepoints")),
    ("damage", ("damage", "dmg", "attackdamage", "attack_damage", "attackpower", "attack_power", "defense", "armour", "armor")),
    ("speed", ("movespeed", "move_speed", "attackspeed", "attack_speed", "timescale", "time_scale", "speed")),
    ("cooldown", ("cooldown", "cool_down", "skillcd", "skill_cd", "recharge", "recast")),
    ("currency", ("diamond", "diamonds", "gem", "gems", "gold", "coin", "coins", "wallet", "balance", "premiumcurrency", "premium_currency")),
    ("level_xp", ("level", "playerlevel", "player_level", "experience", "exp", "xp")),
    ("inventory", ("inventory", "itemamount", "item_amount", "itemcount", "item_count", "stackcount", "stack_count", "reward", "drop")),
    ("camera", ("camera", "fieldofview", "field_of_view", "fov", "zoom")),
    ("movement", ("movement", "position", "teleport", "gravity", "jump", "velocity")),
    ("mana_energy", ("mana", "stamina", "energy")),
)


def _semantic_blob(card: dict) -> str:
    values = [
        card.get("title"), card.get("category"), card.get("description"),
        card.get("source"), card.get("ownership"), card.get("evidence"),
    ]
    return " ".join(_str(v) for v in values).casefold()


def _gameplay_domain(card: dict) -> str:
    blob = _semantic_blob(card)
    tokens = set(re.findall(r"[a-z0-9_]+", blob))
    compact = re.sub(r"[^a-z0-9]", "", blob)
    for domain, aliases in _GAMEPLAY_DOMAIN_RULES:
        for alias in aliases:
            low = alias.casefold()
            if low in tokens or low.replace("_", "") in compact:
                return domain
    return ""


def _has_flow_evidence(evidence: object) -> bool:
    if not isinstance(evidence, dict):
        return False
    for key in ("directInvokes", "invokes", "callers", "callees", "callReferences", "references", "xref", "xrefs"):
        value = evidence.get(key)
        if isinstance(value, (list, dict)) and len(value) > 0:
            return True
    return bool(evidence.get("flowConfirmed") or evidence.get("dataFlowConfirmed"))


def _runtime_confirmed(card: dict) -> bool:
    evidence = card.get("evidence") if isinstance(card.get("evidence"), dict) else {}
    status = str(card.get("status") or "").upper()
    return (
        "RUNTIME" in status
        or bool(evidence.get("runtimeConfirmed"))
        or bool(evidence.get("runtimeObserved"))
        or str(evidence.get("confirmation") or "").casefold() == "runtime"
    )


def _verification_stage(card: dict) -> str:
    if card.get("serverAudit"):
        return "SERVER_AUDIT"
    ownership = str(card.get("ownership") or "UNKNOWN")
    if ownership == "FRAMEWORK":
        return "FRAMEWORK_NOISE"
    if ownership == "BUNDLED_SDK":
        return "SDK_NOISE"
    if card.get("buildable"):
        return "PATCH_READY"
    if _runtime_confirmed(card):
        return "RUNTIME_CONFIRMED"
    status = str(card.get("status") or "")
    if card.get("actionable") or status.startswith("READY"):
        return "LOCATOR_CONFIRMED"
    evidence = card.get("evidence")
    if _has_flow_evidence(evidence):
        return "FLOW_CONFIRMED"
    raw = status.upper()
    if ownership in {"APP", "APP_OR_GAME"} and raw in {
        "CONFIRMED", "VERIFIED", "PACKAGE_OBSERVED", "FIELD_OBSERVED", "FOUND_STATIC",
        "SCRIPT_CONTENT_SEARCH", "SCRIPT/CONTENT_SEARCH",
    }:
        return "APP_OWNED"
    return "FOUND_STATIC"


def _readiness_reason(card: dict, stage: str) -> tuple[str, str]:
    if stage == "PATCH_READY":
        return "Есть проверенный локальный executable binding; пункт разрешён для fail-closed автосборки.", ""
    if stage == "LOCATOR_CONFIRMED":
        return "Есть точный локальный locator для перехода/ручной проверки.", "Для автосборки всё ещё нужен проверенный executable binding/MenuSpec control."
    if stage == "RUNTIME_CONFIRMED":
        return "Поведение подтверждено runtime evidence.", "Нужна точная локальная patch-point привязка и preflight перед автосборкой."
    if stage == "FLOW_CONFIRMED":
        return "Связь подтверждена call/data-flow evidence.", "Нужен точный locator или runtime confirmation."
    if stage == "APP_OWNED":
        return "Находка относится к коду/данным приложения или игры.", "Пока нет достаточного flow/locator подтверждения."
    if stage == "SERVER_AUDIT":
        return "Серверная/network/trust поверхность сохранена для defensive audit.", "Автоматический server/payment/economy bypass запрещён политикой ModKit."
    if stage in {"SDK_NOISE", "FRAMEWORK_NOISE"}:
        return "", "Низкий приоритет: SDK/framework evidence не считается игровой patch-point без сильной app-owned связи."
    return "Статически найдено.", "Нужно подтвердить принадлежность приложению, flow и точный locator."
'''
replace_once(
    "modkit/mobile/simple_mode.py",
    "\n\ndef _quality(card: dict) -> dict:",
    "\n" + helpers + "\n\ndef _quality(card: dict) -> dict:",
    "confirmation helpers",
)

replace_once(
    "modkit/mobile/simple_mode.py",
    '''    card["priority"] = priority\n    card["lowSignal"] = priority < 50\n    card["important"] = priority >= 60\n    return card\n''',
    '''    card["priority"] = priority\n    domain = _gameplay_domain(card)\n    card["gameplayDomain"] = domain\n    stage = _verification_stage(card)\n    card["verificationStage"] = stage\n    card["confirmationRank"] = {\n        "FOUND_STATIC": 10, "APP_OWNED": 20, "FLOW_CONFIRMED": 30,\n        "LOCATOR_CONFIRMED": 40, "RUNTIME_CONFIRMED": 50, "PATCH_READY": 60,\n        "SERVER_AUDIT": 15, "SDK_NOISE": 2, "FRAMEWORK_NOISE": 1,\n    }.get(stage, 0)\n    ready_reason, not_ready_reason = _readiness_reason(card, stage)\n    card["readyReason"] = ready_reason\n    card["notReadyReason"] = not_ready_reason\n    card["patchReady"] = stage == "PATCH_READY"\n    evidence = card.get("evidence") if isinstance(card.get("evidence"), dict) else {}\n    trust = " ".join(_str(evidence.get(k)) for k in ("trustBoundary", "authority", "localAuthority")).casefold()\n    card["offlineCandidate"] = bool(\n        not card.get("serverAudit") and card.get("ownership") in {"APP", "APP_OR_GAME"}\n        and ("local" in trust or bool(domain))\n    )\n    if stage == "PATCH_READY":\n        card["priority"] = max(int(card["priority"]), 110)\n    elif stage == "RUNTIME_CONFIRMED":\n        card["priority"] = max(int(card["priority"]), 105)\n    elif stage == "LOCATOR_CONFIRMED":\n        card["priority"] = max(int(card["priority"]), 96)\n    elif stage == "FLOW_CONFIRMED":\n        card["priority"] = max(int(card["priority"]), 84)\n    elif stage == "APP_OWNED" and domain:\n        card["priority"] = max(int(card["priority"]), 76)\n    if stage == "SDK_NOISE":\n        card["priority"] = min(int(card["priority"]), 42)\n    if stage == "FRAMEWORK_NOISE":\n        card["priority"] = min(int(card["priority"]), 12)\n    card["lowSignal"] = int(card["priority"]) < 50\n    card["important"] = int(card["priority"]) >= 60\n    return card\n''',
    "quality confirmation fields",
)

replace_once(
    "modkit/mobile/simple_mode.py",
    '''        "serverAudit": sum(1 for c in cards if c.get("serverAudit")),\n        "policy": {\n''',
    '''        "serverAudit": sum(1 for c in cards if c.get("serverAudit")),\n        "verificationCounts": {stage: sum(1 for c in cards if c.get("verificationStage") == stage)\n                               for stage in sorted({str(c.get("verificationStage") or "FOUND_STATIC") for c in cards})},\n        "gameplayCounts": {domain: sum(1 for c in cards if c.get("gameplayDomain") == domain)\n                           for domain in sorted({str(c.get("gameplayDomain") or "") for c in cards if c.get("gameplayDomain")})},\n        "policy": {\n''',
    "catalog confirmation counts",
)

# ---------------------------------------------------------------------------
# WorkerService: stage-aware Simple Mode, byte-fingerprint cache and fast cancel.
# Expensive existing analyzers are reused; no network connection is introduced.
# ---------------------------------------------------------------------------
worker = r'''    private long simpleStartedAt=0L;
    private void simpleCheckCancelled() throws IOException {
        if(app.cancelled.get())throw new IOException("Simple Mode: отменено пользователем");
    }
    private void simpleStage(int stage,int total,String name) throws Exception {
        simpleCheckCancelled();
        JSONObject p=new JSONObject();p.put("schema","modkit-simple-progress-1.0");p.put("stage",stage);p.put("totalStages",total);p.put("name",name);p.put("remainingStages",Math.max(0,total-stage));p.put("elapsedMs",Math.max(0L,System.currentTimeMillis()-simpleStartedAt));
        try{if(app.file("simple-catalog.json").isFile()){JSONObject c=new JSONObject(Io.readUtf8(app.file("simple-catalog.json")));p.put("candidates",c.optInt("total"));p.put("confirmed",c.optInt("actionable"));p.put("patchReady",c.optInt("buildable"));}}catch(Exception ignored){}
        try(java.io.FileOutputStream out=new java.io.FileOutputStream(app.file("simple-progress.json"))){out.write(p.toString(2).getBytes(java.nio.charset.StandardCharsets.UTF_8));}
        app.progress("Simple Mode ["+stage+"/"+total+"]: "+name);
    }
    private void simplePrepare() throws Exception {
        if(!app.file("game.apk").isFile()&&!app.file("installed-target.json").isFile())throw new IOException("Сначала выберите установленное приложение/игру или APK");
        simpleStartedAt=System.currentTimeMillis();if(!Python.isStarted())Python.start(new AndroidPlatform(this));
        PyObject cache=Python.getInstance().getModule("modkit.mobile.simple_cache");
        simpleStage(1,6,"инвентаризация APK/split + SHA-256 кэш");
        JSONObject plan=new JSONObject(cache.callAttr("plan_workspace",getFilesDir().getPath(),app.file("simple-cache.json").getPath()).toString());
        boolean unchanged=plan.optBoolean("unchanged",false);boolean haveAnalysis=app.file("analysis.json").isFile()||app.file("re-analysis.json").isFile()||app.file("analysis.methods.jsonl").isFile();
        simpleStage(2,6,unchanged&&haveAnalysis?"кэш hit: DEX/native/IL2CPP результаты не изменились":"engine + DEX/native/IL2CPP discovery/analysis");
        if(!unchanged||!haveAnalysis){
            if(app.file("installed-scan.json").isFile()){
                JSONObject scan=new JSONObject(Io.readUtf8(app.file("installed-scan.json")));simpleCheckCancelled();
                if(scan.optBoolean("fullIl2cppPair")&&app.file("metadata.bin").isFile()&&app.file("library.so").isFile())analyze();
                else if(app.file("installed-apk-set.zip").isFile())splitDiscovery(scan);
            }else if(!haveAnalysis){
                app.progress("Simple Mode: APK выбран; полного analysis report ещё нет — продолжаю engine/security/content discovery и не повышаю неподтверждённые точки до READY.");
            }
        }
        simpleStage(3,6,"gameplay semantics + существующие Deep Resolver/Menu evidence");
        if(app.file("analysis.json").isFile()||app.file("analysis.methods.jsonl").isFile()||app.file("re-analysis.json").isFile()){try{menuSmartPrepare();}catch(Exception e){new Progress().progress("Simple Mode: Menu prepare остаётся REVIEW — "+e.getMessage());}}
        simpleCheckCancelled();
        simpleStage(4,6,unchanged&&app.file("security-surfaces.json").isFile()?"кэш hit: passive Network/API + Crypto/Keys":"passive Network/API + TLS + Crypto/Keys scan");
        JSONObject secObj;
        if(unchanged&&app.file("security-surfaces.json").isFile())secObj=new JSONObject(Io.readUtf8(app.file("security-surfaces.json")));
        else{PyObject sec=Python.getInstance().getModule("modkit.mobile.security_scan");PyObject secOut=sec.callAttr("scan_workspace",getFilesDir().getPath(),app.file("security-surfaces.json").getPath());secObj=new JSONObject(secOut.toString());}
        simpleCheckCancelled();
        simpleStage(5,6,"ownership + confirmation ladder + exact locators + ranking");
        PyObject mod=Python.getInstance().getModule("modkit.mobile.simple_mode");PyObject out=mod.callAttr("build_catalog",getFilesDir().getPath(),app.file("simple-catalog.json").getPath());JSONObject obj=new JSONObject(out.toString());
        simpleCheckCancelled();simpleStage(6,6,"сохранение кэша и каталога");
        cache.callAttr("record_workspace",getFilesDir().getPath(),app.file("simple-cache.json").getPath(),plan.toString());
        app.progress("Simple Mode: найдено "+obj.optInt("total")+", важных "+obj.optInt("important")+", PATCH_READY "+obj.optInt("buildable")+", locator "+obj.optInt("actionable")+", server/trust "+obj.optInt("serverAudit")+", framework "+obj.optInt("frameworkNoise")+(unchanged?" · cache hit":" · fresh target")+".");
    }
'''
replace_function(
    "android/app/src/main/java/dev/modkit/mobile/WorkerService.java",
    "    private void simplePrepare() throws Exception {",
    "    private void simpleBuild(",
    worker,
)

# Invalidate cache/progress whenever selected target changes.
p = root / "android/app/src/main/java/dev/modkit/mobile/WorkerService.java"
s = p.read_text(encoding="utf-8")
needle = '"security-surfaces.json","simple-catalog.json"}'
if needle in s:
    s = s.replace(needle, '"security-surfaces.json","simple-catalog.json","simple-cache.json","simple-progress.json"}', 1)
else:
    raise SystemExit("WorkerService dev39 derived-state list marker missing")
marker = 'Files.deleteIfExists(app.file("simple-catalog.json").toPath());\n'
if marker in s:
    s = s.replace(marker, marker + '                Files.deleteIfExists(app.file("simple-cache.json").toPath());\n                Files.deleteIfExists(app.file("simple-progress.json").toPath());\n', 1)
p.write_text(s, encoding="utf-8")

# ---------------------------------------------------------------------------
# Simple Mode UI: complete filters, stage progress, cancel, readable confirmation
# ladder, and workspace handoff carrying exact locator metadata.
# ---------------------------------------------------------------------------
replace_once(
    "android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java",
    "    private Button prepare,build;",
    "    private Button prepare,build,cancel;",
    "cancel button field",
)
replace_once(
    "android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java",
    '        prepare=button("2 · Обновить анализ и список находок",root,v->startWork(new Intent().putExtra("op","simple_prepare")));',
    '        prepare=button("2 · Обновить полный анализ",root,v->startWork(new Intent().putExtra("op","simple_prepare")));\n        cancel=button("Отменить анализ",root,v->cancelCurrent());cancel.setEnabled(false);',
    "full analysis + cancel button",
)
replace_once(
    "android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java",
    'String[] modes={"Важное","READY","Gameplay","Server/API","Crypto/Keys","Все"};',
    'String[] modes={"Все","Patch Ready","Gameplay","HP / Health","Damage","Speed","Cooldown","Currency","Level / XP","Inventory","Camera","Movement","Offline","Network/API","Crypto/Keys","Authentication","Server Audit","Game code","SDK","Framework noise"};',
    "complete Simple Mode filters",
)

ui_helpers = r'''    private JSONObject readProgress(){try{return new JSONObject(Io.readUtf8(app.file("simple-progress.json")));}catch(Exception e){return null;}}
    private void cancelCurrent(){if(!app.busy.get()){toast("Анализ сейчас не выполняется");return;}app.cancelled.set(true);app.progress("Отмена запрошена — завершаю текущий безопасный шаг…");cancel.setEnabled(false);}
    private Intent locatorIntent(Class<?> cls,JSONObject c){Intent i=new Intent(this,cls);JSONObject l=c.optJSONObject("locator"),e=c.optJSONObject("evidence");i.putExtra("modkitFinding",c.toString());if(l!=null){i.putExtra("rva",value(l,"rva"));i.putExtra("artifact",value(l,"artifact"));i.putExtra("class",value(l,"class"));i.putExtra("method",value(l,"method"));i.putExtra("entry",value(l,"entry"));i.putExtra("codeOffset",value(l,"codeOffset"));}if(e!=null){if(i.getStringExtra("artifact")==null||i.getStringExtra("artifact").isEmpty())i.putExtra("artifact",value(e,"artifact","apk"));if(i.getStringExtra("class")==null||i.getStringExtra("class").isEmpty())i.putExtra("class",value(e,"class","className"));if(i.getStringExtra("method")==null||i.getStringExtra("method").isEmpty())i.putExtra("method",value(e,"method","methodName"));if(i.getStringExtra("entry")==null||i.getStringExtra("entry").isEmpty())i.putExtra("entry",value(e,"entry","path","file"));}return i;}
    private void showNavigation(JSONObject c){ArrayList<String> a=new ArrayList<>();JSONObject l=c.optJSONObject("locator");String blob=c.toString().toLowerCase(Locale.ROOT);if((l!=null&&!value(l,"class","method","artifact").isEmpty())||blob.contains(".dex"))a.add("Открыть в Decompiler");if((l!=null&&!value(l,"rva").isEmpty())||blob.contains("libil2cpp")||blob.contains(".so"))a.add("Открыть в Native");if((l!=null&&!value(l,"entry","artifact").isEmpty())||blob.contains("assets/")||blob.contains("res/"))a.add("Открыть файл / APK entry");a.add("Deep Resolve / RE Workspace");a.add("Копировать locator/evidence");a.add("Технические доказательства JSON");new AlertDialog.Builder(this).setTitle("Куда перейти").setItems(a.toArray(new String[0]),(d,w)->{String x=a.get(w);if(x.startsWith("Открыть в Decompiler"))startActivity(locatorIntent(DecompilerActivity.class,c));else if(x.startsWith("Открыть в Native"))startActivity(locatorIntent(NativeWorkspaceActivity.class,c));else if(x.startsWith("Открыть файл"))startActivity(locatorIntent(FileWorkspaceActivity.class,c));else if(x.startsWith("Deep Resolve")){Intent i=locatorIntent(ReWorkspaceActivity.class,c);i.putExtra("autoDeepResolve",true);startActivity(i);}else if(x.startsWith("Копировать"))copyRaw(c);else showRaw(c);}).show();}
'''
replace_once(
    "android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java",
    "    private void showDetails(JSONObject c){",
    ui_helpers + "\n    private void showDetails(JSONObject c){",
    "workspace handoff helpers",
)

replace_once(
    "android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java",
    'm.append("\\nИсточник: ").append(c.optString("source"));m.append("\\nКатегория: ").append(c.optString("category"));m.append("\\nВладелец: ").append(c.optString("ownership","UNKNOWN"));',
    'm.append("\\nИсточник: ").append(c.optString("source"));m.append("\\nКатегория: ").append(c.optString("category"));m.append("\\nВладелец: ").append(c.optString("ownership","UNKNOWN"));m.append("\\nПодтверждение: ").append(c.optString("verificationStage","FOUND_STATIC"));String rr=c.optString("readyReason","");String nr=c.optString("notReadyReason","");if(!rr.isEmpty())m.append("\\nПочему подтверждено: ").append(rr);if(!nr.isEmpty())m.append("\\nПочему ещё не Patch Ready: ").append(nr);',
    "confirmation ladder in details",
)
replace_once(
    "android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java",
    'AlertDialog dlg=new AlertDialog.Builder(this).setTitle(title).setMessage(m.toString()).setPositiveButton(android.R.string.ok,null).setNeutralButton("JSON",null).setNegativeButton("Копировать JSON",null).create();\n        dlg.setOnShowListener(x->{dlg.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v->showRaw(c));dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setOnClickListener(v->copyRaw(c));});dlg.show();',
    'AlertDialog dlg=new AlertDialog.Builder(this).setTitle(title).setMessage(m.toString()).setPositiveButton(android.R.string.ok,null).setNeutralButton("Открыть…",null).setNegativeButton("JSON",null).create();\n        dlg.setOnShowListener(x->{dlg.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v->showNavigation(c));dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setOnClickListener(v->showRaw(c));});dlg.show();',
    "details actions",
)

old_refresh = 'private void refresh(){if(revision==app.revision&&currentCatalog!=null)return;revision=app.revision;status.setText(app.status==null?"":app.status);JSONObject o=read();currentCatalog=o;'
new_refresh = 'private void refresh(){revision=app.revision;JSONObject pr=readProgress();String ps=app.status==null?"":app.status;if(pr!=null){long sec=pr.optLong("elapsedMs")/1000L;ps+="\\nЭтап "+pr.optInt("stage")+"/"+pr.optInt("totalStages")+" · "+pr.optString("name")+" · осталось этапов: "+pr.optInt("remainingStages")+" · elapsed: "+sec+"s"+(pr.has("candidates")?" · кандидатов: "+pr.optInt("candidates")+" · locator: "+pr.optInt("confirmed"):"");}status.setText(ps);if(cancel!=null)cancel.setEnabled(app.busy.get()&&!app.cancelled.get());JSONObject o=read();currentCatalog=o;'
replace_once(
    "android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java",
    old_refresh,
    new_refresh,
    "progress rendering",
)

old_mode = 'private boolean modeMatch(JSONObject c,String mode){String status=c.optString("status");String cat=c.optString("category").toLowerCase(Locale.ROOT);String title=c.optString("title").toLowerCase(Locale.ROOT);String src=c.optString("source");if("Все".equals(mode))return true;if("Важное".equals(mode))return c.optBoolean("important");if("READY".equals(mode))return status.startsWith("READY");if("Server/API".equals(mode))return c.optBoolean("serverAudit")||src.startsWith("Security");if("Crypto/Keys".equals(mode))return title.contains("crypto")||title.contains("key")||cat.contains("security");if("Gameplay".equals(mode)){String x=title+" "+cat;for(String n:new String[]{"health","hp","damage","attack","speed","cooldown","currency","gold","coin","gem","diamond","wallet","level","experience","inventory","mana","energy","camera","fov","weather","quest"})if(x.contains(n))return true;return false;}return true;}'
new_mode = 'private boolean modeMatch(JSONObject c,String mode){String stage=c.optString("verificationStage");String domain=c.optString("gameplayDomain");String own=c.optString("ownership");String blob=c.toString().toLowerCase(Locale.ROOT);if("Все".equals(mode))return true;if("Patch Ready".equals(mode))return c.optBoolean("patchReady")||"PATCH_READY".equals(stage);if("Gameplay".equals(mode))return !domain.isEmpty();if("HP / Health".equals(mode))return "health".equals(domain);if("Damage".equals(mode))return "damage".equals(domain);if("Speed".equals(mode))return "speed".equals(domain);if("Cooldown".equals(mode))return "cooldown".equals(domain);if("Currency".equals(mode))return "currency".equals(domain);if("Level / XP".equals(mode))return "level_xp".equals(domain);if("Inventory".equals(mode))return "inventory".equals(domain);if("Camera".equals(mode))return "camera".equals(domain);if("Movement".equals(mode))return "movement".equals(domain);if("Offline".equals(mode))return c.optBoolean("offlineCandidate");if("Network/API".equals(mode))return c.optBoolean("serverAudit")||blob.contains("endpoint")||blob.contains("http")||blob.contains("websocket")||blob.contains("retrofit")||blob.contains("okhttp")||blob.contains("grpc");if("Crypto/Keys".equals(mode))return blob.contains("crypto")||blob.contains("encrypt")||blob.contains("keystore")||blob.contains("secretkey")||blob.contains("certificate")||blob.contains("pinning");if("Authentication".equals(mode))return blob.contains("authentication")||blob.contains("session")||blob.contains("login")||blob.contains("oauth")||blob.contains("access token")||blob.contains("refresh token");if("Server Audit".equals(mode))return "SERVER_AUDIT".equals(stage)||c.optBoolean("serverAudit");if("Game code".equals(mode))return ("APP".equals(own)||"APP_OR_GAME".equals(own))&&!c.optBoolean("serverAudit");if("SDK".equals(mode))return "BUNDLED_SDK".equals(own);if("Framework noise".equals(mode))return "FRAMEWORK".equals(own);return true;}'
replace_once(
    "android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java",
    old_mode,
    new_mode,
    "complete filter logic",
)

# Ensure UI buttons correctly follow busy state.
replace_once(
    "android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java",
    'adapter.set(cards==null?new JSONArray():cards);build.setEnabled(!app.busy.get()&&!selected.isEmpty());prepare.setEnabled(!app.busy.get());',
    'adapter.set(cards==null?new JSONArray():cards);build.setEnabled(!app.busy.get()&&!selected.isEmpty());prepare.setEnabled(!app.busy.get());cancel.setEnabled(app.busy.get()&&!app.cancelled.get());',
    "busy button state",
)

# Current-release historical guard follows active dev version.
p = root / "tests/test_project_docs.py"
s = p.read_text(encoding="utf-8")
name = "def test_dev34_parallel_index_checkpoint_is_versioned_and_fail_closed():"
a = s.find(name)
b = s.find("\ndef ", a + len(name))
if a < 0:
    raise SystemExit("current release guard missing")
if b < 0:
    b = len(s)
block = s[a:b].replace("versionCode 44", "versionCode 45").replace("0.9.0.dev39", "0.9.0.dev40").replace("0.9.0-dev39", "0.9.0-dev40")
s = s[:a] + block + s[b:]
p.write_text(s, encoding="utf-8")

# Regression tests for dev40.
write("tests/test_dev40_simple_pipeline.py", r'''import json
from pathlib import Path

from modkit.mobile.simple_cache import plan_workspace, record_workspace
from modkit.mobile.simple_mode import build_catalog


def test_simple_cache_reuses_hash_and_invalidates_changed_target(tmp_path):
    apk = tmp_path / "game.apk"
    apk.write_bytes(b"APK-one")
    manifest = tmp_path / "simple-cache.json"
    first = json.loads(plan_workspace(tmp_path, manifest))
    assert first["unchanged"] is False and first["targetCount"] == 1
    record_workspace(tmp_path, manifest, json.dumps(first))
    second = json.loads(plan_workspace(tmp_path, manifest))
    assert second["unchanged"] is True and second["reusedHashCount"] == 1
    apk.write_bytes(b"APK-two-changed")
    third = json.loads(plan_workspace(tmp_path, manifest))
    assert third["unchanged"] is False and "game.apk" in third["changedFiles"]


def test_confirmation_ladder_and_gameplay_domain(tmp_path):
    (tmp_path / "analysis.gameplay-coverage.json").write_text(json.dumps({
        "findings": [
            {"title":"Player maxHealth","status":"CONFIRMED","category":"stats","trustBoundary":"local","artifact":"classes2.dex","class":"game.PlayerStats","method":"getMaxHealth","codeOffset":321},
            {"title":"androidx.room.RawQuery::observedEntities","status":"CONFIRMED","artifact":"classes.dex","class":"androidx.room.RawQuery","method":"observedEntities","codeOffset":42,"evidenceRole":"framework/third-party"},
            {"title":"Authentication / Session","status":"FOUND_STATIC","category":"authentication","trustBoundary":"server","class":"game.Auth"},
        ]
    }), encoding="utf-8")
    out = build_catalog(tmp_path)
    hp = next(c for c in out["cards"] if c["title"] == "Player maxHealth")
    assert hp["status"] == "READY_DEX"
    assert hp["verificationStage"] == "LOCATOR_CONFIRMED"
    assert hp["gameplayDomain"] == "health" and hp["offlineCandidate"]
    fw = next(c for c in out["cards"] if c["title"].startswith("androidx.room.RawQuery"))
    assert fw["verificationStage"] == "FRAMEWORK_NOISE"
    auth = next(c for c in out["cards"] if c["title"] == "Authentication / Session")
    assert auth["verificationStage"] == "SERVER_AUDIT" and not auth["patchReady"]


def test_menu_binding_is_patch_ready(tmp_path):
    (tmp_path / "menu-spec.json").write_text(json.dumps({"controls":[{
        "id":"hp","title":"Health multiplier","category":"health","type":"slider_float","binding":"native","rva":4096,"library":"libil2cpp.so"
    }]}), encoding="utf-8")
    out = build_catalog(tmp_path)
    card = next(c for c in out["cards"] if c.get("menuControlId") == "hp")
    assert card["verificationStage"] == "PATCH_READY" and card["patchReady"] and card["buildable"]
''')

write("tests/test_dev40_architecture.py", r'''from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]


def test_dev40_version_and_cache_module():
    gradle=(ROOT/"android/app/build.gradle").read_text(encoding="utf-8")
    assert "versionCode 45" in gradle and "0.9.0-dev40" in gradle
    cache=(ROOT/"modkit/mobile/simple_cache.py").read_text(encoding="utf-8")
    assert "reuseOnlyWhenTargetDigestMatches" in cache and "cacheDoesNotRelaxValidation" in cache


def test_dev40_simple_mode_filters_progress_cancel_and_handoff():
    ui=(ROOT/"android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java").read_text(encoding="utf-8")
    for token in ("Patch Ready","HP / Health","Damage","Cooldown","Currency","Level / XP","Inventory","Movement","Authentication","Framework noise"):
        assert token in ui
    for token in ("Отменить анализ","simple-progress.json","Открыть в Decompiler","Открыть в Native","Deep Resolve / RE Workspace"):
        assert token in ui


def test_dev40_worker_is_staged_cached_and_cancel_aware():
    worker=(ROOT/"android/app/src/main/java/dev/modkit/mobile/WorkerService.java").read_text(encoding="utf-8")
    assert "simpleStage(1,6" in worker and "simpleStage(6,6" in worker
    assert "plan_workspace" in worker and "record_workspace" in worker
    assert "simpleCheckCancelled" in worker and "passive Network/API" in worker


def test_dev40_confirmation_ladder_is_distinct_from_locator_status():
    sm=(ROOT/"modkit/mobile/simple_mode.py").read_text(encoding="utf-8")
    for token in ("FOUND_STATIC","APP_OWNED","FLOW_CONFIRMED","LOCATOR_CONFIRMED","RUNTIME_CONFIRMED","PATCH_READY","SERVER_AUDIT","SDK_NOISE","FRAMEWORK_NOISE"):
        assert token in sm
    assert 'card["verificationStage"]' in sm and 'card["gameplayDomain"]' in sm
''')

write("RELEASE-0.9.0-DEV40-RU.md", '''# ModKit 0.9.0-dev40 — Simple Mode pipeline, cache, progress and confirmation ladder

- Добавлена отдельная шкала подтверждения: `FOUND_STATIC → APP_OWNED → FLOW_CONFIRMED → LOCATOR_CONFIRMED → RUNTIME_CONFIRMED → PATCH_READY`; `SERVER_AUDIT`, `SDK_NOISE`, `FRAMEWORK_NOISE` остаются отдельными ветками. Locator-тип (`READY_DEX/NATIVE/SCRIPT/RESOURCE`) больше не смешивается со степенью доказанности.
- Gameplay-классификация получила канонические домены и синонимы для HP/health, damage/attack/defense, speed/timeScale, cooldown, currency, level/XP, inventory/reward/drop, camera/FOV, movement/teleport/gravity/jump, mana/stamina/energy.
- Simple Mode получил полный набор фильтров, поиск, объяснение «почему подтверждено / почему ещё не Patch Ready» и handoff точного locator в Decompiler / Native / File Workspace / RE Workspace.
- Добавлен структурированный `simple-progress.json`: этап/всего, оставшиеся этапы, elapsed, число кандидатов/locator/PATCH_READY. В UI есть явная кнопка отмены; между дорогими этапами проверяется cancel flag.
- Добавлен первый безопасный инкрементальный cache layer: SHA-256 каждого APK/split + target digest. При неизменном target переиспользуются уже проверенные analysis/security reports; изменение любого split переводит pipeline на fresh path. Кэш не снижает требования fail-closed validation.
- Network/API/Crypto scan остаётся полностью пассивным. Автоматический server/payment/economy bypass не добавлялся.
- Автосборка по-прежнему разрешена только для MenuSpec controls с проверенным executable binding/RVA и не включает server/trust findings.
''')

write("VALIDATION-DEV40.json", json.dumps({
    "version":"0.9.0-dev40","versionCode":45,
    "features":["confirmation-ladder","gameplay-domain-ranking","complete-simple-filters","structured-progress","fast-cancel-checkpoints","split-sha256-cache","workspace-locator-handoff"],
    "policy":{"activeNetworkUse":False,"serverBypassGenerated":False,"cacheRelaxesValidation":False,"autoBuildRequiresValidatedExecutableBinding":True},
    "ci":"full pytest + selftest + runtime-check + assembleDebug + lintDebug + unzip + zipalign + apksigner"
}, ensure_ascii=False, indent=2) + "\n")

print("dev40 applied to", root)
