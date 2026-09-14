#!/usr/bin/env python3
from pathlib import Path
import shutil, sys
root=Path(sys.argv[1]).resolve(); here=Path(__file__).resolve().parent

def rw(rel, fn):
    p=root/rel; s=p.read_text(encoding='utf-8'); n=fn(s); p.write_text(n,encoding='utf-8')
def one(s,a,b,label):
    if s.count(a)!=1: raise SystemExit(f'{label}: marker count={s.count(a)}')
    return s.replace(a,b,1)

shutil.copyfile(here/'net_scan.py',root/'modkit/mobile/security_scan.py')
rw('android/app/build.gradle',lambda s:one(one(s,'versionCode 42','versionCode 43','code'),"versionName '0.9.0-dev37'","versionName '0.9.0-dev38'",'name'))
rw('pyproject.toml',lambda s:one(s,'version = "0.9.0.dev37"','version = "0.9.0.dev38"','pyproject'))
rw('modkit/__init__.py',lambda s:one(s,'__version__ = "0.9.0-dev37"','__version__ = "0.9.0-dev38"','init'))

def simple(s):
    s=one(s,'SCHEMA = "modkit-simple-mode-1.0"','SCHEMA = "modkit-simple-mode-1.1"','schema')
    s=one(s,'("installed-scan.json", "InstalledScan"),\n    ]','("installed-scan.json", "InstalledScan"),\n        ("security-surfaces.json", "SecuritySurface"),\n    ]','sources')
    marker='''    cards.sort(key=lambda c: (\n'''
    inject='''    # Exact local locators are useful even when they are not generic MenuSpec bindings.\n    # Keep auto-build fail-closed; READY_* only means the corresponding workspace has an exact target.\n    for c in cards:\n        c.setdefault("actionable", bool(c.get("buildable")))\n        if c.get("serverAudit") or c.get("buildable") or c.get("status") not in {"CONFIRMED","VERIFIED","PACKAGE_OBSERVED","FIELD_OBSERVED"}:\n            continue\n        ev=c.get("evidence") if isinstance(c.get("evidence"),dict) else {}\n        title=str(c.get("title") or ""); low=(title+" "+str(c.get("source") or "")).lower()\n        if title.lower().startswith(("android.","androidx.","java.","javax.","kotlin.","kotlinx.","com.google.","org.jetbrains.")):\n            continue\n        if ev.get("rva") is not None:\n            c["status"]="READY_NATIVE"; c["actionable"]=True; c["locator"]={"rva":ev.get("rva"),"abi":ev.get("abi"),"library":ev.get("library") or ev.get("module")}\n        elif "::" in title and "(" in title and ")" in title and any(x in low for x in ("dex","smali")):\n            c["status"]="READY_DEX"; c["actionable"]=True; c["locator"]={"signature":title}\n        else:\n            entry=str(ev.get("entry") or ev.get("path") or ev.get("file") or ev.get("apkEntry") or ev.get("asset") or "")\n            fn=str(ev.get("function") or ev.get("functionName") or ev.get("symbol") or ev.get("name") or "")\n            if entry.lower().endswith((".lua",".luac",".luae",".js",".jsc")) and fn:\n                c["status"]="READY_SCRIPT"; c["actionable"]=True; c["locator"]={"entry":entry,"symbol":fn}\n            elif entry and (entry.lower().startswith("res/") or entry.lower().startswith("assets/")) and ev.get("offset") is not None:\n                c["status"]="READY_RESOURCE"; c["actionable"]=True; c["locator"]={"entry":entry,"offset":ev.get("offset")}\n\n'''
    s=one(s,marker,inject+marker,'ready-inject')
    s=one(s,'0 if c.get("status") == "READY" else 1 if c.get("status") == "READY_FOR_PREPARE" else 2 if c.get("status") == "REVIEW" else 3,','0 if str(c.get("status", "")).startswith("READY") else 2 if c.get("status") == "REVIEW" else 3,','sort')
    s=one(s,'"buildable": sum(1 for c in cards if c.get("buildable")),\n        "serverAudit":','"buildable": sum(1 for c in cards if c.get("buildable")),\n        "actionable": sum(1 for c in cards if c.get("actionable")),\n        "serverAudit":','count')
    return s
rw('modkit/mobile/simple_mode.py',simple)

def worker(s):
    old='''        if(app.file("analysis.json").isFile()||app.file("re-analysis.json").isFile()){try{menuSmartPrepare();}catch(Exception e){new Progress().progress("Simple Mode: Menu prepare остаётся REVIEW — "+e.getMessage());}}\n        if(!Python.isStarted())Python.start(new AndroidPlatform(this));PyObject mod=Python.getInstance().getModule("modkit.mobile.simple_mode");PyObject out=mod.callAttr("build_catalog",getFilesDir().getPath(),app.file("simple-catalog.json").getPath());JSONObject obj=new JSONObject(out.toString());app.progress("Simple Mode: показано "+obj.optInt("total")+" находок; READY "+obj.optInt("buildable")+", server/trust audit "+obj.optInt("serverAudit")+".");\n'''
    new='''        if(!Python.isStarted())Python.start(new AndroidPlatform(this));\n        app.progress("Simple Mode: пассивный поиск API/endpoint, TLS pinning и crypto/key markers…");\n        PyObject sec=Python.getInstance().getModule("modkit.mobile.security_scan");sec.callAttr("scan_workspace",getFilesDir().getPath(),app.file("security-surfaces.json").getPath());\n        if(app.file("analysis.json").isFile()||app.file("analysis.methods.jsonl").isFile()||app.file("re-analysis.json").isFile()){try{menuSmartPrepare();}catch(Exception e){new Progress().progress("Simple Mode: Menu prepare остаётся REVIEW — "+e.getMessage());}}\n        PyObject mod=Python.getInstance().getModule("modkit.mobile.simple_mode");PyObject out=mod.callAttr("build_catalog",getFilesDir().getPath(),app.file("simple-catalog.json").getPath());JSONObject obj=new JSONObject(out.toString());app.progress("Simple Mode: показано "+obj.optInt("total")+" находок; auto-build READY "+obj.optInt("buildable")+", actionable "+obj.optInt("actionable")+", server/trust audit "+obj.optInt("serverAudit")+".");\n'''
    return one(s,old,new,'worker')
rw('android/app/src/main/java/dev/modkit/mobile/WorkerService.java',worker)

rw('android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java',lambda s:one(s,'summary.setText("Найдено: "+o.optInt("total")+" · READY: "+o.optInt("buildable")+" · server/trust audit: "+o.optInt("serverAudit")+"\\n"+(counts==null?"":counts.toString()));','summary.setText("Найдено: "+o.optInt("total")+" · авто-сборка READY: "+o.optInt("buildable")+" · locator/actionable: "+o.optInt("actionable")+" · server/trust audit: "+o.optInt("serverAudit")+"\\n"+(counts==null?"":counts.toString()));','ui'))

p=root/'tests/test_project_docs.py'; s=p.read_text(encoding='utf-8'); name='def test_dev34_parallel_index_checkpoint_is_versioned_and_fail_closed():'; a=s.find(name); b=s.find('\ndef ',a+len(name))
if a<0: raise SystemExit('version guard missing')
if b<0:b=len(s)
block=s[a:b].replace('versionCode 42','versionCode 43').replace('0.9.0.dev37','0.9.0.dev38').replace('0.9.0-dev37','0.9.0-dev38'); p.write_text(s[:a]+block+s[b:],encoding='utf-8')
(root/'RELEASE-0.9.0-DEV38-RU.md').write_text('# ModKit 0.9.0-dev38 — Security Surface Scan + точный READY\n\nSimple Mode пассивно ищет API/server endpoints, TLS pins, network/crypto/key-handling markers и показывает точные READY_NATIVE / READY_DEX / READY_SCRIPT / READY_RESOURCE locators. Автосборка по-прежнему требует проверенный executable MenuSpec binding.\n',encoding='utf-8')
print('dev38 applied')
