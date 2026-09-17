package dev.modkit.mobile;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Locale;

/** Exact-SHA freshness verifier for the AutoMod native-recovery prepare audit. */
final class AutoModAuditVerifier {
    interface CancelGate { boolean isCancelled(); }

    private AutoModAuditVerifier() {}

    static JSONObject read(App app) {
        try {
            File file=app.file("menu-native-recovery.json");
            return file.isFile()?new JSONObject(Io.readUtf8(file)):null;
        } catch(Exception ignored) {
            return null;
        }
    }

    static boolean structurallyReady(JSONObject audit) {
        if(audit==null) return false;
        if(!audit.optBoolean("completed")) return false;
        if(!audit.optBoolean("normalBindingRequired")||!audit.optBoolean("preflightRequired")) return false;
        if(audit.optBoolean("promotesBuildability")||audit.optBoolean("addressRecoveryPromotesBuildability")) return false;
        if(!audit.optBoolean("phase7PlanRequired")) return false;
        JSONObject phase7=audit.optJSONObject("phase7Gate");
        if(phase7==null||!phase7.optBoolean("validated")) return false;
        if(!"modkit-automod-phase7-prepare-gate-1.0".equals(phase7.optString("schema"))) return false;
        if(!phase7.optBoolean("methodIdentityRequiredForBoundRva")) return false;
        if(phase7.optInt("identityBoundRvaCount",-1)<0) return false;
        if(phase7.optInt("rejectedControlCount",-1)!=0) return false;
        if(phase7.optInt("executableControlCount",0)<=0||phase7.optInt("allowedRvaCount",0)<=0) return false;
        if(phase7.optBoolean("runtimeEvidencePromotesBuildability")||phase7.optBoolean("reviewEvidencePromotesBuildability")) return false;
        if(!"EXACT_INPUT_SHA256".equals(audit.optString("freshnessPolicy"))) return false;
        if(!"EXACT_PLAN_AND_CATALOG_SHA256".equals(audit.optString("phase7FreshnessPolicy"))) return false;
        JSONArray rows=audit.optJSONArray("inputFingerprints");
        JSONArray outputs=audit.optJSONArray("outputFingerprints");
        if(rows==null||rows.length()<6||outputs==null||outputs.length()<2) return false;
        return validFingerprint(fingerprint(rows,"metadata"))
                &&validFingerprint(fingerprint(rows,"library"))
                &&validFingerprint(fingerprint(rows,"catalog"))
                &&validFingerprint(fingerprint(rows,"sourceApk"))
                &&validFingerprint(fingerprint(rows,"phase7Plan"))
                &&validFingerprint(fingerprint(rows,"simpleCatalog"))
                &&validFingerprint(fingerprint(outputs,"menuSpec"))
                &&validFingerprint(fingerprint(outputs,"menuPreflight"));
    }

    /** Bind the completed Python prepare audit to the exact Evidence Graph projection used by Phase 7. */
    static JSONObject bindPhase7Inputs(App app,CancelGate gate)throws Exception {
        check(gate);
        JSONObject audit=read(app);
        if(audit==null||!audit.optBoolean("completed"))throw new IOException("Phase 7 prepare audit отсутствует или не завершён");
        JSONObject phase7=audit.optJSONObject("phase7Gate");
        if(phase7==null||!phase7.optBoolean("validated")||phase7.optInt("rejectedControlCount",-1)!=0)
            throw new IOException("Phase 7 executable-control gate не подтверждён");
        JSONArray existing=audit.optJSONArray("inputFingerprints");
        if(existing==null)throw new IOException("Phase 7 prepare audit не содержит input fingerprints");
        JSONArray rows=new JSONArray();
        for(int i=0;i<existing.length();i++){
            JSONObject row=existing.optJSONObject(i);if(row==null)continue;
            String role=row.optString("role","");
            if("phase7Plan".equals(role)||"simpleCatalog".equals(role))continue;
            rows.put(row);
        }
        rows.put(currentFingerprint("phase7Plan",app.file("automod-plan.json"),gate));
        rows.put(currentFingerprint("simpleCatalog",app.file("simple-catalog.json"),gate));
        audit.put("inputFingerprints",rows);

        JSONArray existingOutputs=audit.optJSONArray("outputFingerprints");
        if(existingOutputs==null)throw new IOException("Phase 7 prepare audit не содержит output fingerprints");
        JSONArray outputs=new JSONArray();
        for(int i=0;i<existingOutputs.length();i++){
            JSONObject row=existingOutputs.optJSONObject(i);if(row==null)continue;
            if("menuPreflight".equals(row.optString("role","")))continue;
            outputs.put(row);
        }
        outputs.put(currentFingerprint("menuPreflight",app.file("menu-preflight.json"),gate));
        audit.put("outputFingerprints",outputs);
        audit.put("phase7FreshnessPolicy","EXACT_PLAN_AND_CATALOG_SHA256");
        File destination=app.file("menu-native-recovery.json"),temp=app.file("menu-native-recovery.json.tmp");
        Io.writeUtf8(temp,audit.toString(2));
        check(gate);
        Files.move(temp.toPath(),destination.toPath(),StandardCopyOption.REPLACE_EXISTING);
        check(gate);
        return audit;
    }

    /**
     * Rebuild the preflight from the exact current MenuSpec/source APK before a build.
     *
     * Legacy Menu Builder callers may rewrite menu-preflight.json without the newer
     * callable/range readiness fields.  We never trust or merely re-hash that file:
     * all stable inputs and MenuSpec are verified first, the base report is regenerated
     * by the canonical Python review_preflight implementation, then callable_preflight
     * augments it, and only that regenerated artifact is SHA-bound into the audit.
     */
    static JSONObject refreshCanonicalPreflight(App app,File sourceApk,CancelGate gate)throws Exception {
        JSONObject audit=read(app);
        if(!structurallyReady(audit))throw new IOException("Exact recovery audit не готов к canonical preflight refresh");
        verifyStableInputs(app,sourceApk,audit,gate);
        check(gate);
        if(!Python.isStarted())Python.start(new AndroidPlatform(app));
        PyObject engine=Python.getInstance().getModule("modkit.mobile.engine");
        engine.callAttr("menu_review_preflight",
                app.file("menu-spec.json").getPath(),sourceApk.getPath(),app.file("menu-preflight.json").getPath(),null);
        check(gate);
        PyObject callable=Python.getInstance().getModule("modkit.menu.callable_preflight");
        JSONObject preflight=new JSONObject(callable.callAttr("augment_preflight_json",
                app.file("menu-spec.json").getPath(),app.file("menu-preflight.json").getPath(),sourceApk.getPath(),0.85).toString());
        check(gate);
        bindPhase7Inputs(app,gate);
        verifyCurrent(app,sourceApk,gate);
        return preflight;
    }

    static JSONObject verifyCurrent(App app,File sourceApk,CancelGate gate)throws Exception {
        JSONObject audit=read(app);
        if(!structurallyReady(audit))throw new IOException("Exact recovery audit не содержит обязательную Phase 7 identity + plan/catalog/preflight SHA-256 freshness proof");
        verifyStableInputs(app,sourceApk,audit,gate);
        JSONArray outputs=audit.getJSONArray("outputFingerprints");
        verify(outputs,"menuPreflight",app.file("menu-preflight.json"),gate);
        return audit;
    }

    private static void verifyStableInputs(App app,File sourceApk,JSONObject audit,CancelGate gate)throws Exception {
        JSONArray rows=audit.getJSONArray("inputFingerprints");
        JSONArray outputs=audit.getJSONArray("outputFingerprints");
        verify(rows,"metadata",app.file("metadata.bin"),gate);
        verify(rows,"library",app.file("library.so"),gate);
        verify(rows,"catalog",app.file("analysis.methods.jsonl"),gate);
        verify(rows,"sourceApk",sourceApk,gate);
        verify(rows,"phase7Plan",app.file("automod-plan.json"),gate);
        verify(rows,"simpleCatalog",app.file("simple-catalog.json"),gate);
        verify(outputs,"menuSpec",app.file("menu-spec.json"),gate);
        JSONObject phase7=audit.getJSONObject("phase7Gate");
        if(!phase7.optBoolean("validated")||!phase7.optBoolean("methodIdentityRequiredForBoundRva")||phase7.optInt("rejectedControlCount",-1)!=0)
            throw new IOException("AutoMod Phase 7 identity gate stale или содержит rejected executable control");
        if(!"EXACT_PLAN_AND_CATALOG_SHA256".equals(audit.optString("phase7FreshnessPolicy")))
            throw new IOException("AutoMod Phase 7 plan/catalog freshness policy отсутствует");
    }

    private static JSONObject currentFingerprint(String role,File file,CancelGate gate)throws Exception {
        check(gate);
        if(file==null||!file.isFile())throw new IOException("Exact recovery audit: вход "+role+" отсутствует");
        return new JSONObject().put("role",role).put("name",file.getName()).put("size",file.length()).put("sha256",sha256(file,gate));
    }

    private static JSONObject fingerprint(JSONArray rows,String role) {
        for(int i=0;i<rows.length();i++){
            JSONObject row=rows.optJSONObject(i);
            if(row!=null&&role.equals(row.optString("role")))return row;
        }
        return null;
    }

    private static boolean validFingerprint(JSONObject row) {
        if(row==null)return false;
        if(row.optLong("size",-1L)<0L)return false;
        String sha=row.optString("sha256","");
        return sha.matches("(?i)[0-9a-f]{64}");
    }

    private static void verify(JSONArray rows,String role,File file,CancelGate gate)throws Exception {
        check(gate);
        JSONObject expected=fingerprint(rows,role);
        if(!validFingerprint(expected))throw new IOException("Exact recovery audit: повреждён fingerprint "+role);
        if(file==null||!file.isFile())throw new IOException("Exact recovery audit stale: вход "+role+" отсутствует");
        long expectedSize=expected.optLong("size",-1L);
        String expectedSha=expected.optString("sha256","");
        if(expectedSize!=file.length())throw new IOException("Exact recovery audit stale: размер "+role+" изменился");
        String actual=sha256(file,gate);
        if(!expectedSha.equalsIgnoreCase(actual))throw new IOException("Exact recovery audit stale: SHA-256 "+role+" изменился");
        check(gate);
    }

    private static String sha256(File file,CancelGate gate)throws Exception {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        byte[] buffer=new byte[1024*1024];
        try(FileInputStream in=new FileInputStream(file)){
            int n;
            while((n=in.read(buffer))!=-1){check(gate);digest.update(buffer,0,n);}
        }
        check(gate);
        StringBuilder out=new StringBuilder();
        for(byte b:digest.digest())out.append(String.format(Locale.ROOT,"%02x",b));
        return out.toString();
    }

    private static void check(CancelGate gate)throws IOException {
        if(gate!=null&&gate.isCancelled())throw new java.io.InterruptedIOException("AutoMod audit verification cancelled");
    }
}
