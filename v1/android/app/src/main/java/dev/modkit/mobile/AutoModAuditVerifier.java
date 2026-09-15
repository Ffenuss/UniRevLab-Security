package dev.modkit.mobile;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
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
        if(phase7.optInt("rejectedControlCount",-1)!=0) return false;
        if(phase7.optInt("executableControlCount",0)<=0||phase7.optInt("allowedRvaCount",0)<=0) return false;
        if(phase7.optBoolean("runtimeEvidencePromotesBuildability")||phase7.optBoolean("reviewEvidencePromotesBuildability")) return false;
        if(!"EXACT_INPUT_SHA256".equals(audit.optString("freshnessPolicy"))) return false;
        JSONArray rows=audit.optJSONArray("inputFingerprints");
        JSONArray outputs=audit.optJSONArray("outputFingerprints");
        if(rows==null||rows.length()<4||outputs==null||outputs.length()<1) return false;
        return validFingerprint(fingerprint(rows,"metadata"))
                &&validFingerprint(fingerprint(rows,"library"))
                &&validFingerprint(fingerprint(rows,"catalog"))
                &&validFingerprint(fingerprint(rows,"sourceApk"))
                &&validFingerprint(fingerprint(outputs,"menuSpec"));
    }

    static JSONObject verifyCurrent(App app,File sourceApk,CancelGate gate)throws Exception {
        JSONObject audit=read(app);
        if(!structurallyReady(audit))throw new IOException("Exact recovery audit не содержит обязательную Phase 7 + SHA-256 freshness proof");
        JSONArray rows=audit.getJSONArray("inputFingerprints");
        JSONArray outputs=audit.getJSONArray("outputFingerprints");
        verify(rows,"metadata",app.file("metadata.bin"),gate);
        verify(rows,"library",app.file("library.so"),gate);
        verify(rows,"catalog",app.file("analysis.methods.jsonl"),gate);
        verify(rows,"sourceApk",sourceApk,gate);
        verify(outputs,"menuSpec",app.file("menu-spec.json"),gate);
        JSONObject phase7=audit.getJSONObject("phase7Gate");
        if(!phase7.optBoolean("validated")||phase7.optInt("rejectedControlCount",-1)!=0)
            throw new IOException("AutoMod Phase 7 gate stale или содержит rejected executable control");
        return audit;
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
