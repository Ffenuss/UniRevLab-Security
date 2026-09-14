package dev.modkit.mobile;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;
import java.io.*;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;

final class ApkSignerUtil {
    static void sign(File unsignedApk,File outputApk,SigningKeyManager.Identity identity) throws Exception {
        List<X509Certificate> certs=new ArrayList<>(identity.certificates);
        ApkSigner.SignerConfig signer=new ApkSigner.SignerConfig.Builder("ModKit local",(PrivateKey)identity.privateKey,certs).build();
        new ApkSigner.Builder(Collections.singletonList(signer)).setInputApk(unsignedApk).setOutputApk(outputApk)
                .setV1SigningEnabled(true).setV2SigningEnabled(true).setV3SigningEnabled(false).build().sign();
        ApkVerifier.Result result=new ApkVerifier.Builder(outputApk).build().verify();
        if(!result.isVerified())throw new IOException("Проверка подписи собранного APK не пройдена: "+result.getErrors());
    }
}
