package dev.modkit.mobile;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;

/** Local APK signing identity. The private key never ships in the ModKit APK. */
final class SigningKeyManager {
    private static final String PROVIDER="AndroidKeyStore";
    private static final String ALIAS="modkit-local-apk-signing-v1";

    static final class Identity {
        final PrivateKey privateKey;
        final List<X509Certificate> certificates;
        final String fingerprintSha256;
        Identity(PrivateKey key,List<X509Certificate> certs,String fingerprint){
            privateKey=key;certificates=certs;fingerprintSha256=fingerprint;
        }
    }

    static Identity getOrCreate() throws Exception {
        KeyStore store=KeyStore.getInstance(PROVIDER);store.load(null);
        if(!store.containsAlias(ALIAS))create();
        KeyStore.Entry raw=store.getEntry(ALIAS,null);
        if(!(raw instanceof KeyStore.PrivateKeyEntry))throw new IllegalStateException("AndroidKeyStore signing identity unavailable");
        KeyStore.PrivateKeyEntry entry=(KeyStore.PrivateKeyEntry)raw;
        List<X509Certificate> certs=new ArrayList<>();
        for(java.security.cert.Certificate cert:entry.getCertificateChain())certs.add((X509Certificate)cert);
        if(certs.isEmpty())throw new IllegalStateException("Signing certificate chain empty");
        return new Identity(entry.getPrivateKey(),certs,fingerprint(certs.get(0)));
    }

    private static void create() throws Exception {
        long now=System.currentTimeMillis();
        KeyPairGenerator generator=KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA,PROVIDER);
        generator.initialize(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_SIGN|KeyProperties.PURPOSE_VERIFY)
            .setKeySize(3072)
            .setDigests(KeyProperties.DIGEST_SHA256,KeyProperties.DIGEST_SHA512)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setCertificateSubject(new X500Principal("CN=ModKit Local APK Signing,O=ModKit"))
            .setCertificateSerialNumber(new BigInteger(1,new byte[]{0x4d,0x4b,0x31}))
            .setCertificateNotBefore(new Date(now-24L*60*60*1000))
            .setCertificateNotAfter(new Date(now+20L*365*24*60*60*1000))
            .build());
        generator.generateKeyPair();
    }

    private static String fingerprint(X509Certificate certificate) throws Exception {
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        StringBuilder out=new StringBuilder(digest.length*2);
        for(byte b:digest)out.append(String.format(java.util.Locale.ROOT,"%02x",b&0xff));
        return out.toString();
    }
}
