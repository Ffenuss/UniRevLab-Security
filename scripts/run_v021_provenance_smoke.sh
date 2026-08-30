#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${TMPDIR:-/tmp}/unirevlab-v021-provenance"
rm -rf "$OUT" && mkdir -p "$OUT/ghidra/arm64" "$OUT/ghidra/arm32" "$OUT/ghidra/x86_64"
python3 - "$OUT" <<'PY'
from pathlib import Path
import json, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
out=Path(sys.argv[1])
key=Ed25519PrivateKey.generate()
(out/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
(out/'pub.pem').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
(out/'feed.json').write_text(json.dumps({'schemaVersion':'1.0','feedId':'fixture','source':'fixture','generatedAt':'2026-08-30T00:00:00Z','advisories':[]},sort_keys=True)+'\n')
(out/'package-index.json').write_text('{"packages":[]}\n')
for abi in ('arm64','arm32','x86_64'):
    (out/'ghidra'/abi/'result.json').write_text(json.dumps({'abi':abi,'status':'COMPLETE'},sort_keys=True)+'\n')
(out/'signing.txt').write_text('Signer #1 certificate SHA-256 digest: ' + '1'*64 + '\n')
(out/'toolchain.json').write_text(json.dumps({'java':'17','gradle':'9.5.0','androidSdk':'37','buildTools':'36.0.0','ndk':'28.2.13676358'},sort_keys=True)+'\n')
(out/'apk').write_bytes(b'apk-fixture')
(out/'aab').write_bytes(b'aab-fixture')
PY
python3 "$ROOT/scripts/sign_feed_provenance.py" sign --payload "$OUT/feed.json" --private-key "$OUT/key.pem" --key-id fixture --payload-type ADVISORY_FEED --out "$OUT/feed.envelope.json"
python3 "$ROOT/scripts/sign_feed_provenance.py" verify --payload "$OUT/feed.json" --envelope "$OUT/feed.envelope.json" --public-key "$OUT/pub.pem"
python3 "$ROOT/scripts/sign_feed_provenance.py" sign --payload "$OUT/package-index.json" --private-key "$OUT/key.pem" --key-id fixture --payload-type PACKAGE_INDEX --out "$OUT/package.envelope.json"
python3 "$ROOT/scripts/sign_feed_provenance.py" verify --payload "$OUT/package-index.json" --envelope "$OUT/package.envelope.json" --public-key "$OUT/pub.pem"
# Synthetic release manifest compatible with attestation generator.
python3 - "$ROOT" "$OUT" <<'PY'
import hashlib,json,sys
from pathlib import Path
root,out=map(Path,sys.argv[1:])
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
manifest={
 'schemaVersion':'1.1','product':'UniRevLab Security','versionName':'fixture','versionCode':1,'commit':'f'*40,'sourceDateEpoch':1,'generatedAt':'1970-01-01T00:00:01Z',
 'sourceManifestSha256':'a'*64,
 'signing':{'certificateSha256':'1'*64,'evidenceSha256':sha(out/'signing.txt')},
 'toolchainEvidenceSha256':sha(out/'toolchain.json'),'toolchain':{'java':'17','gradle':'9.5.0','androidSdk':'37','buildTools':'36.0.0','ndk':'28.2.13676358'},
 'requiredConnectedGates':['ANDROID_SIGNED_RELEASE','GHIDRA_MULTIABI_IL2CPP'],
 'artifacts':[{'kind':'APK','name':'app.apk','sizeBytes':(out/'apk').stat().st_size,'sha256':sha(out/'apk')},{'kind':'AAB','name':'app.aab','sizeBytes':(out/'aab').stat().st_size,'sha256':sha(out/'aab')}]
}
(out/'release-manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
PY
python3 "$ROOT/scripts/make_release_attestation.py" --release-manifest "$OUT/release-manifest.json" --ghidra-evidence-dir "$OUT/ghidra" --android-evidence "$OUT/signing.txt" --android-evidence "$OUT/toolchain.json" --android-evidence "$OUT/release-manifest.json" --out "$OUT/release-attestation.json"
python3 "$ROOT/scripts/sign_detached_ed25519.py" --payload "$OUT/release-attestation.json" --private-key "$OUT/key.pem" --key-id fixture-attestation --out "$OUT/release-attestation.sig.json"
python3 - "$ROOT" "$OUT" <<'PY'
import base64,hashlib,json,sys
from pathlib import Path
from jsonschema import Draft202012Validator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
root,out=map(Path,sys.argv[1:])
for name in ('signed-feed-envelope.schema.json','release-attestation.schema.json','detached-signature.schema.json'):
    schema=json.loads((root/'schemas'/name).read_text()); Draft202012Validator.check_schema(schema)
att=json.loads((out/'release-attestation.json').read_text())
assert [g['status'] for g in att['connectedGates']]==['PASS','PASS']
sig=json.loads((out/'release-attestation.sig.json').read_text()); payload=(out/'release-attestation.json').read_bytes()
assert hashlib.sha256(payload).hexdigest()==sig['payloadSha256']
pub=serialization.load_pem_public_key((out/'pub.pem').read_bytes()); assert isinstance(pub,Ed25519PublicKey)
pub.verify(base64.b64decode(sig['signatureBase64']), payload)
print('v0.21 signed feed/package-index + release attestation smoke PASS')
PY
