#!/usr/bin/env python3
from __future__ import annotations
import argparse, base64, hashlib, json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--payload', type=Path, required=True)
    ap.add_argument('--private-key', type=Path, required=True)
    ap.add_argument('--key-id', required=True)
    ap.add_argument('--out', type=Path, required=True)
    args=ap.parse_args()
    data=args.payload.read_bytes(); digest=hashlib.sha256(data).hexdigest()
    key=serialization.load_pem_private_key(args.private_key.read_bytes(), password=None)
    if not isinstance(key,Ed25519PrivateKey): raise TypeError('Ed25519 private key required')
    sig=key.sign(data)
    pub=key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    out={'schemaVersion':'1.0','algorithm':'ED25519','keyId':args.key_id,'payloadSha256':digest,'publicKeySha256':hashlib.sha256(pub).hexdigest(),'signatureBase64':base64.b64encode(sig).decode()}
    args.out.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n')
    return 0
if __name__=='__main__': raise SystemExit(main())
