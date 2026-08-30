#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def signing_message(payload_type: str, digest: str) -> bytes:
    return f"UNIREVLAB-SIGNED-PAYLOAD-1\n{payload_type}\n{digest.lower()}\n".encode()


def sign(payload: Path, key_path: Path, key_id: str, payload_type: str, out: Path) -> dict[str, str]:
    data = payload.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise TypeError("Signing key must be Ed25519")
    signature = private.sign(signing_message(payload_type, digest))
    envelope = {
        "schemaVersion": "1.0",
        "payloadType": payload_type,
        "payloadSha256": digest,
        "keyId": key_id,
        "algorithm": "ED25519",
        "signatureBase64": base64.b64encode(signature).decode("ascii"),
    }
    out.write_text(json.dumps(envelope, sort_keys=True, indent=2) + "\n")
    return envelope


def verify(payload: Path, envelope_path: Path, public_key_path: Path) -> None:
    envelope = json.loads(envelope_path.read_text())
    data = payload.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != envelope["payloadSha256"]:
        raise ValueError("payload hash mismatch")
    public = serialization.load_pem_public_key(public_key_path.read_bytes())
    if not isinstance(public, Ed25519PublicKey):
        raise TypeError("Verification key must be Ed25519")
    public.verify(base64.b64decode(envelope["signatureBase64"]), signing_message(envelope["payloadType"], digest))


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("sign")
    p.add_argument("--payload", type=Path, required=True)
    p.add_argument("--private-key", type=Path, required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--payload-type", choices=["ADVISORY_FEED", "PACKAGE_INDEX"], required=True)
    p.add_argument("--out", type=Path, required=True)
    v = sub.add_parser("verify")
    v.add_argument("--payload", type=Path, required=True)
    v.add_argument("--envelope", type=Path, required=True)
    v.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "sign":
        sign(args.payload, args.private_key, args.key_id, args.payload_type, args.out)
    else:
        verify(args.payload, args.envelope, args.public_key)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
