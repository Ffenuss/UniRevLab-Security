#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path


def sha(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--release-manifest', type=Path, required=True)
    ap.add_argument('--ghidra-evidence-dir', type=Path, required=True)
    ap.add_argument('--android-evidence', type=Path, action='append', default=[])
    ap.add_argument('--out', type=Path, required=True)
    args=ap.parse_args()
    manifest=json.loads(args.release_manifest.read_text())
    ghidra=sorted(args.ghidra_evidence_dir.rglob('result.json'))
    if len(ghidra) != 3:
        raise SystemExit(f'expected exactly 3 Ghidra result.json files, got {len(ghidra)}')
    android=[p for p in args.android_evidence if p.is_file()]
    if len(android) != len(args.android_evidence) or not android:
        raise SystemExit('missing Android release evidence')
    att={
      'schemaVersion':'1.0',
      'predicateType':'https://unirevlab.org/attestation/release/v1',
      'commit':manifest['commit'],
      'releaseManifestSha256':sha(args.release_manifest),
      'sourceManifestSha256':manifest['sourceManifestSha256'],
      'signerCertificateSha256':manifest['signing']['certificateSha256'],
      'subjects':[{'kind':a['kind'],'name':a['name'],'sha256':a['sha256']} for a in manifest['artifacts']],
      'connectedGates':[
        {'name':'ANDROID_SIGNED_RELEASE','status':'PASS','evidence':[{'name':p.name,'sha256':sha(p)} for p in sorted(android)]},
        {'name':'GHIDRA_MULTIABI_IL2CPP','status':'PASS','evidence':[{'name':str(p.relative_to(args.ghidra_evidence_dir)),'sha256':sha(p)} for p in ghidra]},
      ],
    }
    args.out.write_text(json.dumps(att, sort_keys=True, indent=2)+'\n')
    return 0
if __name__=='__main__': raise SystemExit(main())
