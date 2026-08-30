#!/usr/bin/env python3
import argparse, hashlib, json, os, re
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def signer_digest(path: Path) -> str:
    text = path.read_text(encoding='utf-8', errors='replace')
    match = re.search(r'certificate SHA-256 digest:\s*([0-9a-fA-F:]{64,95})', text, re.IGNORECASE)
    if not match:
        raise SystemExit('Signer certificate SHA-256 digest not found in apksigner evidence')
    value = match.group(1).replace(':', '').lower()
    if not re.fullmatch(r'[0-9a-f]{64}', value):
        raise SystemExit('Invalid signer certificate SHA-256 digest')
    return value


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default='.')
    ap.add_argument('--apk', required=True)
    ap.add_argument('--aab', required=True)
    ap.add_argument('--signer-report', required=True)
    ap.add_argument('--toolchain-report', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--commit', default=os.environ.get('GITHUB_SHA', 'unknown'))
    args = ap.parse_args()
    root = Path(args.root).resolve()
    app_build = (root / 'app/build.gradle.kts').read_text()
    version_name = re.search(r'versionName\s*=\s*"([^"]+)"', app_build).group(1)
    version_code = int(re.search(r'versionCode\s*=\s*(\d+)', app_build).group(1))
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '0'))
    generated = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace('+00:00', 'Z')
    apk, aab = Path(args.apk), Path(args.aab)
    signer, toolchain = Path(args.signer_report), Path(args.toolchain_report)
    source_manifest = root / 'SOURCE_MANIFEST.sha256'
    toolchain_payload = json.loads(toolchain.read_text(encoding='utf-8'))
    payload = {
        'schemaVersion': '1.1',
        'product': 'UniRevLab Security',
        'versionName': version_name,
        'versionCode': version_code,
        'commit': args.commit,
        'sourceDateEpoch': epoch,
        'generatedAt': generated,
        'sourceManifestSha256': sha256(source_manifest),
        'signing': {
            'certificateSha256': signer_digest(signer),
            'evidenceSha256': sha256(signer),
        },
        'toolchainEvidenceSha256': sha256(toolchain),
        'toolchain': toolchain_payload.get('toolchain', {}),
        'requiredConnectedGates': ['ANDROID_SIGNED_RELEASE', 'GHIDRA_MULTIABI_IL2CPP'],
        'artifacts': [
            {'kind': 'APK', 'name': apk.name, 'sizeBytes': apk.stat().st_size, 'sha256': sha256(apk)},
            {'kind': 'AAB', 'name': aab.name, 'sizeBytes': aab.stat().st_size, 'sha256': sha256(aab)},
        ],
    }
    Path(args.out).write_text(json.dumps(payload, sort_keys=True, indent=2) + '\n')

if __name__ == '__main__':
    main()
