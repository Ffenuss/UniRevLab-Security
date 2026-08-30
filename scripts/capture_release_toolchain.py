#!/usr/bin/env python3
import argparse, json, os, re, subprocess
from datetime import datetime, timezone
from pathlib import Path


def run(*cmd: str) -> str:
    completed = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
    return completed.stdout.strip()


def first(pattern: str, text: str, fallback: str = "unknown") -> str:
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1).strip() if match else fallback


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--apksigner', required=True)
    args = ap.parse_args()
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '0'))
    java = run('java', '-version')
    gradle = run('gradle', '--version')
    rustc = run('rustc', '--version')
    cargo = run('cargo', '--version')
    cargo_ndk = run('cargo', 'ndk', '--version')
    sdkmanager = run('sdkmanager', '--version')
    apksigner = run(args.apksigner, 'version')
    payload = {
        'schemaVersion': '1.0',
        'generatedAt': datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace('+00:00', 'Z'),
        'sourceDateEpoch': epoch,
        'toolchain': {
            'java': first(r'version "([^"]+)"', java),
            'gradle': first(r'^Gradle\s+([^\s]+)', gradle),
            'rustc': first(r'^rustc\s+([^\s]+)', rustc),
            'cargo': first(r'^cargo\s+([^\s]+)', cargo),
            'cargoNdk': first(r'cargo-ndk\s+([^\s]+)', cargo_ndk, cargo_ndk.splitlines()[0] if cargo_ndk else 'unknown'),
            'sdkmanager': sdkmanager.splitlines()[0] if sdkmanager else 'unknown',
            'apksigner': apksigner.splitlines()[0] if apksigner else 'unknown',
            'ghidra': '12.1.3',
            'androidPlatform': '37',
            'androidBuildTools': '36.0.0',
            'androidNdk': '28.2.13676358',
        },
    }
    Path(args.out).write_text(json.dumps(payload, sort_keys=True, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
