#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "app/src/main/java/org/unirevlab/security/analysis/AutoModEngine.kt"


def replace_any(text: str, old: str, new: str) -> str:
    return text.replace(old, new)


def main() -> None:
    text = TARGET.read_text(encoding="utf-8")
    original = text

    # Behavior-changing AutoMod decisions must be backed by complete identifier tokens from the
    # method name. Substrings such as `pro` in `professional`, `score` in `scoreboard`, or `config`
    # inside an unrelated type/evidence string are not sufficient evidence for mutation.
    text = replace_any(
        text,
        "marker in methodTokens || methodCompact.contains(marker)",
        "marker in methodTokens",
    )
    text = replace_any(
        text,
        "LOCAL_INT_VALUES.entries.firstOrNull { (term, _) -> termInMethod(term, methodTokens, methodCompact) }",
        "LOCAL_INT_VALUES.entries.firstOrNull { (term, _) -> term in methodTokens }",
    )
    text = replace_any(
        text,
        '"integrity", "tamper", "signature", "checksum", "attestation", "attest", "root", "rooted",',
        '"integrity", "tamper", "tampered", "signature", "checksum", "attestation", "attest", "root", "rooted",',
    )

    if text == original:
        print("v0.26.3 AutoMod token precision already present")
        return

    TARGET.write_text(text, encoding="utf-8")
    print("v0.26.3 AutoMod token precision applied")


if __name__ == "__main__":
    main()
