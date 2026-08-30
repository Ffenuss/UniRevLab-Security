# Parser corpus

All files in this directory are inert, intentionally malformed parser inputs used to verify that
UniRevLab treats APK/AXML data as hostile input without executing it.

- `apk/path-traversal.zip`: contains a `../` central-directory entry to exercise path validation.
- `apk/minimal-invalid.apk`: APK-shaped ZIP with deliberately invalid/minimal manifest and DEX bytes.
- `native-core/fuzz/corpus/parse_axml/*`: tiny malformed AXML seeds for libFuzzer.

Do not add copyrighted third-party APKs or live malware to the repository.
