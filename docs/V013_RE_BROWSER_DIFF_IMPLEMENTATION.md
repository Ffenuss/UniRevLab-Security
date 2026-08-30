# UniRevLab v0.13 RE Browser + Version Diff

## Implemented
- `ReBrowserIndex` derives navigation indexes from bounded DEX/native scanner output without reparsing target files.
- DEX hierarchy: package -> class -> method, with callers, callees, strings, fields, types and basic-block counts.
- Native index: library -> import/export/JNI symbol, including RVA/size when available.
- `AssessmentDiffEngine` compares two reports for the same application and records added/removed/changed security-relevant surface.
- Diff categories include permissions, dangerous permissions, exported components, deep links, signing schemes/certificates, findings, dependencies, DEX classes/methods, native libraries and exports.
- Android manifest inspection now records structured X.509 signing-certificate identity and signer-history metadata in addition to SHA-256 fingerprints.
- Dashboard has dedicated RE Browser and Version diff sections.

## Verification
Host-side regression validates RE hierarchy/xrefs and version-diff behavior. Existing v0.12 and static-core regressions remain compatible. Android Compose compilation is not claimed from the isolated local runtime; no APK was built for this checkpoint by request.
