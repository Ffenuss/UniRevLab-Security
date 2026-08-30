# Android Static Worker

Isolated worker boundary for AXML, DEX, resources, native ELF/JNI, dependency and future SBOM analysis. It accepts immutable artifacts by hash and emits normalized, versioned findings.

Current on-device/static-core capabilities that can be mirrored in the worker:

- binary AndroidManifest / AXML metadata;
- bounded DEX strings, types, classes, methods, prototypes and `ACC_NATIVE` declarations;
- bounded ELF32/ELF64 header/section/program-header parsing;
- Build-ID, `DT_NEEDED`, `.dynsym` imports/exports and JNI symbols;
- native hardening metadata;
- DEX ↔ JNI static-symbol correlation;
- deterministic JSON schema v1.4.

The worker and local analyzer treat APK/DEX/ELF inputs as hostile data. They do not execute the analyzed application or load target native libraries.
