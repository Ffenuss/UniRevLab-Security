# Synthetic IL2CPP regression fixtures

UniRevLab does not commit proprietary Unity player binaries or third-party application artifacts.

The host-side smoke and Android unit tests generate a minimal ZIP/APK-shaped fixture at runtime with:

- `assets/bin/Data/Managed/Metadata/global-metadata.dat` containing only a synthetic IL2CPP header and non-proprietary marker strings;
- `assets/bin/Data/globalgamemanagers` containing a synthetic Unity version marker;
- a placeholder `lib/arm64-v8a/libil2cpp.so` archive entry, while the ELF inventory is supplied by a benign in-memory model.

This corpus validates detector/parser behavior without executing target code or distributing Unity-owned binaries.
