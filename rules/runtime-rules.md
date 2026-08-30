# Runtime-specific analysis rules

These rules describe coverage and analyst-review behavior rather than treating a framework choice as a vulnerability.

## Flutter

- Detect AOT packaging (`libapp.so`) and inventory `flutter_assets`.
- Reuse native hardening, URL, secret, import, and ELF rules against `libapp.so` and plugins.
- Do not infer Dart source-level reachability from printable native strings alone.

## Hermes / React Native

- Validate HBC magic/header before reporting Hermes bytecode metadata.
- Treat bytecode version as a decoder-selection key; unknown versions remain inventory-only.
- Plain JS bundles and Hermes HBC are distinct artifact types.

## Unity Mono

- Require valid PE/CLI metadata before calling a `.dll` a managed assembly.
- Managed assembly presence is informational; security impact comes from code/data-flow findings.

## Unity IL2CPP

- Metadata parsing and native registration correlation must remain version-aware.
- Registration symbols are candidate evidence until validated by native analysis.
- Never manufacture method offsets by fixed constants when the native registration layout is unknown.

## Unreal Engine

- Inventory PAK and IoStore containers and native engine libraries.
- Container presence is not a vulnerability.
- Version/encryption-aware container parsing must fail closed on unsupported layouts.
