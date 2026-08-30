# M2.5 — Deep runtime metadata and SBOM

Checkpoint: `0.9.0-m2-deep-metadata-sbom-dev` / static report schema `1.8`.

## Scope

M2.5 deepens passive, non-executing analysis for Hermes and ECMA-335 and turns supply-chain evidence into deterministic CycloneDX/SPDX exports. Target APK, DEX, HBC, PE/CLI, ELF, IL2CPP, Flutter, and Unreal artifacts remain hostile read-only inputs and are never executed by the local analyzer.

## Hermes HBC

The analyzer now validates and records the stable fixed prefix of the Hermes bytecode file header and reads a bounded number of `SmallFuncHeader` entries. It records file/header counts, source hash, section-size indicators, structured-prefix size, and bounded function metadata such as bytecode offset/size, parameter count, frame size, flags, and overflowed large-header offsets.

Unsupported or structurally inconsistent files fail closed or remain partial. This checkpoint does not claim full Hermes disassembly or runtime reachability.

## ECMA-335 reconstruction

For PE/CLI managed assemblies, the analyzer now follows the CLI metadata directory to the `BSJB` metadata root, parses the stream directory, and reconstructs selected tables from `#~`/`#-` using the appropriate heap/table/coded-index widths.

Bounded reconstruction currently covers:

- `TypeRef`;
- `TypeDef`;
- `MethodDef`;
- `MemberRef`;
- `Assembly`;
- `AssemblyRef`.

Names are resolved through `#Strings`; assembly versions are read from ECMA-335 version fields. Method definitions are associated with type definitions by validated `MethodList` ranges. Blob indices are retained as structural evidence rather than interpreted as executable IL.

## IL2CPP registration evidence

ELF dynamic-symbol records now retain symbol value/RVA evidence and symbol size where available. IL2CPP registration candidates therefore record whether a candidate is a defined symbol and, when present, its static virtual address and size. No code-registration address is guessed when a symbol is absent.

Exact metadata-method to native-function mapping remains a later worker-assisted stage.

## Supply-chain evidence

The supply-chain scanner now accepts the original APK as a bounded read-only source. It can recover exact Maven coordinates from packaged `META-INF/maven/**/pom.properties` and only reports a version when supported by explicit evidence.

Additional exact-version evidence can come from managed `AssemblyRef` records or explicit runtime version markers. DEX package markers remain useful component evidence but do not invent a version.

## SBOM exports

Two deterministic exports are available from the Android dashboard:

- CycloneDX 1.6 JSON;
- SPDX 3.0.1 JSON-LD.

Both are derived solely from evidence already present in the immutable static report. The application artifact SHA-256 anchors the root component/document identity. Unknown versions stay unknown.

## Privacy and safety properties

- no target artifact is executed;
- no arbitrary script from the target is evaluated;
- malformed sizes/counts are bounded and overflow checked;
- secret-like evidence remains redacted/hash-only;
- package/version attribution carries confidence/evidence;
- assembly identity is not falsely converted into a NuGet purl;
- unsupported metadata layouts are partial/unknown rather than guessed.

## Regression coverage

Host-side M2.5 fixtures verify:

- Hermes fixed header and function headers;
- ECMA-335 `TypeRef`, `TypeDef`, `MethodDef`, `MemberRef`, `Assembly`, and `AssemblyRef` reconstruction;
- exact Maven version recovery (`OkHttp 4.12.0`) from synthetic `pom.properties`;
- defined IL2CPP registration-symbol address evidence;
- CycloneDX and SPDX JSON generation and structural parseability.
