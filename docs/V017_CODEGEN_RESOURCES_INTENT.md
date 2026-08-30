# v0.17 — Codegen modules, resources and intent/provider analysis

Checkpoint: `v0.17.0-dev-codegen-resources-intent`

## Native / IL2CPP

Ghidra result schema 1.3 adds bounded structural `Il2CppCodeGenModule` evidence. The worker records module identity, method-pointer count/table location and sampled executable function RVAs only after validating the surrounding CodeRegistration/module structures. Android maps a managed MethodDef token to a native RVA only when the assembly/module identity and token RID select a sampled slot; otherwise it keeps the evidence uncorrelated rather than inventing an address.

## Multi-ABI corpus

Project-owned, non-executed benign ELF fixtures are pinned for AArch64, ARM EABI5 and x86-64. The gate verifies file identity, ELF machine and expected exported fixture symbols.

## Compiled resources

The bounded pure-Kotlin resolver supports regular 32-bit entry offsets, `FLAG_OFFSET16`, `FLAG_SPARSE`, and complex/bag entry structure. Complex values are inventoried structurally; recursive semantic interpretation remains deferred.

## Intent and provider surface

Manifest analysis records deep-link ports, paths, prefixes, patterns and MIME types. ContentProvider evidence includes authorities, exported state, URI-grant state, provider read/write permissions and path-permission entries. Defensive rules flag exposed URI-grant surfaces and path-pattern review cases.

## Compatibility and build gate

Static report schema is 1.15. Android/coordinator import remains compatible with Ghidra 1.1/1.2 while the worker emits 1.3. A deterministic build-config preflight now verifies the Android/Gradle/NDK/version contract before connected CI performs the real framework compile.
