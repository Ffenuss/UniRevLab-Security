# v0.16 — Structural native correlation and resources.arsc

Checkpoint: `0.16.0-dev-structural-native-resources` / static report schema `1.14` / Ghidra result schema `1.2`.

## Ghidra / JNI

The worker now records processor family, pointer size and endianness. Static `JNINativeMethod` records retain the table RVA. When a function that references the table also contains a unique JNI-class string and a RegisterNatives reference, the result records that contextual class identity and relevant FindClass/RegisterNatives callsites. Context is never inferred globally; it is propagated only across adjacent triples in the same recovered table.

## IL2CPP

For `il2cpp_codegen_register` callsites, the worker asks Ghidra's decompiler HighFunction/P-code representation for constant/address arguments. Resolved arguments are normalized to RVAs as CodeRegistration, MetadataRegistration and codegen-options candidates.

Given a recovered CodeRegistration RVA, a bounded architecture-aware scanner examines count/pointer pairs and samples pointed-to arrays. Arrays are reported only when the sample is predominantly executable memory. These are explicitly **structural pointer-table candidates**. The project does not claim that table order is a one-to-one mapping to metadata methods without a version/module-specific structural proof.

## Android resources

A new pure-Kotlin `ResourceTableResolver` parses bounded portions of `resources.arsc`:

- table/package chunks;
- global/type/key string pools;
- ordinary non-sparse type chunks;
- simple `ResTable_entry` + `Res_value` records;
- compiled 32-bit resource ID → package/type/key/value resolution;
- string/file values such as `res/xml/network_security_config.xml`.

Sparse, offset16 and complex/bag layouts are detected and left truncated rather than guessed. When binary AXML exposes a numeric Network Security Config reference, the resolved exact XML entry is preferred over broad `res/xml` enumeration.

## Compatibility

Android and coordinator importers accept Ghidra result 1.1 and 1.2. New worker output is 1.2. Static reports are schema 1.14.

## Verification

Host-side verification covers a synthetic `resources.arsc` fixture, v0.16 model/index/report smoke, previous v0.12-v0.15 regressions, static core, M2.4/M2.5, worker contracts/tests, coordinator persistence/ingestion tests, JSON schemas and secret preflight. Android framework/Compose compilation remains the connected Gradle/SDK gate.
