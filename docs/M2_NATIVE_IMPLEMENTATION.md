# M2 Native implementation checkpoint

Version: `0.4.0-m2-native-dev`  
Report schema: `1.3`

## Implemented

### DEX index

The previous DEX string scanner is now a bounded structural indexer. It validates and indexes:

- Modified UTF-8 string data;
- `type_ids`;
- `proto_ids`;
- `method_ids`;
- `class_defs`;
- `class_data_item` method lists;
- methods marked with `ACC_NATIVE`.

The report contains bounded class/method inventories and native method declarations. No DEX class is loaded or executed.

### ELF analysis

For APK `lib/*/*.so` entries the local analyzer now performs bounded static parsing of ELF32/ELF64 little-endian files. It inspects headers, sections, program headers, dynamic symbols, dynamic dependencies, notes/Build-ID and printable strings.

Native libraries are extracted one at a time into app-private temporary storage under strict per-library and aggregate decompression limits and deleted after parsing.

### JNI bridge

DEX `native` declarations are matched against classic static JNI symbol names. Libraries with `JNI_OnLoad` / `RegisterNatives` indicators are marked as candidates for dynamic registration when no static export exists.

### Native hardening

Current checks cover:

- executable stack;
- GNU RELRO;
- immediate binding / full-RELRO signal;
- stack-canary runtime import evidence;
- stripped-build indicator;
- non-standard `.so` packaging locations;
- hardcoded cleartext HTTP strings;
- hash/redaction-only native secret candidates;
- process-execution and dynamic-loading API review signals;
- JNI attack-surface inventory.

## Intentionally deferred

The local Android app does not yet:

- disassemble native instructions;
- recover exact `JNINativeMethod[]` tables from dynamically registered code;
- build native CFG/xrefs;
- emulate or execute `.so` files;
- perform exploit generation;
- attach to other processes.

Those capabilities that are useful for defensive review will be introduced as bounded static analysis or inside isolated self-hosted workers.

## Test corpus

`test-corpus/native/jni_fixture.c` is UniRevLab-owned benign source used to generate:

- `libjni_hardened.so` — RELRO + BIND_NOW + stack protector + non-executable stack;
- `libjni_weak.so` — executable stack and no RELRO, solely for detector regression tests.

The fixtures export `JNI_OnLoad` and `Java_com_example_NativeBridge_nativeCheck` and contain a non-routable `.invalid` HTTP URL. They contain no malicious behavior.
