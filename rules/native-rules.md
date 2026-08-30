# Native ELF / JNI rules — schema 1.3

All target `.so` files are treated as untrusted data. The local analyzer never calls `System.loadLibrary`, `dlopen`, JNI entry points, constructors, or target code.

## Inventory

For each `lib/<abi>/*.so` the bounded ELF parser records:

- ELF32/ELF64 class and machine architecture;
- ELF file type and Build-ID when present;
- `DT_NEEDED` dependencies;
- bounded `.dynsym` imports and exports;
- `JNI_OnLoad` and statically named `Java_*` JNI exports/imports;
- printable HTTP/HTTPS endpoint strings with query/fragment removal;
- GNU stack executable flag;
- GNU RELRO segment;
- immediate binding (`DT_BIND_NOW`, `DF_BIND_NOW`, or `DF_1_NOW`);
- stack-canary runtime import evidence;
- presence/absence of a full symbol table as a stripped-build indicator;
- a bounded `RegisterNatives` string indicator;
- high-signal potential-secret candidates stored only as type + SHA-256 + length-only redaction;
- review inventory for process-execution and dynamic-library-loading imports.

The current milestone does **not** execute native code, emulate instructions, or claim reachability from string/symbol presence alone.

## JNI correlation

DEX methods carrying `ACC_NATIVE` are correlated with classic JNI exports using JNI name mangling. Outcomes:

- `STATIC_SYMBOL_MATCH` — a matching `Java_<class>_<method>` export is present;
- `DYNAMIC_REGISTRATION_POSSIBLE` — no static export matched, but `JNI_OnLoad` / registration evidence suggests runtime registration may occur;
- `UNRESOLVED` — no static or bounded dynamic-registration evidence matched.

Dynamic registration still requires deeper disassembly/data-flow analysis in a future isolated worker for exact method-table recovery.

## Findings

### `NATIVE-EXECUTABLE-STACK`
High-confidence hardening finding when `PT_GNU_STACK` has `PF_X`.

### `NATIVE-RELRO-MISSING`
Review finding when `PT_GNU_RELRO` is absent.

### `NATIVE-BIND-NOW-MISSING`
Review finding when RELRO exists but immediate binding was not observed (partial vs. full RELRO signal).

### `NATIVE-STACK-CANARY-REVIEW`
Informational/low-confidence review signal when `__stack_chk_fail` / `__stack_chk_guard` are absent from dynamic imports. Absence is not proof that every function lacks stack protection.

### `NATIVE-NONSTANDARD-LOCATION`
Low-severity review signal when a `.so` is packaged outside conventional `lib/<abi>/`, prompting review of extraction/dynamic-loading and integrity checks.

### `NATIVE-POTENTIAL-HARDCODED-SECRET`
Pattern-based review for token/private-key-like printable native data. Raw values are never persisted by default.

### `NATIVE-PROCESS-EXECUTION-API-REVIEW`
Low-severity manual-review signal for `system`, `popen`, `exec*`, or `posix_spawn*` imports. Import presence alone is not considered a vulnerability.

### `NATIVE-DYNAMIC-LOADING-API-REVIEW`
Informational review signal for `dlopen`, `android_dlopen_ext`, or `dlsym` imports, especially when correlated with non-standard packaged `.so` files.

### `NATIVE-HARDCODED-HTTP-URL`
Potential cleartext endpoint evidence from printable native data. Requires code-level/runtime reachability confirmation.

### `NATIVE-JNI-ATTACK-SURFACE`
Informational inventory that tells the assessor which native boundary requires memory-safety and input-validation review.

### `ANALYSIS-NATIVE-PARTIAL`
Explicitly reports parser errors or defensive-limit truncation so partial coverage never appears as a clean result.
