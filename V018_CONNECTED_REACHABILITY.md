# v0.18 connected build + manifest/DEX reachability

Checkpoint: `0.18.0-dev-connected-reachability` / static report schema `1.16`.

## Implemented

- bounded manifest component -> DEX lifecycle-entry -> static invoke-graph reachability evidence;
- explicit externally-addressable component flag from exported/deep-link/provider evidence;
- resource-reference chains with bounded depth, unresolved-target and cycle detection;
- Network Security Config resource resolution now follows compiled `TYPE_REFERENCE` chains before selecting the terminal XML entry;
- benign structural IL2CPP codegen fixtures for AArch64, ARM EABI5 and x86-64 with pinned SHA-256;
- connected Ghidra CI matrix for all three ABIs, asserting `Assembly-CSharp.dll` codegen module and method-pointer slot -> function RVA evidence;
- Android connected gate hardened to run unit tests, lint, debug assembly and release assembly after JNI Rust build;
- Android build-config preflight now pins v0.18/versionCode 14 and verifies the full connected command contract;
- report provenance fixed so `LocalArtifactInspector.ENGINE_VERSION` matches the current checkpoint.

## Verification boundary

Host-side Kotlin smoke, schemas, worker/coordinator tests, multi-ABI ELF structure and historical regressions pass in the current environment.

The current execution container cannot resolve external download hosts, so Android SDK/Gradle and Ghidra cannot be bootstrapped here. Therefore the actual connected Android Gradle execution and headless Ghidra matrix are **configured but not claimed as executed PASS** in this checkpoint. Those jobs are deterministic CI gates and must run on a connected runner before an APK/release checkpoint.
