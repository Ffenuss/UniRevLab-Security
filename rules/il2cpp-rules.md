# Unity IL2CPP review rules

## IL2CPP-APPLICATION-SURFACE

Informational review signal when the artifact contains a high/medium-confidence Unity IL2CPP surface. IL2CPP is not considered a vulnerability; the signal ensures native code, client trust assumptions, metadata exposure, and resilience controls are not skipped during an authorized assessment.

## ANALYSIS-IL2CPP-METADATA-UNRECOGNIZED

Informational analysis-quality signal when a `global-metadata.dat` candidate is present but the standard metadata magic cannot be verified. The engine must not assume a version/layout in that state.

## Safety boundary

The on-device analyzer does not recover live process addresses, install hooks, generate patches, or execute `libil2cpp.so`. Later Ghidra/self-hosted workers may add richer static type/function correlation while preserving assessment scope and non-execution by default.
