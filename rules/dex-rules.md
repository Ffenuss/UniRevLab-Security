# DEX static rules — M2 native developer checkpoint

The DEX analyzer is bounded and non-executing. It decodes DEX Modified UTF-8, validates top-level table ranges with checked arithmetic, indexes types/classes/methods/prototypes, and reads `class_data_item` method metadata sufficiently to recover `ACC_NATIVE` declarations. It never class-loads or executes target bytecode.

## DEX-HARDCODED-HTTP-URL

- Severity: Medium
- Confidence: High
- Review required: yes
- Mapping: MASVS-NETWORK / MASTG-TEST-0233
- Trigger: a DEX string contains an `http://` URL.
- Evidence policy: URL userinfo, query and fragment are removed before persistence/export.
- Remediation: migrate application endpoints to HTTPS and review Network Security Configuration / transport policy.

## DEX-POTENTIAL-HARDCODED-SECRET

- Severity: Medium
- Confidence: Medium
- Review required: yes
- Mapping: MASWE-0004 / MASTG-TECH-0019
- Trigger: bounded string inventory matches a high-signal secret-shaped pattern (private-key material, JWT-like token, Google API-key-like token, AWS access-key-id-like token).
- Evidence policy: raw candidate value is never written to the report. Only SHA-256 of the candidate, location, type, and a length-only redaction marker are retained.
- Remediation: verify manually; remove real credentials from the package and rotate exposed credentials when appropriate.

## ANALYSIS-DEX-PARTIAL

- Severity: Informational
- Confidence: Confirmed
- Trigger: a defensive size/count limit was reached or a DEX parse failed.
- Purpose: prevent partial coverage from being silently interpreted as a clean scan.

## Structural index emitted in schema 1.3

- strings declared/scanned;
- types declared/indexed;
- classes declared/indexed with descriptors/super descriptors/access flags;
- methods declared/indexed with declaring class, name and prototype;
- native method declarations recovered from `ACC_NATIVE` class-data metadata;
- bounded HTTP/HTTPS and redacted secret evidence.

This structural index feeds the JNI correlator. Code-item instruction/xref analysis is the next M2.1 milestone.

## Current parser limits

- 32 DEX files per APK;
- 96 MiB decompressed size per DEX;
- 384 MiB aggregate DEX decompression budget;
- 300,000 strings per DEX;
- 64 KiB retained bytes per individual string;
- 100,000 indexed types per DEX;
- 50,000 indexed classes per DEX;
- 150,000 indexed methods per DEX;
- bounded class/method/native-method, URL and secret-candidate report lists.
