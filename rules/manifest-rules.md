# Android manifest rule pack — M1

This rule pack is detection-oriented. It does not execute target code and does not generate exploit payloads. Findings are normalized into severity, confidence, evidence, remediation, and security-standard references.

| Rule ID | Trigger | Severity | Confidence | Review | Mapping |
|---|---|---:|---:|---|---|
| `ANDROID-MANIFEST-DEBUGGABLE` | Release artifact exposes the Android debuggable flag | High | Confirmed | No | OWASP MASTG-TEST-0226 / MASVS-RESILIENCE |
| `ANDROID-MANIFEST-CLEARTEXT` | Cleartext flag is enabled and no Network Security Configuration is confirmed | High | High/Low | Conditional | OWASP MASTG-TEST-0235 / MASVS-NETWORK |
| `ANDROID-MANIFEST-BACKUP` | Backup is enabled without confirmed backup/data-extraction rules | Medium/Low | Medium/Low | Yes | OWASP MASTG-TEST-0262 / MASVS-STORAGE |
| `ANDROID-EXPORTED-PROVIDER-UNPROTECTED` | Exported ContentProvider has no read/write/combined permission | Medium | High | Yes | OWASP MASTG-TEST-0355 / MASVS-PLATFORM |
| `ANDROID-EXPORTED-UNPROTECTED-REVIEW` | Exported activity/service/receiver has no manifest-level permission | Informational | Low | Yes | OWASP MASTG-TEST-0364/0365/0366 / MASVS-PLATFORM |
| `ANDROID-EXPORTED-WEAK-PERMISSION` | Exported component relies on app-declared normal/dangerous permission | Low | High | Yes | OWASP MASTG-BEST-0052 / MASVS-PLATFORM |
| `ANDROID-UNVERIFIED-APP-LINKS` | Browsable HTTP(S) VIEW filter omits `android:autoVerify=true` | Medium | Confirmed | No | OWASP MASTG-TEST-0393 / MASVS-PLATFORM |
| `ANDROID-CUSTOM-SCHEME-REVIEW` | Browsable VIEW filter handles a custom non-HTTP(S) scheme | Informational | High | Yes | OWASP MASTG-TEST-0394 / MASVS-PLATFORM |
| `ANDROID-DANGEROUS-PERMISSIONS` | Target requests Android permissions classified as dangerous by the assessor device | Low | High | Yes | OWASP MASTG-TEST-0254 / MASVS-PRIVACY |

## Interpretation

An exported activity/service/receiver, custom scheme, or dangerous permission is **not automatically a vulnerability**. These rules deliberately create review findings unless the unsafe configuration itself is deterministic. A future semantic analyzer will trace reachable code, authorization checks, intent/provider inputs, data flows, and sensitive API use before raising exploitability claims.

`networkSecurityConfig`, `fullBackupContent`, `dataExtractionRules`, and deep-link intent-filter metadata are derived from the bounded binary-AXML path rather than hidden Android platform APIs. If the native parser is unavailable, the corresponding state remains unknown/empty and the engine does not invent a safe result.
