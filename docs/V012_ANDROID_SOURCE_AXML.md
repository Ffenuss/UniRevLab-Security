# v0.12-dev — Android source selection, installed packages, AXML fallback and mobile triage UI

## Source selection

The Android client now supports two first-class assessment sources:

1. **File** — APK/AAB/APKS/XAPK through Storage Access Framework.
2. **Installed application** — package inventory through `PackageManager`.

Installed applications are shown in a searchable list with label, package name, version, user/system classification, enabled state, installer and split-APK count. The selected package is never launched.

The lab/security build declares `android.permission.QUERY_ALL_PACKAGES` because complete package inventory is a core security-assessment function. Store publication must include the corresponding package-visibility policy declaration/review.

## Installed split APK analysis

An installed App Bundle deployment can contain `base.apk` plus multiple split APKs. UniRevLab uses `publicSourceDir` / `splitPublicSourceDirs` where available and includes every readable APK in:

- aggregate artifact size and deterministic SHA-256 binding;
- ZIP/path inventory;
- DEX string/class/method/code/xref analysis;
- native ELF/JNI analysis;
- runtime detection;
- IL2CPP metadata/native correlation inputs;
- supply-chain component inventory.

DEX/native entry names are prefixed with their source APK (`base.apk!/…`, `split:<name>!/…`) so equal names such as `classes.dex` do not become ambiguous in reports.

## Pure-Kotlin binary AXML fallback

`KotlinAxmlManifestParser` parses Android binary XML without loading target code. It includes bounded:

- chunk parsing;
- UTF-8/UTF-16 string pools;
- start/end element parsing;
- typed values;
- application security attributes;
- VIEW/BROWSABLE deep-link filters;
- schemes/hosts and `autoVerify`.

The optional Rust/JNI parser remains supported. The Android client first consumes native parser output when available and falls back to pure Kotlin when it is not.

## APK signing schemes

`ApkSigningSchemeScanner` passively inventories:

- JAR/v1 signature files;
- APK Signature Scheme v2 block;
- v3 block;
- v3.1 block;
- signing-block IDs for reproducible evidence.

The Manifest rule engine emits review findings for v1-only releases and for certificate-bearing APKs whose scheme could not be classified by the passive parser.

## Report schema 1.10

Artifact provenance now records:

- `sourceKind` (`FILE` / `INSTALLED_APP`);
- `sourcePackageName`;
- `sourceInstallerPackageName`;
- `splitApkCount`.

No private `/data/app/...` filesystem path is exported into the report.

## Mobile results navigation

The dashboard now separates results into:

- Overview;
- Manifest;
- DEX;
- Native;
- Runtime;
- SBOM;
- Findings.

Manifest triage shows dangerous permissions, exported components and deep links. Native triage adds search across libraries, imports, exports, JNI bridges and sanitized HTTP URL evidence.

## Verification in this checkpoint

Host-side verified:

- pure Kotlin AXML synthetic binary-manifest smoke;
- existing static-core regression;
- M2.4 runtime metadata/supply-chain regression;
- M2.5 Hermes/ECMA-335/SBOM regression;
- report JSON Schema 1.9;
- Ghidra schemas;
- repository secret preflight.

Android UI/PackageManager compilation is deferred to the next connected Android CI gate; no APK is produced for this checkpoint by request.

## Network Security Config inspection

v0.12 also parses compiled `res/xml/*.xml` resources with the same bounded pure-Kotlin AXML reader. When the manifest references a network security configuration the analyzer identifies the actual `network-security-config` document and records:

- base and per-domain `cleartextTrafficPermitted`;
- domain names and `includeSubdomains`;
- trust-anchor sources such as `system`, `user`, or packaged `@raw` certificates;
- whether trust anchors are confined to `debug-overrides`;
- `overridePins` evidence;
- presence of `pin-set` and debug overrides.

This produces confirmed/review findings for production cleartext allowances and production trust of user-installed CAs. Parsing is bounded by entry count, per-entry bytes, total bytes, domain configs, and trust-anchor counts.

## Installed application provenance

Installed-app assessments keep source provenance in the report (`INSTALLED_APP`, package, installer, split count). Analysis reads the installed package files as static artifacts and does not launch the selected target. The full set uses the base APK plus all readable split APKs; split-prefixed evidence prevents same-named `classes.dex` entries from being conflated.
