# Threat model (initial)

Primary threats:

- malicious APK crafted to exploit archive/DEX/ELF parsers;
- zip bombs and archive path traversal;
- malicious target code escaping dynamic-analysis isolation;
- unauthorized widening of assessment scope;
- sensitive pre-release APK leakage;
- compromised analysis plugins/workers;
- poisoned dependency/CVE feeds;
- forged reports or mismatched artifact hashes.

Initial controls:

- local-first import and SHA-256 identity;
- bounded archive enumeration; no archive extraction in v0.1;
- worker isolation and ephemeral dynamic labs;
- artifact hash in every assessment/report;
- least privilege and no `QUERY_ALL_PACKAGES` in the public Android client;
- signed release artifacts and SBOM planned for release pipeline;
- fuzzing gates before native parsers are enabled.
