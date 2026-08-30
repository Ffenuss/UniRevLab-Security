# M2.4 Runtime Metadata + Supply Chain

Checkpoint: `0.8.0-m2-runtime-metadata-sbom-dev` / report schema `1.7`.

## Added

- Flutter snapshot/kernel artifact fingerprints (SHA-256, bounded reads).
- ECMA-335 metadata stream directory parsing for managed assemblies.
- ECMA-335 table row counts for Module, TypeRef, TypeDef, MethodDef, MemberRef, CustomAttribute, Assembly, AssemblyRef, and ManifestResource.
- Unreal PAK/IoStore bounded prefix fingerprints without executing or mounting target content.
- Passive supply-chain component fingerprinting from DEX package evidence, runtime evidence, IL2CPP/Unity evidence, and ELF `DT_NEEDED` dependencies.
- Report schema 1.7 with normalized `supplyChain` output.

## Safety properties

Target code is never loaded. All archive reads are bounded. Component versions are omitted unless supported by explicit evidence; framework presence alone is not treated as a vulnerability.

## Next

M2.5 will add deeper Hermes section/string metadata, ECMA-335 TypeDef/MethodDef name reconstruction, CycloneDX/SPDX exporters, version evidence extraction, and validated IL2CPP registration correlation before the headless Ghidra worker.
