# Rules

UniRevLab rule packs are versioned, defensive detection logic. Findings map evidence to severity, confidence, remediation and security-standard references. Exploit-payload generation is outside the official project scope.

Implemented:
- [`manifest-rules.md`](manifest-rules.md) — Android manifest/package metadata rules;
- [`dex-rules.md`](dex-rules.md) — bounded DEX string/index rules;
- [`native-rules.md`](native-rules.md) — ELF/JNI inventory and hardening rules.

Future rule packs will add code-item/data-flow, crypto, WebView, IPC, dependency/supply-chain, privacy and marketplace-policy analysis. Semantic rules should prefer evidence-backed reachability/data-flow analysis over simple string matching whenever feasible.
