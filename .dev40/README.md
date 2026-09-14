# ModKit 0.9.0-dev40 transport

Continuation of the dev39 precision pass. dev40 keeps the fail-closed builder and passive security policy, while adding the remaining Simple Mode orchestration layer: explicit confirmation stages, gameplay-domain filters, target SHA-256 cache/reuse, structured stage progress, cancellation checkpoints, and locator handoff to the professional workspaces.

The cache is deliberately conservative: it reuses expensive derived reports only when the complete APK/split target digest matches. Any changed split takes the fresh-analysis path.
