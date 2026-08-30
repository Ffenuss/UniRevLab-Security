# M2.2 — DEX Flow + Runtime Profiles

Checkpoint: `0.6.0-m2-flow-runtimes-dev` / report schema `1.5`.

## DEX flow layer

- validates DEX code_item instruction boundaries before analysis;
- field xrefs for iget/iput/sget/sput families;
- normal control-flow basic blocks for goto, conditional branches, packed/sparse switch, return and throw;
- bounded intra-basic-block constant propagation for move, integer/long constants, strings and const-class;
- invoke observations attach only statically known/redacted arguments to call sites;
- unknown/unmodelled register mutations conservatively kill local state;
- no target bytecode is executed.

This enables higher-confidence defensive rules while avoiding claims of whole-program data-flow precision.

## IL2CPP

The IL2CPP metadata analyzer performs bounded structured reconstruction for metadata v27-v31 when table ranges validate. It can inventory type and method definitions, tokens and type membership. It does not recover live runtime addresses or patch the target. Native registration/address recovery remains a later Ghidra-backed phase.

## Runtime profiles

Passive framework fingerprinting routes artifacts to specialist analyzers for:

- Unity IL2CPP
- Unity Mono
- Unreal Engine
- Flutter
- React Native / Hermes
- Xamarin / .NET Android
- Cordova / WebView

Framework presence is inventory information, never itself a vulnerability.
