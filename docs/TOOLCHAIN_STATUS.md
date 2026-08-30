# Toolchain status

## Requested local development baseline

- JDK: 17+ (runtime currently has OpenJDK 21)
- Android command-line tools: build 15859902
- Android SDK Platform: 37
- Android Build Tools: 36.0.0
- Android NDK: 28.2.13676358
- Gradle: 9.5.0
- Rust: stable via rustup
- Cargo: from the same stable Rust toolchain
- Android Rust targets: aarch64, armv7, x86_64, i686
- cargo-ndk: 4.1.2

## Current runtime result

OpenJDK 21 is present.

Android SDK/Gradle/Rust/Cargo could not be downloaded in this runtime because outbound DNS and outbound TCP are blocked. Direct connections by resolved IPv4 address were also rejected, so this is an environment egress restriction rather than a DNS-only problem. The runtime file-download bridge was also unable to retrieve a public test file.

`scripts/bootstrap_toolchain.sh` contains the reproducible installation procedure and verifies the Android command-line and Gradle archives with known SHA-256 values before extracting them. Rustup's current installer checksum is fetched from the official Rust static distribution endpoint and checked before execution.

Do not mark Android/Rust local builds as verified until all of the following succeed:

```bash
source "$HOME/.unirevlab-toolchain/env.sh"
sdkmanager --version
gradle --version
rustc --version
cargo --version
cargo ndk --version
cd native-core && cargo test --all-features
cd .. && gradle :app:testDebugUnitTest :app:assembleDebug
```

## v0.21 APK build attempt (2026-08-30)

After the full v0.21 host regression suite passed, local APK assembly was attempted. No preinstalled Android/Gradle toolchain was found. `scripts/bootstrap_toolchain.sh /mnt/data/step21/toolchain` failed at the Android command-line tools download with `curl: (6) Could not resolve host: dl.google.com`. No v0.21 APK was produced or substituted with an older artifact.
