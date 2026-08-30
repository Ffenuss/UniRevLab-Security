# Local development

## Coordinator

From the repository root:

```bash
cd coordinator
python -m pip install -e '.[test]'
python -m pytest -q
```

The tests intentionally run with `coordinator` as the working directory so the local `app` package resolves exactly as it does in CI.

## Android

Required baseline:
- JDK 17;
- Android SDK platform 37;
- Android build tools 36.0.0;
- Android NDK 28.2.13676358;
- Gradle 9.5.0 until the standard wrapper is committed;
- Rust stable with Android targets;
- `cargo-ndk` 4.1.2.

The connected CI workflow builds the Rust `cdylib` for `arm64-v8a`, `armeabi-v7a`, `x86_64`, and `x86`, places the `.so` files under `app/src/main/jniLibs`, then runs:

```bash
gradle :app:testDebugUnitTest :app:assembleDebug
```

## Rust native core

```bash
cd native-core
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

For parser fuzzing in a trusted development environment with `cargo-fuzz` installed:

```bash
cd native-core
cargo fuzz run parse_axml -- -max_total_time=60
```

## Security preflight

```bash
python scripts/check_secrets.py .
```

Connected CI additionally runs cargo-deny and OSV Scanner.
