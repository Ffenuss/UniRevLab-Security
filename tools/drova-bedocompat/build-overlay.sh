#!/usr/bin/env bash
set -euo pipefail
: "${ANDROID_HOME:?ANDROID_HOME is required}"
BUILD_TOOLS="${ANDROID_HOME}/build-tools/35.0.0"
PLATFORM_JAR="${ANDROID_HOME}/platforms/android-35/android.jar"
mkdir -p java-build/classes java-build/dex output
javac -source 8 -target 8 -encoding UTF-8 -classpath "$PLATFORM_JAR" \
  -d java-build/classes $(find java -name '*.java' -print)
"$BUILD_TOOLS/d8" --lib "$PLATFORM_JAR" --min-api 24 \
  --output java-build/dex java-build/classes/com/android/support/*.class
cp java-build/dex/classes.dex output/classes3.dex
sha256sum output/classes3.dex >> output/SHA256SUMS.txt
