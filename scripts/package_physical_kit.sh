#!/usr/bin/env bash
set -euo pipefail

# Packages a clean, self-contained source bundle of SealFrame (fp)
# for physical two-host testing (Linux x86_64 <-> ARM64 / Raspberry Pi / Jetson / VPS).

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/build/physical-kit"
STAGE="$OUT_DIR/sealframe-kit"
ARCHIVE="$OUT_DIR/sealframe-kit.tar.gz"

rm -rf "$OUT_DIR"
mkdir -p "$STAGE"

cp -r "$ROOT/include" "$ROOT/src" "$ROOT/tests" "$ROOT/bench" \
      "$ROOT/bindings" "$ROOT/examples" "$ROOT/docs" "$ROOT/control-plane" \
      "$ROOT/packaging" "$ROOT/third_party" \
      "$ROOT/Makefile" "$ROOT/SPEC.md" "$ROOT/README.md" \
      "$ROOT/ROADMAP.md" "$ROOT/ROADMAP_WORLD.md" \
      "$ROOT/PHYSICAL_TEST_GUIDE.md" "$STAGE/"
mkdir -p "$STAGE/scripts"
cp "$ROOT/scripts/generate_sbom.sh" "$ROOT/scripts/build_deb.sh" "$ROOT/scripts/demo_cto.sh" "$STAGE/scripts/"

(cd "$STAGE" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS)
tar -C "$OUT_DIR" -czf "$ARCHIVE" sealframe-kit
(cd "$OUT_DIR" && sha256sum "$(basename "$ARCHIVE")" > SHA256SUMS)

echo "Packaged physical kit: $ARCHIVE ($(stat -c%s "$ARCHIVE") bytes)"
cat "$OUT_DIR/SHA256SUMS"
