#!/usr/bin/env bash
set -euo pipefail

# Builds a self-contained 100% pure-C11 Debian/Ubuntu package for SealFrame (v0.6.0).

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="0.6.0"
ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
PKG_DIR="$ROOT/build/deb-stage"
OUT_DEB="$ROOT/build/sealframe_${VERSION}_${ARCH}.deb"

command -v dpkg-deb >/dev/null 2>&1 || { echo "ERROR: dpkg-deb not found (build on Debian/Ubuntu)"; exit 1; }

rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN" \
         "$PKG_DIR/usr/local/bin" \
         "$PKG_DIR/usr/local/lib/pkgconfig" \
         "$PKG_DIR/usr/local/include" \
         "$PKG_DIR/usr/local/share/doc/sealframe" \
         "$PKG_DIR/etc/systemd/system"

install -m 755 "$ROOT/bin/sf" "$PKG_DIR/usr/local/bin/sf"
install -m 755 "$ROOT/bin/sf-agent" "$PKG_DIR/usr/local/bin/sf-agent"
install -m 755 "$ROOT/bin/sf-cp" "$PKG_DIR/usr/local/bin/sf-cp"
install -m 755 "$ROOT/bin/sf-llama-bridge" "$PKG_DIR/usr/local/bin/sf-llama-bridge"

install -m 644 "$ROOT/build/libsealframe.a" "$PKG_DIR/usr/local/lib/libsealframe.a"
install -m 755 "$ROOT/build/libsealframe.so" "$PKG_DIR/usr/local/lib/libsealframe.so.${VERSION}"
ln -sf "libsealframe.so.${VERSION}" "$PKG_DIR/usr/local/lib/libsealframe.so.1"
ln -sf "libsealframe.so.1" "$PKG_DIR/usr/local/lib/libsealframe.so"

install -m 644 "$ROOT/build/libsealframe.pc" "$PKG_DIR/usr/local/lib/pkgconfig/libsealframe.pc"
install -m 644 "$ROOT/include/sealframe.h" "$PKG_DIR/usr/local/include/sealframe.h"
install -m 644 "$ROOT/include/sealframe_agent.h" "$PKG_DIR/usr/local/include/sealframe_agent.h"
install -m 644 "$ROOT/include/sealframe_chain.h" "$PKG_DIR/usr/local/include/sealframe_chain.h"
install -m 644 "$ROOT/include/sealframe_split.h" "$PKG_DIR/usr/local/include/sealframe_split.h"
install -m 644 "$ROOT/include/fp.h" "$PKG_DIR/usr/local/include/fp.h"
install -m 644 "$ROOT/include/fp_agent.h" "$PKG_DIR/usr/local/include/fp_agent.h"

install -m 644 "$ROOT/packaging/systemd/sealframe-agent.service" "$PKG_DIR/etc/systemd/system/sealframe-agent.service"
install -m 644 "$ROOT/packaging/systemd/sealframe-control-plane.service" "$PKG_DIR/etc/systemd/system/sealframe-control-plane.service"

install -m 644 "$ROOT/LICENSE" "$PKG_DIR/usr/local/share/doc/sealframe/LICENSE"
install -m 644 "$ROOT/LICENSE-COMMERCIAL.md" "$PKG_DIR/usr/local/share/doc/sealframe/LICENSE-COMMERCIAL.md"
install -m 644 "$ROOT/NOTICE" "$PKG_DIR/usr/local/share/doc/sealframe/NOTICE"
install -m 644 "$ROOT/TRADEMARKS.md" "$PKG_DIR/usr/local/share/doc/sealframe/TRADEMARKS.md"
install -m 644 "$ROOT/docs/"*.md "$PKG_DIR/usr/local/share/doc/sealframe/"
install -m 644 "$ROOT/build/sbom.cdx.json" "$PKG_DIR/usr/local/share/doc/sealframe/sbom.cdx.json"

cat >"$PKG_DIR/DEBIAN/control" <<EOF
Package: sealframe
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Maintainer: SealFrame Authors <tonyswagcard@gmail.com>
Depends: libc6, libsodium23 | libsodium26, libzstd1, libsqlite3-0
Description: SealFrame — Pure-C11 Verified Content, Edge OTA, Split-Model WAN Bridge & CRA Control Plane
 Compact hardened pure-C11 engine (sf CLI, sf-agent daemon, sf-cp Control Plane,
 sf-llama-bridge WAN split-model accelerator, libsealframe SDK) for Edge AI,
 distributed inference, industrial IoT, and robotics aligned with EU Cyber Resilience
 Act (Regulation 2024/2847). Zero Python, zero C++, zero OpenSSL. Includes vendored
 BLAKE3, 2-of-3 Root Multi-Sig, atomic File+SQLite rollback, FP-UDP1 + Adaptive FEC,
 SFT1 outlier-safe tensor streaming, multi-chain adapters, and CycloneDX 1.5 SBOM.
EOF

cat >"$PKG_DIR/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
ldconfig || true
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

dpkg-deb --build --root-owner-group "$PKG_DIR" "$OUT_DEB"
sha256sum "$OUT_DEB" > "${OUT_DEB}.sha256"
echo "Built Debian package: $OUT_DEB ($(stat -c%s "$OUT_DEB") bytes)"
cat "${OUT_DEB}.sha256"
