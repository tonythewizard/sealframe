#!/usr/bin/env bash
set -euo pipefail

# Generates a CycloneDX 1.5 JSON Software Bill of Materials (SBOM) for
# SealFrame (sf / sf-agent / sf-cp / libsealframe) aligned with EU CRA Annex I/VII.
# 100% pure POSIX/Bash — ZERO Python dependency.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/sbom.cdx.json"
mkdir -p "$ROOT/build"

VERSION="0.5.1"
GIT_REV="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
CC_VER="$("${CC:-gcc}" --version 2>/dev/null | head -n1 | tr '"' "'" || echo unknown)"
ARCH="$(uname -m)"
OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
NOW_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
UUID_VAL="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || printf '00000000-0000-4000-8000-%012x' "$(date +%s)")"
SYS_B3="${SF_SYSTEM_BLAKE3:-${FP_SYSTEM_BLAKE3:-0}}"

sha_of() {
  if [ -f "$1" ]; then sha256sum "$1" | awk '{print $1}'; else echo "not-built"; fi
}

SF_SHA="$(sha_of "$ROOT/bin/sf")"
AGENT_SHA="$(sha_of "$ROOT/bin/sf-agent")"
CP_SHA="$(sha_of "$ROOT/bin/sf-cp")"
SO_SHA="$(sha_of "$ROOT/build/libsealframe.so")"
A_SHA="$(sha_of "$ROOT/build/libsealframe.a")"

if [ "$SYS_B3" = "1" ]; then
  B3_VER="$(pkg-config --modversion libblake3 2>/dev/null || echo unknown)"
  B3_LINK="dynamic-system-library"
else
  B3_VER="1.8.2"
  B3_LINK="vendored-c-source"
fi
SODIUM_VER="$(pkg-config --modversion libsodium 2>/dev/null || echo unknown)"
ZSTD_VER="$(pkg-config --modversion libzstd 2>/dev/null || echo unknown)"
SQLITE_VER="$(pkg-config --modversion sqlite3 2>/dev/null || echo unknown)"

MAIN_REF="pkg:generic/sealframe@${VERSION}?arch=${ARCH}&os=${OS_NAME}"

cat >"$OUT" <<EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:${UUID_VAL}",
  "version": 1,
  "metadata": {
    "timestamp": "${NOW_UTC}",
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "sealframe-sbom-generator",
          "version": "${VERSION}"
        }
      ]
    },
    "component": {
      "type": "application",
      "bom-ref": "${MAIN_REF}",
      "name": "sealframe",
      "version": "${VERSION}",
      "description": "SealFrame (FP01) — Pure-C11 Verified Content, Delta, Swarm, Bundle, Tensor & Control Plane",
      "purl": "${MAIN_REF}",
      "licenses": [
        {
          "license": {
            "name": "Proprietary Commercial B2B"
          }
        }
      ],
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "${SF_SHA}"
        }
      ],
      "properties": [
        { "name": "sealframe:git-commit", "value": "${GIT_REV}" },
        { "name": "sealframe:compiler", "value": "${CC_VER}" },
        { "name": "sealframe:target-arch", "value": "${ARCH}" },
        { "name": "sealframe:hardening", "value": "PIE,Full-RELRO,NX,Stack-Protector-Strong,FORTIFY_SOURCE=3" },
        { "name": "sealframe:artifact-sf-agent-sha256", "value": "${AGENT_SHA}" },
        { "name": "sealframe:artifact-sf-cp-sha256", "value": "${CP_SHA}" },
        { "name": "sealframe:artifact-libsealframe-so-sha256", "value": "${SO_SHA}" },
        { "name": "sealframe:artifact-libsealframe-a-sha256", "value": "${A_SHA}" }
      ]
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:generic/BLAKE3@${B3_VER}",
      "name": "BLAKE3",
      "version": "${B3_VER}",
      "description": "Cryptographic Merkle & Content DNA hashing",
      "purl": "pkg:generic/BLAKE3@${B3_VER}",
      "licenses": [{ "expression": "CC0-1.0 OR Apache-2.0" }],
      "properties": [
        { "name": "sealframe:pkg-config-name", "value": "libblake3" },
        { "name": "sealframe:link-type", "value": "${B3_LINK}" }
      ]
    },
    {
      "type": "library",
      "bom-ref": "pkg:generic/libsodium@${SODIUM_VER}",
      "name": "libsodium",
      "version": "${SODIUM_VER}",
      "description": "Ed25519 signatures, X25519 key exchange, XChaCha20-Poly1305 AEAD, SHA-256",
      "purl": "pkg:generic/libsodium@${SODIUM_VER}",
      "licenses": [{ "expression": "ISC" }],
      "properties": [
        { "name": "sealframe:pkg-config-name", "value": "libsodium" },
        { "name": "sealframe:link-type", "value": "dynamic-system-library" }
      ]
    },
    {
      "type": "library",
      "bom-ref": "pkg:generic/zstd@${ZSTD_VER}",
      "name": "zstd",
      "version": "${ZSTD_VER}",
      "description": "ZSTD compression and reference-based DELTA morphing",
      "purl": "pkg:generic/zstd@${ZSTD_VER}",
      "licenses": [{ "expression": "BSD-3-Clause" }],
      "properties": [
        { "name": "sealframe:pkg-config-name", "value": "libzstd" },
        { "name": "sealframe:link-type", "value": "dynamic-system-library" }
      ]
    },
    {
      "type": "library",
      "bom-ref": "pkg:generic/sqlite@${SQLITE_VER}",
      "name": "sqlite",
      "version": "${SQLITE_VER}",
      "description": "SQLite3 session extension for logical database delta & Control Plane state",
      "purl": "pkg:generic/sqlite@${SQLITE_VER}",
      "licenses": [{ "expression": "blessing" }],
      "properties": [
        { "name": "sealframe:pkg-config-name", "value": "sqlite3" },
        { "name": "sealframe:link-type", "value": "dynamic-system-library" }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "${MAIN_REF}",
      "dependsOn": [
        "pkg:generic/BLAKE3@${B3_VER}",
        "pkg:generic/libsodium@${SODIUM_VER}",
        "pkg:generic/zstd@${ZSTD_VER}",
        "pkg:generic/sqlite@${SQLITE_VER}"
      ]
    }
  ]
}
EOF

echo "Generated CycloneDX 1.5 SBOM: $OUT (4 runtime dependencies)"
