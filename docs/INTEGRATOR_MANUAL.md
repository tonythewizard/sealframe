# SealFrame (`v0.5.0`) — B2B OEM Integrator Security & Deployment Manual

> **Compliance Reference**: EU Cyber Resilience Act (Regulation 2024/2847), Annex II (Information and Instructions to the User)
> **Audience**: Industrial IoT, Robotics, Edge AI, and Embedded Linux System Integrators

---

## 1. Installation (Debian / Ubuntu `.deb` or Source SDK)

### 1.1 Installing the Commercial `.deb` Package
```bash
sha256sum -c sealframe_0.5.1_amd64.deb.sha256
sudo dpkg -i sealframe_0.5.1_amd64.deb
sudo apt-get install -f   # resolves libsodium, libzstd1, libsqlite3-0 if needed
```
Installed artifacts:
- `/usr/local/bin/sf` — Operator & signing CLI (PIE + Full RELRO + NX + Stack Canary + `_FORTIFY_SOURCE=3`)
- `/usr/local/bin/sf-agent` — Edge reconciliation daemon (~123 KB)
- `/usr/local/lib/libsealframe.so`, `libsealframe.a`, `include/{fp.h,fp_agent.h}` — C11 SDK
- `/usr/local/bin/sf-cp` — On-premises Control Plane
- `/etc/systemd/system/{sealframe-agent.service,sealframe-control-plane.service}` — Hardened `systemd` units
- `/usr/local/share/doc/sealframe/` — CRA Technical File, SBOM (`sbom.cdx.json`), CVD Policy

### 1.2 Building from Licensed Source (Zero `libblake3-dev` Friction)
```bash
# Auto-detects system libblake3 or seamlessly uses vendored official BLAKE3 1.8.2 C source:
make all test security-check sbom
# Force fully self-contained vendored BLAKE3 (recommended for portable .deb / Yocto builds):
make clean && make USE_SYSTEM_BLAKE3=0 all test security-check sbom deb
```

---

## 2. Offline 2-of-3 Root Key Ceremony (Mandatory for Production)

1. Generate **3 Root keypairs** (`r1`, `r2`, `r3`) on an **air-gapped machine** (or HSM/YubiKey). Store private keys (`r1.sk`, `r2.sk`, `r3.sk`) in physically separated safes under distinct custodians.
2. Generate **1 online Release keypair** (`rel.sk`, `rel.pk`) for CI/CD release signing.
3. Sign the initial `root.fpr` with at least 2 Root keys (`--threshold 2`):
   ```bash
   fp root-init --repo <REPO_HEX64> --threshold 2 \
     --root-pub r1.pk --root-pub r2.pk --root-pub r3.pk \
     --release-pub rel.pk \
     --sign r1.sk --sign r3.sk \
     --out root.fpr
   ```
4. Embed `root.fpr` into the edge device image at `/var/lib/sealframe-agent/pinned_root.fpr` (read-only bootstrap).
5. **Key Compromise Procedure**: If `rel.sk` is ever compromised, generate `rel_v2`, sign `root_v2.fpr` (`--version 2 --revoke-pub rel.pk --release-pub rel_v2.pk`) with 2 offline Root keys, and publish to `/repo/root.fpr`. Every edge device verifies the dual-quorum rotation automatically and permanently rejects the compromised key.

---

## 3. Deploying Hardened `systemd` Services

### 3.1 Edge Device (`/etc/sealframe/agent.env`)
```ini
FP_REPO_URL=http://<control-plane-ip>:8080
FP_CHANNEL=stable
FP_DEVICE_ID=robot-line4-01
FP_STORE_DIR=/var/lib/sealframe-agent/store
FP_TARGET_DIR=/opt/fp-app
FP_ROOT_FPR=/var/lib/sealframe-agent/pinned_root.fpr
FP_DEVICE_KEY=/var/lib/sealframe-agent/device.sk
FP_HEALTH_CMD="systemctl is-active my-edge-app && curl -sf http://127.0.0.1:9000/health"
FP_INTERVAL_SEC=30
```
Enable the hardened daemon (`NoNewPrivileges=yes`, `ProtectSystem=strict`, `MemoryMax=32M`):
```bash
sudo systemctl enable --now sealframe-agent.service
sudo systemctl status sealframe-agent.service
```

### 3.2 Hybrid LAN Peer (Save WAN Bandwidth in Factories / Fleets)
To pull multi-GB AI models from an encrypted local LAN gateway (`fp serve`) with automatic HTTP/S3 Range fallback:
```bash
sf-agent --repo http://cp.corp:8080 --lan-peer 10.0.0.5:7777 --lan-peer-pub /etc/sealframe/lan_gw.pk \
         --key /var/lib/sealframe-agent/device.sk ...
```

### 3.3 Control Plane with Native HTTPS/TLS & Signed Heartbeats
```bash
/usr/local/bin/sf-cp \
  --bind 0.0.0.0 --port 8443 \
  --data-dir /var/lib/sealframe-control-plane \
  --sbom /var/lib/sealframe-control-plane/sbom.cdx.json \
  --tls-cert /etc/sealframe/tls/server.crt \
  --tls-key  /etc/sealframe/tls/server.key \
  --require-signed-heartbeat
```
- The admin Bearer token is stored with `0600` permissions in `/var/lib/sealframe-control-plane/admin.token`.
- Export compliance reports anytime via `GET /api/v1/audit/cra` (JSON with `report_sha256`) or `GET /api/v1/audit/cra.html` (print-ready PDF/HTML).

---

## 4. Health-Check & Automatic Rollback Contract
- Your `--health-cmd` MUST exit `0` if and only if the newly deployed bundle is fully operational.
- If `--health-cmd` exits non-zero OR exceeds `--health-timeout` (killed via `SIGKILL`), `sf-agent` **automatically invokes `fp_bundle_rollback()`**, restoring the previous generation's files and inverting SQLite changesets bit-exact, and reports `ROLLED_BACK` (signed Ed25519) to the Control Plane.
