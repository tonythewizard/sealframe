# SealFrame — Proprietary B2B Commercial Licensing & Source Escrow Overview

> **Distribution Model**: Closed-Source Proprietary B2B Software (Commercial License & NDA)
> **Notice**: This document is a commercial framework summary for enterprise sales discussions and does not replace a signed Master Software License Agreement (MSLA) reviewed by legal counsel.

---

## 1. Commercial Packaging Tiers

| Tier | Deliverables | Target Customers | Pricing Structure (Indicative) |
|---|---|---|---|
| **Edge Fleet License** | Hardened binary packages (`.deb` / `.rpm` / ARM64 tarball) for `sf-agent` + `sf` + On-Premises Control Plane + CRA Audit Export + SBOM | Industrial IoT, Robotics, Energy, Edge AI fleets (50 – 10,000+ nodes) | Annual subscription per managed device (volume tiers) |
| **OEM Embedded SDK License** | Proprietary `libsealframe.a` / `libsealframe.so` + `fp.h` / `fp_agent.h` headers + cross-compile toolchain support + CRA Technical File excerpt + NDA Third-Party Pentest Attestation | Hardware OEMs embedding `libsealframe` directly into firmware/appliances | Annual OEM royalty / flat product-line license + support SLA |
| **Enterprise / Critical Infrastructure** | Dedicated LTS branch (5–10 years), custom HSM/TPM 2.0 integration, optional transparency anchor module, **Source Code Escrow** | Defense, Medical, Energy, Rail, Air-Gapped Industrial | Custom multi-year enterprise agreement |

---

## 2. Intellectual Property & Open-Source Dependency Hygiene
- **Proprietary Core**: All `include/*.h`, `src/*.c`, `control-plane/*.py`, `packaging/*`, and binary wire specifications (`FP01`, `FPE1`, `FPD1`, `FPC1`, `FPB1`, `FPR1`, `FPN1`, `FPU1`) are proprietary and copyright-protected trade secrets.
- **Permissive, Zero-Copyleft Third-Party Dependencies** (safe for closed-source commercial redistribution, tracked automatically in `sbom.cdx.json`):
  - **BLAKE3 1.8.2** — `CC0-1.0 OR Apache-2.0` (vendored or system library)
  - **libsodium** — `ISC`
  - **Zstandard (zstd)** — `BSD-3-Clause`
  - **SQLite3** — Public Domain (`blessing`)
  - *Zero GPL / LGPL / AGPL dependencies in the core C11 engine.*

---

## 3. Enterprise Trust Without Public Source Exposure
B2B enterprise buyers frequently ask how to trust closed-source security software. SealFrame provides four standard institutional guarantees:
1. **Independent Third-Party Security Audit Attestation** *(Phase 3 gate)*: Executive summary & letter of attestation delivered under NDA without exposing proprietary source code.
2. **Automated CycloneDX 1.5 SBOM + Reproducible Binary Hardening Proof** (`make security-check`, `sbom.cdx.json`).
3. **EU CRA Annex VII Technical Documentation & Compliance Audit Export** built directly into the Control Plane.
4. **Source Code Escrow Option**: For mission-critical customers, source code and reproducible build scripts are deposited with a neutral EU escrow agent, released only upon defined contractual trigger events (e.g., vendor insolvency or cessation of LTS support).
