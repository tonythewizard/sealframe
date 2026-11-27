# Security Policy

> **Audit Status:** SealFrame™ is under active engineering hardening and **has not yet undergone an independent third-party cryptographic or security audit**. Custom transports (`FPN1`/`FPU1`) should be treated as experimental until formally audited (see [`ROADMAP.md`](ROADMAP.md)).

SealFrame™ includes Coordinated Vulnerability Disclosure (CVD) templates aligned with **EU Cyber Resilience Act (Regulation 2024/2847)** documentation practices (not a formal third-party compliance certification). See [`docs/CVD_POLICY.md`](docs/CVD_POLICY.md).

## Reporting a Vulnerability

**Please do NOT open a public GitHub Issue for security vulnerabilities.**

Instead, please report suspected vulnerabilities privately via:
- **GitHub Private Vulnerability Reporting** (Security tab → *Report a vulnerability*), or
- **Email:** `tonyswagcard@gmail.com`.

Please include:
- Affected version / commit hash and component (`libsealframe`, `sf`, `sf-agent`, `sf-cp`, `sf-llama-bridge`),
- Minimal reproduction steps or Proof of Concept input,
- Potential impact assessment.

## Best-Effort Target Response Times
*(Formal contractual SLAs are provided only under a Commercial License.)*
- **Acknowledgment:** best-effort within 72 hours
- **Initial triage:** best-effort within 7 days
- **Critical security fix:** prioritized ahead of all feature work

## Security Hardening Baseline
All official SealFrame™ C11 (POSIX/Linux) binaries are built with `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3`, `PIE`, `Full RELRO`, `NX stack`, `-Wall -Wextra -Werror -pedantic`, and verified in CI across all 11 test suites with GCC ASan + UBSan and Clang.
