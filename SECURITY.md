# Security Policy

SealFrame™ follows a Coordinated Vulnerability Disclosure (CVD) process aligned with the **EU Cyber Resilience Act (Regulation 2024/2847)**. See [`docs/CVD_POLICY.md`](docs/CVD_POLICY.md) for the full compliance playbook.

## Reporting a Vulnerability

**Please do NOT open a public GitHub Issue for security vulnerabilities.**

Instead, please report suspected vulnerabilities privately via:
- **GitHub Private Vulnerability Reporting** (Security tab → *Report a vulnerability*), or
- **Email:** `tonyswagcard@gmail.com`.

Please include:
- Affected version / commit hash and component (`libsealframe`, `sf`, `sf-agent`, `sf-cp`, `sf-llama-bridge`),
- Minimal reproduction steps or Proof of Concept input,
- Potential impact assessment.

## Target Response SLAs
- **Acknowledgment:** within 24 hours
- **Initial triage:** within 72 hours
- **Critical security fix:** within 7 days (emergency mitigation within 48 hours)
- **High severity fix:** within 30 days

## Security Hardening Baseline
All official SealFrame™ pure-C11 binaries are built with `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3`, `PIE`, `Full RELRO`, `NX stack`, `-Wall -Wextra -Werror -pedantic`, and verified against GCC ASan/UBSan, Clang TSan, and libFuzzer.
