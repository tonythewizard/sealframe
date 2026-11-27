# Coordinated Vulnerability Disclosure (CVD) & CRA Art. 14 Reporting Policy

> **Product**: SealFrame (`sf`, `sf-agent`, `libsealframe`, Control Plane)
> **Compliance**: EU Cyber Resilience Act (Regulation 2024/2847), Annex I Part II & Article 14

---

## 1. Reporting a Security Vulnerability
B2B customers, integrators, and security researchers can report suspected vulnerabilities confidentially via:
- **Email**: `tonyswagcard@gmail.com`
- **Required details**: affected version/SBOM serial, component (`libsealframe`, `sf-agent`, `sf-cp`, or dependency), reproduction steps or crash input, and impact assessment.

## 2. Response & Remediation SLAs
| Milestone | Target SLA |
|---|---|
| Receipt acknowledgment | Within **24 hours** |
| Initial triage & CVSS v4.0 severity scoring | Within **72 hours** |
| Critical / Actively Exploited hotfix (`FPE1` signed release + updated SBOM) | Within **7 days** (emergency mitigation within 48 hours) |
| High severity fix | Within **30 days** |
| Medium / Low severity fix | Next scheduled maintenance release (≤ 90 days) |

## 3. Mandatory CRA Article 14 Regulatory Notification Playbook
Upon becoming aware of an **actively exploited vulnerability** or **severe incident** impacting SealFrame:
1. **≤ 24 Hours (Early Warning)**: Submit Early Warning to the designated national CSIRT (**CSIRT Italia / ACN**) and **ENISA** single reporting platform, indicating whether exploitation is suspected to be unlawful/malicious and potential cross-border EU impact.
2. **≤ 72 Hours (Vulnerability / Incident Notification)**: Submit formal update with CVSS assessment, affected versions/DNA hashes, indicators of compromise (if any), and available mitigations/revocations (`FP_ACTION_REVOKE` / `FPR1` key rotation).
3. **≤ 14 Days after Patch Availability (Final Report)**: Submit root-cause analysis, corrective measures, signed patch DNA + CycloneDX 1.5 SBOM, and verification evidence.
4. **Simultaneous Customer Advisory**: Notify all contracted B2B integrators with signed revocation/patch bundles and updated CRA Audit references.

## 4. Support Lifecycle & End-of-Life
- Every commercial `v1.x` LTS release receives a minimum of **5 years** of security updates and dependency CVE monitoring (`libblake3`, `libsodium`, `libzstd`, `sqlite3`) via automated CycloneDX 1.5 SBOM scanning.
