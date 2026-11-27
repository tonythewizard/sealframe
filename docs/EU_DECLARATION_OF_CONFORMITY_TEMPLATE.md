# EU Declaration of Conformity (TEMPLATE — Annex V, Regulation (EU) 2024/2847)

> **STATUS**: `PRE-COMMERCIAL ENGINEERING TEMPLATE (NOT SIGNED)`
> This template MUST NOT be signed or used to affix CE marking until commercial `v1.0.0` release, completion of all Phase 1–3 verification gates (including physical ARM64 / power-cut validation and independent third-party security review), and formal legal manufacturer registration.

---

## EU DECLARATION OF CONFORMITY

1. **Product with digital elements**:
   - Name: **SealFrame Enterprise Edge OTA Core (`sf`, `sf-agent`, `libsealframe`, On-Premises Control Plane)**
   - Version / Build: `1.0.0` *(drafted at `0.5.0`)*
   - Binary/SBOM Reference: CycloneDX 1.5 SBOM (`sbom.cdx.json`) + SHA-256 release manifest

2. **Name and address of the manufacturer**:
   - `<Legal Manufacturer Name / Società>`
   - `<Registered EU Street Address, City, Postal Code, Italy / EU>`
   - Security contact (CVD): `tonyswagcard@gmail.com`

3. **Sole responsibility**:
   This declaration of conformity is issued under the sole responsibility of the manufacturer.

4. **Object of the declaration**:
   - Hardened C11 content-addressed verification, differential morphing, atomic composite bundle (`FPB1`), Multi-Sig Root (`FPR1`) trust core, Edge Agent daemon (`sf-agent`), and on-premises Control Plane software for industrial Linux edge systems.

5. **Conformity statement**:
   The object of the declaration described above is in conformity with the relevant Union harmonisation legislation:
   - **Regulation (EU) 2024/2847** of the European Parliament and of the Council of 23 October 2024 on horizontal cybersecurity requirements for products with digital elements (**Cyber Resilience Act — CRA**).

6. **References to relevant harmonised standards / technical specifications**:
   - Technical Documentation (Annex VII): `docs/CRA_TECHNICAL_FILE.md`
   - Secure Development & Vulnerability Handling alignment: **IEC 62443-4-1 / IEC 62443-4-2** *(target alignment)*
   - Software Bill of Materials format: **CycloneDX 1.5 (ISO/IEC 5962 / ECMA-424)**

7. **Conformity assessment procedure**:
   - Module A (Internal Control) supported by independent third-party cryptographic and binary penetration test summary (`<Audit Lab Name, Report Ref, Date>`).

8. **Support Period**:
   - Minimum **5 years** of security updates from commercial release date (`<YYYY-MM-DD>` to `<YYYY-MM-DD>`).

9. **Signed for and on behalf of**:
   - Place and date of issue: `<City, Italy — YYYY-MM-DD>`
   - Name, function: `<Legal Representative Name, CEO / Managing Director>`
   - Signature: `___________________________`
