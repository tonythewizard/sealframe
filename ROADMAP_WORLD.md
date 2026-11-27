# SealFrame (`sf`) — Roadmap Commerciale B2B & Certificazione (Closed-Source)

> **Strategia scelta**: **Prodotto commerciale B2B** rivolto a clienti industriali (Industrial IoT, Robotica, Automazione, Edge AI, Difesa/Infrastrutture critiche).
> **Dove siamo oggi (`v0.5.0`)**: prodotto commerciale B2B completo pacchettizzato in **`sealframe_0.5.1_amd64.deb` (144 KB!)** con BLAKE3 1.8.2 vendorizzato (zero dipendenze esterne `libblake3`), Edge Agent `systemd` hardened (`MemoryMax=32M`), Control Plane On-Prem con HTTPS/TLS nativo, verifica Ed25519, Bearer RBAC, workflow approvazione 2-su-3, Export Audit CRA JSON+HTML e pacchetto documentale CRA Fase 3 (`EU DoC` template, `Integrator Manual`, `CVD Policy`, `Commercial License`). Verificato LIVE su Proxmox Debian 13 (`192.168.1.12`, 256 MiB RAM, Pentium P6100, HDD).

---

## FASE 1 — Fisica Reale, Hardening Binario & Multi-GB Streaming (`v0.2` — Mesi 1–2)
*Obiettivo: trasformare il nucleo di laboratorio in un binario C indistruttibile su hardware reale.*

1. **[PARZIALE `v0.2.1` — 2-HOST FISICO VERIFICATO, RESTA SILICIO ARM64]** **Test fisico 2-host reale (`x86_64 ↔ x86_64` su Proxmox Pentium P6100 256 MiB RAM + HDD, report in `docs/PHYSICAL_TEST_REPORT_v0.2.md`)**:
   - **[FATTO]** Trasferimento fisico reale **512 MiB** (`2× RAM del container`) su Ethernet↔Wi-Fi a **29.8 MiB/s** con **5.86 MiB Peak RSS**, `SIGKILL` a metà + resume di `8.529` chunk, DELTA 32 MiB in **56.3 KiB** (vs `scp` 32 MiB / `rsync` 75.4 KiB), UDP cifrato `FP-UDP1` 32 MiB a **18.2 MiB/s** (`0` retrans, `srtt=4.21 ms`, `3.30 MiB RSS`) e fail-closed `EFBIG`.
   - **[DA FARE]** Ripetere con `make physical-kit` su board fisica **ARM64** (Raspberry Pi / Jetson) e su 4G/WAN.
2. **[FATTO `v0.2.0`]** **Hardening di compilazione Security-Grade + SBOM + Fascicolo Tecnico CRA**:
   - Compilazione release con `-fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack`, verifica ELF automatizzata (`make security-check`), SBOM CycloneDX 1.5 (`make sbom`) e `docs/CRA_TECHNICAL_FILE.md`.
3. **[PARZIALE `v0.2.0`]** **Congestion Control su `FP-UDP1` (AIMD + Jacobson/Karels SRTT/RTTVAR) + NAT Traversal**:
   - **[FATTO]** Finestra adattiva AIMD (`cwnd`) e stima SRTT/RTTVAR (RFC 6298) su `FP-UDP1`.
   - **[DA FARE]** NAT hole-punching UDP / relay cieco cifrato end-to-end su WAN reale.
4. **[FATTO `v0.2.0`]** **Streaming `pread()` a RAM costante per file Multi-GB**:
   - Eliminata ogni `malloc(obj_len)` sui server TCP (`FPN1`), Swarm e UDP (`FPU1`) tramite `fp_merkle_tree_build_file()` + `fp_store_open_object_fd()` + `pread()` in buffer fissi da 16 KiB.
5. **[DA FARE — RICHIEDE KERNEL/VM]** **Power-Cut Reale (`dm-flakey` / QEMU power-off) su ext4, Btrfs e XFS** + gestione disco pieno (`ENOSPC`).

**Gate Fase 1 (`v0.2`)**: parte software/hardening/streaming/AIMD/SBOM completata e verificata localmente; chiusura definitiva del gate dopo il trasferimento fisico da 10 GB `x86_64 ↔ ARM64` e test power-cut su hardware/VM dedicata.

---

## FASE 2 — Il Prodotto Vendibile: Agent + Control Plane B2B (`v0.3 → v0.5` — Mesi 3–5)
*Obiettivo: costruire il prodotto completo che un'azienda industriale paga subito (non solo la libreria).*

1. **[FATTO `v0.4.0`]** **Edge Agent (`bin/sf-agent`, 123 KB binario hardened, `systemd` `MemoryMax=32M`)**:
   - **Trasporto ibrido LAN-First + HTTP/1.1 Range Fallback** ([`src/agent.c`](src/agent.c), [`src/http.c`](src/http.c)): tenta prima un peer **LAN `FP-NET`** cifrato (`X25519+XChaCha20`, DELTA/Merkle) per risparmiare banda WAN, con fallback trasparente a **HTTP/1.1 `206 Partial Content` Range** + verifica BLAKE3 streaming.
   - **Heartbeat firmati Ed25519** (`X-FP-Device-PubKey` + `X-FP-Signature`), verifica **Root Multi-Sig 2-su-3 (`FPR1`)**, applicazione atomica **`Particle Bundle` (File + Modello AI + SQLite)**, **watchdog health-check (`SIGKILL` timeout)** e **rollback automatico** bit-exact su fallimento.
   - **Unit `systemd` di produzione** ([`packaging/systemd/sealframe-agent.service`](packaging/systemd/sealframe-agent.service)): `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `MemoryMax=32M` — installata e verificata **LIVE** sul nodo Proxmox LXC `900` (`192.168.1.12`): cgroup `MemoryPeak = 11.5 MiB`, rollout autonomo `v1 → v2 rollback → v3`.
2. **[FATTO `v0.4.0`]** **Enterprise Control Plane On-Premises ([`src/cp_main.c`](src/cp_main.c) + [`packaging/systemd/sealframe-control-plane.service`](packaging/systemd/sealframe-control-plane.service))**:
   - **Zero-Trust Auth**: verifica firme **Ed25519** sugli heartbeat tramite `libsodium` (`--require-signed-heartbeat`, rifiuto `401` su non firmati/falsificati) + **Bearer Token RBAC** su promozione canali e **Emergency Rollback** (`401` senza token).
   - Dashboard web live on-prem (`http://192.168.1.12:8080/`) con badge `Ed25519 OK`, contatori `LAN / HTTP`, controlli di promozione/rollback di emergenza.
   - **Export automatico Report di Audit EU CRA**: JSON con `report_sha256` + SBOM CycloneDX 1.5 (`GET /api/v1/audit/cra`) e **Report stampabile HTML/PDF** (`GET /api/v1/audit/cra.html`).
   - *[Prossimo passo `v0.5`]*: approvazione Multi-Sig 2-su-3 da UI/YubiKey/HSM e TLS/HTTPS nativo (o reverse proxy Nginx/mTLS).
3. **[FATTO `v0.5.0`]** **Packaging Commerciale `.deb` + Documentazione B2B & CRA Fase 3**:
   - **BLAKE3 1.8.2 pure-C vendorizzato** (`third_party/blake3/`, 59 KB) con auto-fallback: zero attrito distro su Debian/Ubuntu/RHEL/Yocto/ARM64.
   - **Pacchetto Debian installabile (`make deb` → `sealframe_0.5.1_amd64.deb`, 144 KB)** costruito e installato live via `dpkg -i` sul Proxmox `192.168.1.12`.
   - **HTTPS/TLS 1.2+ nativo** (`--tls-cert`/`--tls-key`) e **workflow approvazione Multi-Sig 2-su-3** (`POST /api/v1/approvals`) tracciato nel Report CRA.
   - Pacchetto documentale completo pronto per revisione legale/audit: [`docs/EU_DECLARATION_OF_CONFORMITY_TEMPLATE.md`](docs/EU_DECLARATION_OF_CONFORMITY_TEMPLATE.md), [`docs/INTEGRATOR_MANUAL.md`](docs/INTEGRATOR_MANUAL.md), [`docs/CVD_POLICY.md`](docs/CVD_POLICY.md), [`docs/COMMERCIAL_LICENSE_SUMMARY.md`](docs/COMMERCIAL_LICENSE_SUMMARY.md).

**Gate Fase 2 (`v0.5.0`)**: parte tecnica e packaging commerciale **100% completata e verificata su hardware Proxmox reale**; prossimo traguardo: primo pilota pagato su flotta industriale + audit indipendente sotto NDA (Fase 3 / `v1.0.0`).

---

## FASE 3 — Certificazione CRA, Audit Indipendente & Standard Industriali (`v1.0` — Mesi 6–9)
*Obiettivo: ottenere la marcatura CE / conformità CRA (Regolamento UE 2024/2847) e i timbri di fiducia richiesti dai CTO B2B.*

1. **Fascicolo Tecnico CRA completo (Allegato VII del Regolamento UE 2024/2847)**:
   - **Threat Model & Risk Assessment** formale (STRIDE su tutti gli 8 formati binari e protocolli di rete).
   - **SBOM automatico (CycloneDX / SPDX)** generato ad ogni build (`libblake3`, `libsodium`, `libzstd`, `libsqlite3`, monitoraggio continuo CVE).
   - **Evidenze SDLC & Fuzzing continuo** (`libFuzzer` / `AFL++` con > 1 miliardo di esecuzioni, ASan/UBSan, Chaos suite riproducibile).
   - **Vulnerability Handling Policy (CVD)** + procedura di notifica ENISA/CSIRT Italia entro 24 ore.
   - **Manuale di Sicurezza per Integratori** (gestione chiavi Root offline, rotazione, hardening, supporto minimo 5 anni) + **Dichiarazione di Conformità UE (EU DoC)**.
2. **Audit di Sicurezza & Penetration Test di Terza Parte (sotto NDA)**:
   - Revisione crittografica e codice C11 da parte di laboratorio indipendente → rilascio di **Attestato / Executive Summary** da consegnare ai clienti B2B senza esporre il codice sorgente.
3. **Allineamento & Certificazione IEC 62443-4-1 / 62443-4-2** *(con Organismo Notificato es. TÜV / IMQ / RINA)*:
   - Standard di riferimento europeo per l'automazione industriale e armonizzato con il CRA (finanziabile con primi ricavi B2B o bandi DeepTech/Cybersecurity UE).

**Gate Fase 3 (`v1.0`)**: prodotto commerciale **CRA-compliant** con attestato di pentest indipendente, SBOM automatizzato, Fascicolo Tecnico completo e primi contratti ricorrenti B2B.

---

## FASE 4 — Scala Industriale, Transparency Log & Leadership (`v1.5 → v2.0` — Anno 1–2)
1. **Connettore Opzionale Transparency Log (`sf-anchor`, modulo separato)**:
   - Core sempre indipendente; i clienti che richiedono **non-equivocazione globale e revoche pubbliche verificabili** abilitano il connettore 32-byte verso un transparency log esterno.
2. **Supporto Hardware Security & Post-Quantum**:
   - Integrazione nativa **TPM 2.0 / PKCS#11 / HSM** sui dispositivi edge (chiave dispositivo non estraibile in hardware).
   - Handshake ibrido **Post-Quantum (X25519 + ML-KEM-768)** per contratti difesa/infrastrutture critiche a lungo ciclo di vita.
3. **Espansione Verticale**:
   - Pacchetti certificati pronti per **Robotica/Automazione**, **Edge AI on-premise**, **Medicale/Energy**, **Difesa/Air-Gapped** (distribuzione offline su USB/data-diode con identico DNA e verifica Multi-Sig).
