# SEALFRAME — Executive One-Pager (B2B)

> **Piattaforma proprietaria di distribuzione OTA, sincronizzazione differenziale e conformità EU Cyber Resilience Act (CRA) per flotte Industrial IoT, Robotica ed Edge AI.**
> *Versione di riferimento: `v0.5.1` (Release Candidate Commerciale — Pacchetto `.deb` da 144 KB)*

---

## Il Problema Reale delle Flotte Edge Oggi
Chi gestisce flotte di robot, PLC industriali, gateway IoT o nodi Edge AI affronta quattro costi nascosti critici:
1. **Spreco di banda su reti 4G/5G/satellitari**: aggiornare un modello AI o un firmware da 500 MB–10 GB ritrasmettendo l'intera immagine (o layer container giganti) costa migliaia di euro al mese e satura i link.
2. **Dispositivi bloccati ("brick") sul campo**: se un aggiornamento corrompe lo stato tra file di configurazione, pesi AI e database locale SQLite, serve un intervento fisico sul posto.
3. **Rischio Supply-Chain e chiavi singole**: se una singola chiave di firma CI/CD viene compromessa, un attaccante può prendere il controllo dell'intera flotta.
4. **Obblighi normativi europei (EU Cyber Resilience Act — Reg. UE 2024/2847)**: le aziende devono dimostrare integrità crittografica degli aggiornamenti, SBOM aggiornati, gestione delle vulnerabilità e tracciabilità completa per almeno 5 anni.

---

## La Soluzione: SealFrame (`libsealframe` + `sf-agent` + Control Plane On-Premises)
**SealFrame** è un motore proprietario scritto in puro **C11 ISO** (senza Java, Go, Docker né OpenSSL) progettato per funzionare su hardware vincolato, reti instabili e fabbriche **100% on-premises o air-gapped**:

- **Impronta minuscola**: l'Edge Agent (`sf-agent`) pesa **123 KB** su disco (intero pacchetto `.deb` con CLI, SDK, Agent, Control Plane, SBOM e documenti CRA = **144 KB**!) e gira sotto `systemd` con **`MemoryMax=32M`** (picco misurato **11,5 MiB** inclusa page cache; **0,5 MiB** a riposo).
- **Trasferimento Multi-GB a RAM costante**: verificato fisicamente su server legacy **Pentium P6100 (2010) con soli 256 MiB di RAM e HDD meccanico** servendo un file da **512 MiB (2× la RAM!)** a **29,8 MiB/s** usando **5,86 MiB di Peak RSS**.
- **Deduplica intelligente e Delta estremi**:
  - Patch binaria da 4 KiB su firmware da 32 MiB → **56,5 KiB su rete** (**-99,83% banda**, **65× più piccolo di `zstd`**, **458× più piccolo di `gzip`**).
  - Deduplica **FastCDC** resistente allo shift (+137 B inseriti all'inizio di 32 MiB) → **99,88% dei chunk riutilizzati** in **42 ms**.
  - Aggiornamenti con modelli AI invariati → **0 byte ritrasmessi** sul modello (solo ~150 B di configurazione).
- **Rollback Atomico Full-Stack (File + Modello AI + Database SQLite)**: se l'applicazione non supera il `--health-cmd` dopo il deploy (o va in timeout), `sf-agent` ripristina automaticamente **sia i file sia le righe del database SQLite** (inversione transazionale `sqlite3changeset_invert`) in millisecondi, senza mai lasciare stati incoerenti.
- **Sicurezza Zero-Trust & CRA-Ready**:
  - **Root Multi-Sig offline 2-su-3 Ed25519 (`FPR1`)** con rotazione e revoca permanente.
  - **Verifica Merkle BLAKE3 ogni 16 KiB** prima di scrivere su disco + **resume crittografico esatto** dopo cadute di rete o `SIGKILL`.
  - **Trasporto ibrido**: peer cifrato **LAN `FP-NET`** (X25519 + XChaCha20-Poly1305) con fallback automatico a **HTTP/1.1 `206` Range** + **UDP cifrato `FP-UDP1`** resistente al 25% di packet loss e cambio IP live (Wi-Fi ↔ 4G).
  - **Control Plane On-Premises** con HTTPS/TLS 1.2+, heartbeat firmati Ed25519, RBAC Bearer, workflow approvazione 2-su-3, **SBOM CycloneDX 1.5 automatico** ed **Export Report Audit EU CRA** (JSON sigillato SHA-256 + certificato stampabile HTML/PDF).

---

## Vantaggi Chiave rispetto ai Sistemi Attuali

| Requisito Critico | **SealFrame** | **Docker / OCI** | **Mender / RAUC** | **OSTree** | **`rsync` / `scp`** |
|---|---|---|---|---|---|
| **Dimensione & RAM Agent** | **123 KB / < 12 MiB** | 50–100+ MB / 80–250+ MiB | 0,5–25 MB / 10–60 MiB | 2–5 MB / 15–40 MiB | Non è un agent OTA |
| **Rollback atomico File + SQLite** | **Sì (nativo)** | No (volumi separati) | Solo partizione A/B | Solo filesystem | No |
| **Root Multi-Sig 2-su-3 offline** | **Sì (nativo)** | Esterno | PKI X.509 / no quorum | No quorum | No |
| **Deduplica Shift / Cross-File** | **Sì (99,88% FastCDC)** | Solo per layer | No / limitata | Solo file interi | Solo 1-a-1 |
| **Swarm LAN + UDP Anti-Loss** | **Sì (nativo)** | No | No | No | No |
| **Audit EU CRA + SBOM integrati** | **Sì (chiavi in mano)** | Esterno | Parziale / Enterprise | No | No |
| **Licenza & Dipendenze** | **Proprietario, 0 GPL** | Misto / complesso | Apache/LGPL/GPL | LGPL | GPL (`rsync`) |

---

## Evidenze di Qualità Verificate (`v0.5.1`)
- **Hardening ELF verificato (`make security-check`)**: PIE, Full RELRO (`GNU_RELRO` + `BIND_NOW`), NX Stack, Stack Canary, `_FORTIFY_SOURCE=3`.
- **Fuzzing Coverage-Guided (`Clang 23 libFuzzer + ASan + UBSan`)**: **10.263.534 esecuzioni** su tutti i parser binari (`641.470 exec/s`) → **0 crash, 0 UB, 0 memory leak**.
- **Chaos & Fisica Reale**: 10× `SIGKILL` consecutivi su HDD meccanico (`0` corruzioni), resume dopo `SIGKILL` a 134 MiB su LAN fisica (`8.529` chunk saltati), 25% perdita pacchetti UDP + cambio porta live recuperati in `19 ms`.

---

## Modelli Commerciali & Proposta di Pilota (PoC 30 Giorni)
- **Licenza Flotta Edge**: abbonamento annuale per dispositivo gestito (binari `.deb` / SDK + Control Plane On-Premises + supporto LTS 5 anni).
- **Licenza OEM Embedded SDK**: integrazione diretta di `libsealframe.a`/`libsealframe.so` nei prodotti del cliente sotto NDA, con **opzione Source Code Escrow**.
- **Prossimo Passo**: **Demo Live di 15 minuti** (rollout reale, attacco supply-chain bloccato, auto-rollback ed export Audit CRA) + **Pilota PoC di 30 giorni** su 5–50 dispositivi fisici del cliente.
