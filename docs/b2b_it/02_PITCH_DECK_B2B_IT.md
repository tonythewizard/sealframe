# SEALFRAME — Pitch Deck Commerciale B2B (12 Slide)

> *Presentazione pronta per riunioni con CTO, CISO, Direttori R&D, OEM Industriali e Investitori DeepTech.*
> *Tutti i numeri di SealFrame riportati sono misurati su codice e hardware reali (`v0.5.1`).*

---

## Slide 1 — Copertina
### **SEALFRAME**
**Infrastruttura OTA Ultra-Compatta, Auto-Riparante e CRA-Ready per Flotte Industriali ed Edge AI**
- Binario C11 proprietario da **123 KB** · **Zero Cloud Obbligatorio** · **Zero Copyleft (0 GPL)**
- Rollback Atomico **File + AI + SQLite** · **Root Multi-Sig 2-su-3** · **Audit EU CRA Nativo**

---

## Slide 2 — Il Problema (Perché le Flotte Edge Costano Troppo e Rischiano Molto)
Le aziende che distribuiscono software e modelli AI su decine o migliaia di dispositivi fisici (robot, gateway fabbrica, droni, colonnine, medicale, edge AI) si scontrano con 4 muri:
1. **Banda & Latenza**: i modelli AI e i firmware pesano da 500 MB a 50 GB; su 4G/5G/satellitare o Wi-Fi di fabbrica ogni aggiornamento completo è lento e costoso.
2. **Aggiornamenti parziali & Disallineamento DB**: sostituire un binario senza allineare configurazioni e database locale SQLite causa crash in produzione e costosi interventi on-site.
3. **Attacchi alla Supply-Chain**: una singola chiave di build compromessa o un server di distribuzione violato può infettare l'intera flotta in pochi minuti.
4. **Regolamento Europeo CRA (UE 2024/2847)**: rende obbligatori aggiornamenti sicuri, tracciabilità, SBOM aggiornati, gestione vulnerabilità (notifica ENISA/CSIRT entro 24h) e supporto pluriennale.

---

## Slide 3 — Perché le Soluzioni Attuali Non Bastano
- **Docker / Container OCI**: richiedono daemon pesanti (80–250+ MB RAM), layer rigidi che ritrasmettono centinaia di MB per piccole modifiche, nessuna atomicità sui volumi database e nessuna governance Multi-Sig nativa.
- **Mender / RAUC (OTA A/B)**: ottimi per l'OS di base, ma raddoppiano lo spazio disco richiesto, non sincronizzano in modo atomico i database SQLite applicativi, non offrono Swarm LAN anti-bizantino né UDP resiliente.
- **OSTree**: gestisce solo file statici (no database, no delta sub-file su shift di byte, no quorum Multi-Sig).
- **`rsync` / `scp` / script custom**: nessun albero di fiducia crittografico, nessun rollback applicativo, vulnerabili a downgrade/freeze attack, nessuna evidenza di audit CRA (`rsync` è inoltre GPLv3).

---

## Slide 4 — La Soluzione: Un'Unica Piattaforma Completa in 144 KB
**SealFrame** unisce in un'architettura modulare 100% on-premises:
1. **Core C11 Hardened (`libsealframe`)**: motore crittografico e di trasporto (BLAKE3 Merkle, Zstd Delta, FastCDC, SQLite Session, Ed25519/X25519/XChaCha20).
2. **Edge Agent (`sf-agent` — 123 KB)**: demone `systemd` isolato (`ProtectSystem=strict`, `MemoryMax=32M`) con verifica Multi-Sig, download ibrido LAN/HTTP, watchdog health-check e auto-rollback.
3. **Enterprise Control Plane On-Premises**: console web air-gapped, HTTPS/TLS 1.2+, verifica Ed25519 sugli heartbeat, RBAC Bearer, workflow approvazione 2-su-3 ed export **Report Audit EU CRA** (JSON + HTML/PDF).

---

## Slide 5 — Le 5 Innovazioni Tecniche che Fanno la Differenza
1. **Content DNA + Verifica Merkle 16 KiB**: ogni blocco da 16 KiB viene verificato crittograficamente prima di toccare il disco. Se cade la rete al 60%, riparte al byte esatto senza mai riscaricare né committare un singolo byte corrotto.
2. **Morph Autonomo + FastCDC (99,88% dedup anche su shift)**: sceglie automaticamente tra `REF` (0 byte se già presente), `DELTA` (56 KiB per 32 MiB) o chunking content-defined resistente allo spostamento di byte.
3. **Particle Bundle Atomico (`FPB1`: File + AI + SQLite)**: applica file, pesi AI e transazioni SQLite insieme; se il health-check fallisce o cade la corrente (`SIGKILL`), inverte automaticamente anche il DB SQLite tornando bit-per-bit alla versione precedente.
4. **Root Multi-Sig Offline 2-su-3 (`FPR1`)**: le chiavi Root restano offline in cassaforte/HSM; una chiave CI/CD compromessa viene revocata e ruotata da remoto senza bloccare la flotta.
5. **Trasporto Ibrido LAN-First + UDP Resiliente (`FP-NET` / `FP-UDP1`)**: i dispositivi in fabbrica scaricano i modelli grandi da un peer LAN cifrato (risparmiando banda WAN) con fallback HTTP Range; su reti mobili/lossy `FP-UDP1` sopravvive al 25% di perdita pacchetti e al cambio rete Wi-Fi ↔ 4G senza interrompere la sessione.

---

## Slide 6 — Benchmark Reali Misurati vs Strumenti Standard
*Misure fisiche reali tra server legacy Proxmox (Pentium P6100, 256 MiB RAM, HDD) e workstation Wi-Fi:*

| Scenario | SealFrame (`v0.5.1`) | Concorrente Reale | Vantaggio Misurato |
|---|---|---|---|
| **Hashing integrità (64 MiB su P6100)** | **`0.36 s`** (`2.7 MiB` RAM) | `sha256sum`: `0.45 s` (`3.7 MiB`) | **+25% velocità, -28% RAM + Merkle** |
| **Patch 4 KiB su firmware 32 MiB** | **`56,5 KiB`** | `zstd`: `3,65 MiB` / `gzip`: `25,9 MiB` | **65×–458× meno dati** |
| **Shift +137 B su 32 MiB** | **99,88% chunk riutilizzati** (`42 ms`) | Blocchi fissi: ~0% dedup | **Solo 2 chunk nuovi su 1.661** |
| **Trasferimento freddo 64 MiB LAN** | **`29,7 MiB/s`** (`3.3 MiB` server RSS) | `rsync -e ssh`: `28,1 MiB/s` / `scp`: `31,7 MiB/s` | **Batte `rsync`, vicino a `scp` con Merkle+resume** |
| **Aggiornamento identico (No-Op 32 MiB)** | **`0.028 s` / `511 B`** | `rsync --checksum`: `0.627 s` / `75,5 KiB` | **22× più veloce, 147× meno banda** |
| **Patch 4 KiB su LAN (byte su rete)** | **`57,0 KiB`** | `rsync`: `~75,4 KiB` | **-24% banda** *(su LAN veloce `rsync` è più rapido in CPU; su 4G vince la banda)* |

---

## Slide 7 — Prova Estrema su Hardware Reale (Zero Bloat Dimostrato)
Abbiamo testato SealFrame su una macchina volutamente estrema:
- **Hardware**: Intel Pentium P6100 del **2010** (1 core, **senza AVX né AES-NI**), **256 MiB di RAM totali**, **HDD meccanico**, Debian 13.
- **Risultati misurati**:
  - **File da 512 MiB (2× l'intera RAM della macchina!)** servito crittografato e verificato Merkle a **29,8 MiB/s** con soli **5,86 MiB di Peak RSS**!
  - **`SIGKILL` reale a 134 MiB** su rete Wi-Fi↔Ethernet → ripartito saltando esattamente **8.529 chunk verificati** (`0` byte corrotti).
  - **UDP cifrato `FP-UDP1` (32 MiB)** su Wi-Fi↔Ethernet: **18,2 MiB/s**, `0` ritrasmissioni, **3,30 MiB di RAM** (più veloce di `scp` TCP nello stesso test!).
  - **Demone `systemd` live (`sealframe-agent.service`)**: **0,5 MiB RAM a riposo**, **11,5 MiB picco cgroup** durante rollout completo `v1 → v2 auto-rollback → v3`.

---

## Slide 8 — Sicurezza Verificata & Conformità EU Cyber Resilience Act (CRA)
Progettato dal giorno 1 per il **Regolamento UE 2024/2847**:
- **Zero superficie OpenSSL / X.509 / ASN.1**: solo crittografia moderna `libsodium` + `BLAKE3`.
- **Hardening binario certificabile (`make security-check`)**: PIE, Full RELRO, NX Stack, Stack Canary, `_FORTIFY_SOURCE=3`, zero warning su **GCC 16** e **Clang 23** (`-Werror -pedantic`).
- **Fuzzing industriale reale**: **10.263.534 esecuzioni coverage-guided** (`Clang 23 libFuzzer + ASan + UBSan`) su tutti i parser binari → **0 crash, 0 UB, 0 memory leak**.
- **Documentazione CRA pronta**: Fascicolo Tecnico Allegato VII + Threat Model STRIDE, SBOM **CycloneDX 1.5** automatico ad ogni build, Manuale Integratore (Allegato II), Policy CVD + notifica ENISA 24h (Art. 14) ed export Audit JSON/PDF dal Control Plane.

---

## Slide 9 — Verticali & Casi d'Uso B2B
1. **Robotica & Automazione Industriale**: zero brick su linee produttive grazie al rollback atomico File+SQLite e aggiornamenti in LAN tra robot senza saturare la rete aziendale.
2. **Edge AI On-Premises**: distribuzione di modelli quantizzati multi-GB su gateway con poca RAM, deduplicando automaticamente i pesi invariati.
3. **Energy, Utility & Infrastrutture Critiche**: funzionamento 100% on-premises/air-gapped con Multi-Sig 2-su-3 e tracciabilità di audit CRA per ogni nodo.
4. **Flotte Mobili & Connettività Instabile (4G/5G/Satellitare)**: resume crittografico al chunk 16 KiB e trasporto UDP `FP-UDP1` con migrazione di connessione live.

---

## Slide 10 — Demo Live in 60 Secondi (`bash scripts/demo_cto.sh`)
In una chiamata di 15 minuti il cliente vede in diretta sul terminale e nel browser:
1. Cerimonia offline **Root 2-su-3** + deploy atomico `v1.0.0` (modello AI 2 MiB + config) in **55 ms**.
2. **Attacco live bloccato**: richiesta senza token (`401`), telemetria falsificata (`401`), firmware firmato da chiave rogue respinto in **0,85 ms (`0 B` scaricati)**.
3. **Update rotto `v2.0.0-bad`**: scarica solo **154 B**, rileva il crash del servizio ed esegue **rollback automatico a `v1.0.0` in 55 ms**.
4. **Approvazione Quorum 2-su-3 (CTO + CISO)** + recovery pulito a `v3.0.0-fixed` (**153 B**).
5. **Export istantaneo del Report Audit EU CRA** (JSON con SHA-256 + certificato HTML/PDF stampabile).

---

## Slide 11 — Modello Commerciale B2B & Fiducia Closed-Source
- **Distribuzione proprietaria sotto contratto B2B/NDA** (zero codice pubblico, zero dipendenze GPL/LGPL/AGPL):
  - **Edge Fleet License**: canone annuale per dispositivo gestito (`.deb` pronto da installare + Control Plane + aggiornamenti sicurezza 5 anni).
  - **OEM Embedded SDK**: licenza annuale/royalty per integrare `libsealframe.a`/`libsealframe.so` nei prodotti del cliente.
  - **Enterprise & Critical Infrastructure**: supporto LTS 5–10 anni, integrazione HSM/TPM 2.0, **Source Code Escrow** presso ente terzo UE.
- **Come garantiamo fiducia senza aprire il codice**: Attestato di Penetration Test indipendente sotto NDA *(gate `v1.0`)* + SBOM CycloneDX 1.5 + Fascicolo Tecnico CRA + Source Code Escrow.

---

## Slide 12 — Trasparenza Tecnica & Proposta di Pilota (30 Giorni)
**Onestà ingegneristica sullo stato attuale (`v0.5.1` → `v1.0.0`)**:
- *Già pronto e verificato oggi*: motore C11 hardened, `.deb` 144 KB, test fisico 2-host Proxmox `x86_64`, Control Plane HTTPS/RBAC/2-su-3, 10,26M fuzzing, documentazione CRA completa.
- *Completamento verso marcatura CE `v1.0.0`*: validazione su silicio fisico **ARM64** del cliente (Raspberry Pi / Jetson / i.MX), test **power-cut kernel (`dm-flakey`)** su filesystem target e **audit di sicurezza indipendente di terza parte**.

**Proposta immediata — Pilota PoC di 30 giorni**:
1. Installazione del Control Plane on-prem + `sealframe_0.5.1_amd64.deb` su **5–20 dispositivi di test** del cliente.
2. Misurazione sul campo di banda risparmiata, tempi di rollback e report di conformità CRA.
3. Conversione in contratto annuale B2B/OEM con roadmap verso `v1.0.0` certificato.
