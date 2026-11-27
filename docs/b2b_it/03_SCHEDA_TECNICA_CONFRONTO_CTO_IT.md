# SEALFRAME — Scheda Tecnica & Risposte alle Obiezioni per CTO / CISO

> **Documento di approfondimento tecnico per due diligence B2B (`v0.5.1`)**
> *Tono: ingegneristico, verificabile, privo di marketing vuoto.*

---

## 1. Architettura a Colpo d'Occhio
- **Linguaggio**: ISO C11 puro (`-std=c11 -Wall -Wextra -Werror -pedantic`), nessuna eccezione, nessun garbage collector, nessuna VM.
- **Dipendenze runtime (pacchetto `.deb` portabile)**: solo `libc6`, `libsodium` (ISC), `libzstd1` (BSD-3), `libsqlite3-0` (Public Domain). **BLAKE3 1.8.2** (CC0/Apache-2.0) è **vendorizzato in C** nel build `.deb` (zero attrito di pacchettizzazione su Debian, Ubuntu, RHEL, Yocto).
- **8 Formati Binari Specificati** (`SPEC.md`, big-endian esplicito, fail-closed):
  - `FP01` (Morph Wire), `FPE1` (Eventi firmati Ed25519), `FPD1` (Derivazioni firmate), `FPC1` (FastCDC Recipe), `FPB1` (Bundle Atomico File+SQLite), `FPR1` (Root Multi-Sig $t$-su-$n$), `FPN1` (TCP cifrato X25519+XChaCha20 + Merkle), `FPU1` (UDP cifrato + AIMD + Connection Migration).

---

## 2. Le 7 Domande Più Dure di un CTO / CISO (e le Risposte Concrete)

### Q1: *"Perché non usiamo semplicemente Docker / Kubernetes Edge (k3s)?"*
- **Risorse**: Docker/k3s assorbono facilmente 150–400 MB di RAM e centinaia di MB di storage già a vuoto. `sf-agent` occupa **123 KB** su disco e gira con **`MemoryMax=32M`** (0,5 MiB a riposo, 11,5 MiB picco cgroup durante un deploy completo).
- **Atomicità stato + dati**: un container sostituisce l'immagine applicativa, ma lascia i volumi SQLite/stato esposti a migrazioni parziali non reversibili. `FPB1` applica file, modelli AI e changeset SQLite in una singola transazione logica con **inversione automatica** su rollback.
- **Banda**: spostare un file o ricompilare un binario in un layer OCI spesso invalida l'intero layer. SealFrame usa **Zstd `DELTA` + FastCDC** (99,88% dedup anche su shift di byte) e **peer LAN cifrati**.

### Q2: *"Perché non Mender o RAUC?"*
- Mender e RAUC sono eccellenti per aggiornare **partizioni rootfs A/B intere**, ma:
  1. Richiedono il doppio dello spazio flash per il partizionamento A/B (critico quando i modelli AI pesano decine di GB).
  2. Non gestiscono il **rollback atomico del database SQLite applicativo** insieme ai file.
  3. Non offrono **Swarm LAN anti-bizantino**, **UDP cifrato resistente al 25% loss con migrazione IP**, né **Root Multi-Sig 2-su-3 nativo** con export Audit EU CRA integrato.
- *Nota di compatibilità*: SealFrame può anche **affiancare** un OS A/B (RAUC/Mender per kernel/OS, SealFrame per modelli AI multi-GB, configurazioni e stato applicativo/SQLite!).

### Q3: *"Perché non `rsync` su SSH o `curl` + script bash?"*
- `rsync` e `curl` sono **strumenti di trasporto**, non sistemi di distribuzione sicura:
  - Nessuna catena di fiducia **Multi-Sig 2-su-3**, nessuna protezione anti-downgrade/anti-freeze (`serial` monotono + `expires_unix`), nessuna lista permanente di revoca (`FP_ACTION_REVOKE`).
  - Nessuna verifica Merkle per chunk da 16 KiB prima della scrittura su disco (su `curl`, un file corrotto da 10 GB viene scoperto solo dopo averlo scaricato tutto).
  - Su file identici (No-Op 32 MiB), `FP-NET REF` ha misurato **`22.7 ms` e `511 B`** contro **`627 ms` e `75,5 KiB`** di `rsync --checksum` (**22× più veloce, 147× meno banda**).
  - Inoltre `rsync` è sotto licenza **GPLv3** (incompatibile con l'embedding statico in firmware proprietari).

### Q4: *"Come possiamo fidarci di un software C chiuso in ambito critico?"*
Offriamo quattro livelli verificabili di fiducia istituzionale senza esporre la proprietà intellettuale pubblica:
1. **Verifica binaria indipendente sul pacchetto ricevuto**: `make security-check` / `readelf` dimostra PIE, Full RELRO, NX, Stack Canary e `_FORTIFY_SOURCE=3` direttamente sul binario consegnato.
2. **SBOM CycloneDX 1.5 automatico** (`sbom.cdx.json`) con SHA-256 esatti dei binari e delle 4 dipendenze permissive (zero GPL).
3. **Evidenze SDLC riproducibili**: 8 suite di test, Clang 23 + GCC 16 `-Werror -pedantic`, ASan/UBSan e **10.263.534 esecuzioni coverage-guided `libFuzzer`** (`0` crash, `0` leak).
4. **Audit di terza parte sotto NDA** *(previsto al gate `v1.0`)* + **Source Code Escrow** contrattuale per clienti Enterprise.

### Q5: *"Cosa succede se va via la rete o la corrente a metà aggiornamento?"*
- **Caduta di rete**: `FP-NET` TCP e `HTTP/1.1 206 Range` mantengono i chunk già verificati in `staging/` e riprendono esattamente dal chunk successivo (verificato fisicamente con `kill -9` a 134 MiB su LAN Proxmox: **8.529 chunk saltati**, `0` byte corrotti).
- **Crash di processo (`SIGKILL`)**: tutti i file sono scritti in una directory di generazione isolata con `fsync()`, la transazione SQLite è in modalità `WAL FULL` e il puntatore `current` cambia con una singola `rename()` atomica POSIX. Verificato con **10 `SIGKILL` consecutivi** su HDD meccanico (`0` stati corrotti).
- **App rotta dopo il deploy**: `--health-cmd` con watchdog `SIGKILL` rileva il guasto o il blocco ed esegue automaticamente `fp_bundle_rollback()` ripristinando file + DB SQLite alla versione precedente.

### Q6: *"Cosa succede se la chiave di firma CI/CD viene rubata?"*
- La chiave di rilascio (`rel.sk`) **non può modificare la fiducia Root**.
- Due custodi su tre firmano offline un nuovo documento `root.fpr` (`version + 1`) che **revoca permanentemente** la chiave compromessa e delega una nuova chiave di rilascio.
- Ogni agente verifica la rotazione con doppio quorum (`fp_root_verify_rotation`) e da quel momento respinge per sempre qualsiasi pacchetto firmato dalla chiave rubata (`FP_ERR_REVOKED`).

### Q7: *"Qual è lo stato di maturità reale oggi (`v0.5.1`) vs la `v1.0.0` certificata?"*
Massima trasparenza tecnica (nessuna promessa non verificata):
- **Già verificato su hardware reale (`x86_64`)**: tutte le funzionalità core, il `.deb` da 144 KB installato su Debian 13 Proxmox (256 MiB RAM, Pentium P6100, HDD), trasferimento 512 MiB con 5,86 MiB RAM, rollout autonomo `systemd` con rollback, 10,26M esecuzioni `libFuzzer`.
- **Ancora da eseguire prima della marcatura CE `v1.0.0`**:
  1. Validazione fisica su silicio **ARM64** (es. Raspberry Pi / NVIDIA Jetson / NXP i.MX del cliente pilota).
  2. Test di **power-cut hardware/kernel (`dm-flakey` / QEMU hard power-off)** sui filesystem specifici del cliente (`ext4`, `Btrfs`, `XFS`).
  3. **Penetration test / audit crittografico indipendente** di laboratorio esterno sotto NDA e firma legale della Dichiarazione di Conformità UE (EU DoC).

---

## 3. Riepilogo Prestazioni Reali Misurate (Estratto Certificabile)
- **Server 512 MiB su container da 256 MiB RAM (Pentium P6100 HDD)**: `29,8 MiB/s`, Peak RSS server **`5,86 MiB`**, `SHA-256` bit-exact.
- **UDP cifrato `FP-UDP1` su Wi-Fi↔Ethernet (32 MiB)**: `18,2 MiB/s`, `0` ritrasmissioni, `srtt=4,21 ms`, Peak RSS server **`3,30 MiB`**.
- **Rollout autonomo `systemd` (`sealframe-agent.service`)**: `0,5 MiB` RSS idle, `11,5 MiB` cgroup peak, `154 B` scaricati per patch config con modello AI da 2 MiB già residente, rollback automatico completato in `< 0,9 s` su HDD meccanico (`55 ms` su NVMe).
- **Fuzzing `libFuzzer + ASan + UBSan`**: `10.263.534` input guidati da copertura (`641k exec/s`), `0` crash / `0` UB / `0` leak.
