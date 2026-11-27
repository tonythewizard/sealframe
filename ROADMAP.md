# SealFrame (`sf`) — Roadmap verso la v1.0

> **Principio guida**: *Sogna come un fisico teorico, taglia come un artigiano Unix, misura senza mentire mai.*
> Ogni milestone produce codice C11 reale, testato con ASan/UBSan, misurato e privo di dipendenze superflue. (L'adattatore di transparency log esterno resta intenzionalmente separato dal core.)

---

## M0 — Il Nucleo Indivisibile (`FP01 Core`) — COMPLETATA
- [x] **DNA 32B** BLAKE3 + Merkle Tree streaming a blocchi da 16 KiB (~2.9 GiB/s) + prove/verifica per chunk.
- [x] **Morph Engine** (`RAW`, `ZSTD` con `CCtx`/`DCtx` riusati, `DELTA` con `refPrefix` + LDM fino a 128 MiB, `REF` 0B payload, `COMPUTE` deterministico) + fallback `RAW` fail-closed.
- [x] **Lineage** binario firmato Ed25519 (`INSTALL`, `ROLLBACK`, `REVOKE`), scadenza anti-freeze, derivazioni `A + Op -> B`.
- [x] **Store atomico crash-safe** (`flock` + temp + `fsync` + `rename` + `fsync(dir)`).
- [x] CLI `bin/sf` (57 KB), `make test`, `make test-asan`, `make bench`.

---

## M1 — Il Campo di Rete & Negoziazione Autonoma (`FP-NET v1`) — COMPLETATA
*La particella esce dal singolo computer, parla sul filo di rete e sceglie da sola la forma migliore in 1 RTT.*

- [x] **Trasporto cifrato & mutua autenticazione stile WireGuard** (`src/net.c`: X25519 effimero + firme Ed25519 + XChaCha20-Poly1305 AEAD, zero certificati X.509, PFS).
- [x] **Negoziazione autonoma (`WANT → OFFER → STREAM`)**: `REF` (511 B totali), `DELTA` (4.00 MiB → 4,661 B cifrati), `ZSTD`, o **resume parziale per chunk**.
- [x] **Merkle Verified Streaming $O(K)$ + Resume a granularità di 16 KiB** (`fp_merkle_tree_t` in `src/dna.c`): **356.6 MiB/s** su TCP cifrato (11.2 ms per 4 MiB), verifica crittografica di ogni blocco prima di toccare il disco, `fsync` ammortizzato ogni 1 MiB.
- [x] **CLI**: `fp put`, `fp serve` e `fp pull` (`bin/sf` = 83 KB).
- [x] **Gate M1**: test MITM/pinning, ZSTD/REF/DELTA autonomi, drop TCP al chunk 20 + resume esatto (20 saltati + 44 ricevuti), corruzione 1 bit in volo rigettata istantaneamente al chunk #7, ASan/UBSan 0 errori.

---

## M2 — Cross-File FastCDC & Composizione Cross-File (`FastCDC + Chunk Index`) — COMPLETATA
*La particella riconosce e riusa materia già esistente anche dentro file completamente diversi.*

- [x] **FastCDC normalizzato in C11** (`src/cdc.c`): **4,878.6 MiB/s (~4.9 GiB/s)** di taglio puro, media ~20 KiB, tabella Gear generata deterministicamente da BLAKE3.
- [x] **Streaming single-pass a RAM costante $O(1)$** (`fp_dna_stream_t` + finestra scorrevole fissa da 128 KiB): calcola contemporaneamente DNA canonico 16 KiB Merkle e chunk FastCDC in un solo passaggio su file di dimensione arbitraria.
- [x] **Chunk Pool sharded (`chunks/<aa>/<id>`) + Ricetta `FPC1`**:
  - Shift +251 B in testa a 16 MiB random incomprimibili → **99.79% riusato** (818/819 chunk, solo 1 nuovo chunk!) a **884.2 MiB/s**.
  - Composizione cross-file (`Z` costruito da fette di `X` + `Y` estranei) → **90.91% già presente**.
  - Ricostruzione verificata (per-chunk ID + DNA radice canonico) a **921.6 MiB/s**.
- [x] **CLI**: `fp ingest` e `fp reconstruct` (`bin/sf` = 92 KB).
- [x] **Gate M2**: ASan/UBSan 0 errori, corruzione 1 bit su chunk rigettata atomicamente senza lasciare file parziali, CLI E2E 100% PASS.

---

## M3 — Transizioni di Stato Composte (`Particle Bundle`: File + SQLite + AI State) — COMPLETATA
*La caratteristica davvero unica: aggiornare o fare rollback di file, modelli e database come UNA sola particella atomica.*

- [x] **Formato `FPB1` (Particle Bundle)** (`src/bundle.c`): un unico `DNA` radice che lega più atomi eterogenei (`FP_ROLE_FILE` + `FP_ROLE_SQLITE_CHANGESET`), con validazione rigorosa anti path-traversal e anti-iniezione `_fp_progress`.
- [x] **Adapter nativo C SQLite Session (`fp_sql_ctx_t`)**: connessione WAL persistente + prepared statements cached, `sqlite3session_changeset`, `sqlite3changeset_apply`, digest logico deterministico BLAKE3 (`fp_sql_state_digest`), e **rollback completo con `sqlite3changeset_invert()`**.
- [x] **CLI**: `fp bundle-pack`, `fp bundle-apply`, `fp bundle-rollback` (`bin/sf` = **114 KB**).
- [x] **Gate M3**: test `fork()` + `raise(SIGKILL)` reale prima del `COMMIT` SQLite → 0 file parziali, 0 righe parziali (100% v1 intatto); replay idempotente verificato; rollback full-stack v2 → v1 bit-exact sia sui file che sullo stato logico SQLite; ASan/UBSan 0 errori.
  - Benchmark su `/tmp`: capture **25 µs**, atomic apply **91 µs**, full-stack rollback **89 µs**.

---

## M4 — Sicurezza da Standard Industriale (`Multi-Sig, Key Rotation, Fuzzing`) — COMPLETATA
*Portare la sicurezza al livello di TUF/Uptane mantenendo la semplicità di un binario C.*

- [x] **Gerarchia di chiavi `FPR1` (`src/trust.c`)**: `Root` multi-sig $k$-of-$n$ Ed25519 (fino a 8 chiavi root) → `Release` online ruotabile e revocabile senza rompere la catena dello Store (`fp_store_apply_event_with_root`).
- [x] **Regola Dual-Quorum TUF + Revoca Monotonica**: ogni rotazione `vN → v(N+1)` esige sia il vecchio quorum che il nuovo quorum e impedisce di de-revocare chiavi compromesse o fare downgrade.
- [x] **CLI**: `fp root-init` e `fp root-verify [--prev]` (`bin/sf` = **123 KB**).
- [x] **Gate M4 (Fuzzing + ASan/UBSan)**:
  - **100.000 input mutati sotto ASan + UBSan** su tutti e 6 i decoder (`FP01`, `FPE1`, `FPD1`, `FPB1`, `FPR1`, `Merkle`) in **0.573 s** (174k exec/s) → **0 crash, 0 UB, 0 leak**.
  - **1.000.000 input mutati `-O3`** (`make fuzz`) in **5.611 s** (178k exec/s) → **0 crash, 0 leak**.

---

## M5 — Multi-Peer Verified Swarm & Trasporto UDP Cifrato (`FP-UDP1`) — COMPLETATA
*Velocità moderna su reti ostili e scaricamento verificato da fonti multiple non fidate.*

- [x] **Multi-Peer Parallel Verified Swarm (`src/swarm.c`)**: download parallelo fino a 16 peer (anche *non fidati*, ancorati solo al `DNA` 32B via Merkle proof su ogni chunk da 16 KiB prima di `pwrite`), **ban istantaneo dei peer bizantini/avvelenati** e riassegnazione automatica ai peer onesti.
  - Benchmark 3-Peer Swarm (4 MiB): **393.9 MiB/s** (`10.16 ms`).
- [x] **Trasporto UDP Cifrato stile WireGuard (`src/udp.c`, `FP-UDP1`)**: zero nuove dipendenze, datagrammi MTU-safe (< 1280 B) XChaCha20-Poly1305, selective fragment NACK/ARQ senza head-of-line blocking, e **connection migration** instradata su `session_id` (cambio porta/socket live senza rifare l’handshake!).
  - Benchmark UDP cifrato (4 MiB): **197.4 MiB/s** (0% loss), **41.7 MiB/s** (5% packet loss, `95.9 ms`).
  - Test 10% packet loss + migrazione live di socket/porta a metà trasferimento (512 KiB): **15.71 ms**, `retrans=31`, `migrations=1`, 100% bit-exact.
- [x] **CLI**: `fp swarm-pull`, `fp udp-serve`, `fp udp-pull` (`bin/sf` = **148 KB**).
- [x] **Gate M5**: ASan/UBSan 0 errori, 0 leak, peer avvelenato bannato al primo chunk corrotto, 10% loss + migrazione live 100% PASS.

---

## M6 — Chaos Testing, Portabilità Dual-Compiler & Physical Two-Host Kit — COMPLETATA (Local Verified / Kit Pronto per 2° Host Fisico)
*Nessun software fa la storia su `127.0.0.1`: prima lo massacriamo col caos in locale, poi lo portiamo su 2 macchine fisiche reali.*

- [x] **Portabilità C11 rigorosa (`-std=c11 -O3 -Wall -Wextra -Werror -pedantic`)**: verificata identica su **GCC 16.2** e **Clang 23.1** (`make test-clang`), zero intrinsics x86, serializzazione big-endian esplicita ovunque.
- [x] **Chaos Testing (`tests/test_chaos.c`) + ASan/UBSan 0 errori**:
  - 10 crash consecutivi `SIGKILL` reale su Bundle composito (File + SQLite WAL) → **0 corruzioni**.
  - 4 blackout TCP ripetuti (`0→5→17→41→64` chunk) → **resume bit-exact**.
  - **25% packet loss UDP + migrazione live socket/porta** → recupero pulito in **18.03 ms**.
  - **Bit-rot silenzioso su disco** (`objects/` e `state.bin`) → rilevato fail-closed al 100%.
- [x] **Benchmark comparativo onesto (`make compare`, 8 MiB single-host x86_64)**: `sf` vs `sha256sum`, `zstd 1.5.7`, `zstd --patch-from`, `rsync 3.5.2 --checksum` (delta 8 MiB in **4,407 B cifrati**; FastCDC su 8 MiB random shiftati **99.63% riusato in 9.42 ms**).
- [x] **Physical Two-Host Kit pronto (`make physical-kit`)**: archivio verificato `build/physical-kit/sealframe-kit.tar.gz` (~83 KB) + guida passo-passo in [PHYSICAL_TEST_GUIDE.md](PHYSICAL_TEST_GUIDE.md). *(Esecuzione fisica reale su 2° host / ARM64 resta esplicitamente da fare sulle tue macchine fisiche.)*

---

## M7 — Il Momento Redis (`v0.1.0` / `SPEC v1.0-rc1`: `libsealframe.so`, Binding, Ecosistema) — COMPLETATA
- [x] **Libreria condivisa + pkg-config (`build/libsealframe.so`, `build/libsealframe.a`, `build/libsealframe.pc`)** + target `make install` / `make uninstall`.
- [x] **Binding Python zero-dipendenze** ([bindings/python/sealframe.py](bindings/python/sealframe.py)) + esempi da 15 righe in C ([examples/c_quickstart.c](examples/c_quickstart.c)) e Python ([examples/py_quickstart.py](examples/py_quickstart.py)).
- [x] **Specifica consolidata** ([SPEC.md](SPEC.md) `v1.0-rc1`) + [README.md](README.md) da 60 secondi.
- [x] **Roadmap completa dal laboratorio al prodotto finale e alla storia**: [ROADMAP_WORLD.md](ROADMAP_WORLD.md).
- [x] **Repository Git pulita** pronta per sviluppo pubblico e battesimo fisico su 2 host.
