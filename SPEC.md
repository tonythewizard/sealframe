# SealFrame (`sf`) — Wire & Contract Specification v1.0-rc1

> *"Universal by nature, materialized by context, verified by math."*

Questa specifica congela i contratti binari del nucleo **SealFrame (`libsealframe` / `bin/sf`)** al termine della fase di laboratorio M0–M7. Tutti gli interi multi-byte sono **big-endian**, tutti gli hash usano **BLAKE3-256** con *domain separation* esplicita, tutte le firme usano **Ed25519**, e tutta la crittografia di trasporto usa **X25519 + XChaCha20-Poly1305** (`libsodium`).

---

## 1. Identità Canonica (`DNA`, 32 byte)
Albero di Merkle binario bilanciato a sinistra (stile RFC 6962) su blocchi fissi da **16 KiB** (`FP_CHUNK_SIZE = 16384`):
- Foglia $i$: `BLAKE3("FP1/LEAF\0" || u64(i) || u32(len) || chunk_bytes)`
- Nodo interno: `BLAKE3("FP1/NODE\0" || left_32 || right_32)`
- Vuoto (`len = 0`): `root = BLAKE3("FP1/EMPTY\0")`
- **DNA**: `BLAKE3("FP1/DNA\0" || u64(total_size) || root_32)`

Garantisce: streaming $O(\log N)$ in RAM, prove di inclusione per singolo blocco da 16 KiB e velocità multi-GiB/s.

---

## 2. Formati Binari del Core

| Magic | Nome | Scopo |
|---|---|---|
| `FP01` | **Morph Frame** | Trasporta un atomo in forma `RAW (0)`, `ZSTD (1)`, `DELTA (2)`, `REF (3)` o `COMPUTE (4)` vincolato a `dna` (32 B) + `ref_dna` opzionale (32 B). Verifica fail-closed prima della consegna. |
| `FPE1` | **Signed Event** | Catena lineare di stato (`INSTALL`, `ROLLBACK`, `REVOKE`) con `repo_id`, `serial = prev + 1`, `prev_event_hash`, `expires_unix` anti-freeze, firma Ed25519 su `"FP1/EVENT\0"`. |
| `FPD1` | **Derivation** | Attestazione crittografica `parent_dna + op_dna -> result_dna` (`parent != result`) firmata Ed25519 su `"FP1/DERIVE\0"`. |
| `FPC1` | **FastCDC Recipe** | Ricetta cross-file di chunk content-defined (4–64 KiB, media ~20 KiB, `FP1/CHUNK\0`) che ricostruisce in streaming $O(1)$ RAM l'esatto `DNA` canonico. |
| `FPB1` | **Particle Bundle** | Transazione composita atomica: lega insieme `FP_ROLE_FILE (1)` e `FP_ROLE_SQLITE_CHANGESET (2)` sotto un unico `DNA` radice con commit atomico e rollback simultaneo (`sqlite3changeset_invert`). |
| `FPR1` | **Root Trust Doc** | Gerarchia TUF-style multi-sig $k$-of-$n$ Ed25519 (fino a 8 chiavi root), rotazione dual-quorum (`vN -> vN+1`), revoca monotonica delle chiavi `release` compromesse. |
| `FPN1` | **Encrypted TCP** | Handshake 1-RTT X25519 + Ed25519 (PFS), AEAD XChaCha20-Poly1305, negoziazione autonoma (`REF`/`DELTA`/`ZSTD`/`MERKLE_STREAM`), resume al singolo chunk, sessioni persistenti (`fp_session_*`) e Swarm multi-peer. |
| `FPU1` | **Encrypted UDP** | Trasporto UDP MTU-safe (< 1280 B), AEAD XChaCha20-Poly1305, selective fragment ARQ, instradamento per `session_id` (64 bit) per **connection migration** trasparente. |
| `SFT1` | **Verified Tensor** | Frame tensore / KV-slice (header 32 B: `dtype`, `ndim` 1–4, `flags`, `dims[4]`, `seq_id`) con quantizzazione IEEE-754 FP32↔FP16 in C11 puro su `fp_session_*` (inferenza distribuita/mista a bassa latenza). |

---

## 3. Interfaccia Opzionale di Transparency Anchor (`FP1/ANCHOR\0`)
Il core ha **zero dipendenze esterne**. L'eventuale ancoraggio off-path su un transparency log locale o esterno usa un singolo commitment da 32 byte:
`BLAKE3("FP1/ANCHOR\0" || repo_id || u64(serial) || event_hash || target_dna)`.
