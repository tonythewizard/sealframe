# SealFrame (`sf`) — Guida al Battesimo Fisico su 2 Host Reali

Questa guida permette di testare **SealFrame** tra **due macchine fisiche reali** (es. PC Linux `x86_64` ↔ Raspberry Pi / NVIDIA Jetson `ARM64` / VPS remota su Wi-Fi, 4G o WAN).

> **Onestà metodologica**: tutti i benchmark presenti finora sono su singolo host `x86_64`. Le misure reali di latenza WAN, packet loss fisico, NAT/firewall, clock indipendenti e architettura `ARM64` iniziano qui.

---

## 1. Prerequisiti su entrambi gli host (Debian/Ubuntu/Raspberry Pi OS o Arch)

- **Debian / Ubuntu / Raspberry Pi OS (ARM64/x86_64)**:
  ```bash
  sudo apt update && sudo apt install -y build-essential pkg-config libblake3-dev libsodium-dev libzstd-dev libsqlite3-dev
  ```
- **Arch Linux**:
  ```bash
  sudo pacman -S --needed base-devel pkgconf blake3 libsodium zstd sqlite
  ```

---

## 2. Scompattazione, verifica integrità e build nativa

Copia `build/physical-kit/sealframe-kit.tar.gz` sull'Host B (es. via `scp` o USB), poi su **entrambi** gli host:

```bash
tar -xzf sealframe-kit.tar.gz
cd sealframe-kit
sha256sum -c SHA256SUMS
make && make test
```

*(Facoltativo: `CC=clang make clean all test` per verificare anche con Clang.)*

---

## 3. Test 1 — Trasferimento cifrato + Delta autonomo (TCP `FP-NET v1`)

**Su Host A (Server, IP es. `192.168.1.10`)**:
```bash
./bin/sf keygen srv.key srv.pub
# Copia srv.pub su Host B e cli.pub da Host B su Host A
./bin/sf put ./srv_store file_v1.bin     # annota DNA1
./bin/sf put ./srv_store file_v2.bin     # annota DNA2
./bin/sf serve ./srv_store --bind 0.0.0.0 --port 7777 --key srv.key --allow-pub cli.pub
```

**Su Host B (Client, es. ARM64 / 4G)**:
```bash
./bin/sf keygen cli.key cli.pub
# 1) Primo pull (negozia ZSTD o Merkle Stream)
./bin/sf pull 192.168.1.10:7777 <DNA1> ./cli_store --key cli.key --peer-pub srv.pub
# 2) Secondo pull identico (negozia REF -> ~511 byte totali!)
./bin/sf pull 192.168.1.10:7777 <DNA1> ./cli_store --key cli.key --peer-pub srv.pub
# 3) Pull di v2 avendo v1 (negozia DELTA autonomamente!)
./bin/sf pull 192.168.1.10:7777 <DNA2> ./cli_store --key cli.key --peer-pub srv.pub --ref <DNA1>
```

---

## 4. Test 2 — Caduta fisica di rete + Resume Merkle a 16 KiB

1. Avvia `./bin/sf pull 192.168.1.10:7777 <DNA_GRANDE> ./cli_store --key cli.key --peer-pub srv.pub --stream`.
2. **Stacca fisicamente il cavo Ethernet / spegni il Wi-Fi** a metà trasferimento.
3. Riattacca la rete e rilancia lo **stesso identico comando**: verifica `resumed_chunks > 0` nell'output e `cmp` bit-exact del file finale!

---

## 5. Test 3 — UDP Cifrato su Wi-Fi / 4G + Connection Migration

**Su Host A**:
```bash
./bin/sf udp-serve ./srv_store --bind 0.0.0.0 --port 7778 --key srv.key
```
**Su Host B**:
```bash
./bin/sf udp-pull 192.168.1.10:7778 <DNA_GRANDE> ./cli_store --key cli.key --peer-pub srv.pub
```

---

## 6. Cosa registrare
Annota per ogni prova: architetture (`uname -m`), rete reale (LAN / Wi-Fi / 4G / WAN), RTT (`ping`), dimensione file, `mode`, `wire`, `elapsed_ms`, `resumed_chunks`, e confronto con `rsync --checksum` sullo stesso link.
