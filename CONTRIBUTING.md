# Contributing to SealFrame™

Thank you for your interest in contributing to SealFrame™!

## Engineering Standards
- **C11 (POSIX/Linux)** in `src/`, `include/`, and `integrations/llama_cpp/` (zero C++, zero Python runtime dependencies, zero OpenSSL, zero `libcurl`; minimal C libraries: `libsodium`, `libzstd`, `libsqlite3`, optional `libblake3`).
- Must compile cleanly with both **GCC** and **Clang** under `-Wall -Wextra -Werror -pedantic`.
- Every PR must pass:
  ```bash
  make all test security-check sbom
  ./bin/sf-llama-bridge --selftest --transport udp --cast int8 --fec auto --logits-topk 64 --drop 2
  ```

## Contributor License Agreement (CLA) & Dual-Licensing Notice

Because SealFrame™ is distributed under a **dual license** (**GNU AGPL-3.0** and a **Commercial License** — see [`LICENSE`](LICENSE) and [`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md)), **all external contributions require an explicit Dual-License CLA grant** (a DCO `Signed-off-by` alone is not sufficient for commercial relicensing).

By submitting a Pull Request, patch, or other contribution to this repository, you agree to the following CLA with the SealFrame project copyright holder (`tonythewizard`, contact `tonyswagcard@gmail.com`):

1. **Originality & Authority:** Your contribution is your original work or you hold sufficient rights to submit it under these terms.
2. **Dual-License Grant:** You grant the SealFrame copyright holder a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright and patent license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute your contribution under **both** GNU AGPL-3.0 and any commercial license offered for SealFrame™.
3. **Attribution:** You retain copyright ownership of your contribution and remain credited in Git history.

*(Optional: you may also sign off commits with `git commit -s` for traceability.)*
