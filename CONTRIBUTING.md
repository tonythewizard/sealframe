# Contributing to SealFrame™

Thank you for your interest in contributing to SealFrame™!

## Engineering Standards
- **100% Pure ISO C11** in `src/`, `include/`, and `integrations/llama_cpp/` (zero C++, zero Python runtime dependencies, zero OpenSSL, zero `libcurl`).
- Must compile cleanly with both **GCC** and **Clang** under `-Wall -Wextra -Werror -pedantic`.
- Every PR must pass:
  ```bash
  make all test security-check sbom
  ./bin/sf-llama-bridge --selftest --transport udp --cast int8 --fec auto --logits-topk 64 --drop 2
  ```

## Contributor License Agreement (CLA) & Dual-Licensing Notice

Because SealFrame™ is distributed under a **dual license** (**GNU AGPL-3.0** and a **Commercial License** — see [`LICENSE`](LICENSE) and [`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md)), **all external contributions must include explicit permission for dual-licensing**.

By submitting a Pull Request, patch, or other contribution to this repository, you certify and agree that:

1. **Originality / Authority (Developer Certificate of Origin):** Your contribution is your original work (or you have the full legal right to submit it under these terms).
2. **Grant of Copyright & Patent License:** You grant the SealFrame Authors a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright and patent license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute your contribution under **both** the GNU AGPL-3.0 and any commercial or alternative license chosen by the SealFrame Authors.
3. **Attribution:** You retain copyright ownership of your contribution and will be credited in the repository history.

Please sign off all commits with `git commit -s` (`Signed-off-by: Your Name <email>`).
