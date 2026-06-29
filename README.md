# WTAS — Weighted Threshold Accountable Signatures

> A pairing-free weighted threshold signature scheme with signer accountability for blockchains.
> Implemented in Rust with an on-chain Solana DAO wallet demo.

## Overview

WTAS is a generic, lightweight, pairing-free Weighted Threshold Accountable Signature scheme. It supports
arbitrary signer weights and thresholds, compresses accountability proofs to O(log n) via Bulletproofs IPA
with Super Basis Injection, and defends against ROS attacks through a dual-nonce binding mechanism.

The protocol produces a standard Ed25519-compatible aggregate signature, enabling native on-chain
verification via Solana's Ed25519 precompile.

**Key features:**
- **Weighted thresholds** — arbitrary integer weight per signer
- **Accountability** — ElGamal encryption on Ristretto with precise post-dispute trace
- **Anti-ROS** — dual-nonce + binding factors defeat rogue-key and concurrency attacks
- **Succinct NIZK** — Bulletproofs IPA compresses proof from O(n) to O(log n), transparent setup
- **Pairing-free** — native compatibility with secp256k1, Ed25519; no trusted setup required

## Protocol

| Phase | What happens |
|-------|-------------|
| **Setup** | Generate Ed25519 signing keys + Ristretto ZK keys for N signers with weights |
| **PSign** | Two-round: (1) dual nonces `(r_i, e_i)`, (2) weighted partial sigs `s_i = r_i + e_i·ρ_i + c·w_i·sk_i` |
| **Combine** | Aggregate sigs, generate ElGamal ciphertexts, produce Bulletproofs NIZK proof |
| **Verify** | `[s_agg]·B ≟ R_eff + [c]·K_agg` — standard Ed25519 form, on-chain verifiable |
| **Trace** | Tracer decrypts ElGamal ciphertexts: `M_i = V_i − tsk·U_i`, identifies exact signer set |

## Repository Structure

```
├── schemes/              # Protocol implementations
│   ├── wtas.rs           # WTAS (our scheme) — dual-nonce + ElGamal trace + NIZK
│   ├── virtual_frost.rs  # Weighted FROST via virtualization (timing benchmark)
│   ├── wts_das.rs        # WTS/Das et al. BLS12-381 (timing benchmark)
│   ├── taps.rs           # TAPS/Boneh-Komlo (timing benchmark)
│   ├── schnorr.rs        # Schnorr/BIP-340 single-signer baseline
│   └── pr_taps.rs        # Ed25519 single-signer baseline
├── zk/                   # Bulletproofs NIZK proof system (prove + 3 verify modes)
├── cli/                  # Solana DAO wallet — end-to-end demo
├── time/                 # Fig 1 comprehensive performance comparison
├── programs/aggtest/     # Solana on-chain program (DAO wallet with PDA treasury)
├── tests/                # TypeScript integration tests
└── ecc_scalar/           # Low-level EC scalar multiplication benchmarks
```

## Quick Start

### Prerequisites
- Rust 1.75+ with `cargo`
- (Optional) Solana CLI + Anchor framework, local test validator (for on-chain demo)

### Tests

```bash
# 20 unit tests covering setup, sign, verify, trace, weight update, ElGamal
cargo test --bin schemes --release

# 7 NIZK proof system tests (prove, normal/fast/consistency verify, tamper detection)
cargo test --lib -p zk --release
```

### WTAS Full Protocol Benchmark

```bash
cargo run --release --bin schemes -- wtas 32 100
```

Outputs every protocol phase: setup, round1 (dual nonces), coordination (Bctx),
round2 (partial sigs), verify, combiner endorsement verify, ElGamal encryption,
NIZK prove (µs + bytes), NIZK verify, trace (decrypt), weight update, communication cost.

### Figure 1 — Performance Comparison

```bash
cargo run --release --bin time -- fig1 --sizes "8,16,32,64,128" --iters 100
```

Outputs CSV comparing WTAS, V-FROST (virtualization), WTS/Das (BLS12-381 pairing),
and TAPS (equal-weight) across sign, verify, and communication metrics.

### On-Chain DAO Wallet Demo

```bash
# Terminal 1: start local validator
solana-test-validator

# Terminal 2: deploy and run
anchor deploy
cargo run --release --bin cli
```

The CLI executes 8 steps:
1. Generate 8 weighted signers via WtasGroup
2. Generate Bulletproofs NIZK proof (672 bytes, O(log n))
3. Build canonical DAO message with ZK hash commitment
4. Dual-nonce signing + Combiner endorsement σ_C
5. Local verification (Ed25519 equation + Combiner sig)
6. On-chain CreateProposal + fund treasury
7. On-chain ExecuteProposal with Ed25519 precompile verification
8. Accountability trace — decrypt ElGamal ciphertexts, output binary participation vector

## Performance (n=32, 120 total weight)

| Metric | WTAS | V-FROST | WTS/Das | TAPS |
|--------|------|---------|---------|------|
| Sign | **163 µs** | 1,149 µs | 5,001 µs | 320 µs |
| Verify | **37 µs** | 39 µs | 590 µs | 53 µs |
| Communication | 2,720 B | 5,760 B | **96 B** | 5,536 B |
| Proof size | 672 B (O(log n)) | — | — | 3,424 B (O(n)) |

WTAS achieves the fastest signing and verification among pairing-free schemes, with
communication cost 2.1× less than V-FROST and 2× less than TAPS.

## Paper Reference

```bibtex
@inproceedings{cui2026wtas,
  title     = {Efficient and Practical Weighted Threshold Signatures for Blockchains},
  author    = {Jie Cui and Yuhang Liu and Lu Wei and Ru Li and Jing Zhang and Hong Zhong},
  booktitle = {ESORICS},
  year      = {2026}
}
```

## Reproducibility

- Use `--release` mode (LTO enabled, single codegen unit)
- Pin CPU frequency: `cpupower frequency-set -g performance` (Linux)
- Run each benchmark ≥100 iterations, take minimum (as recommended in the paper)
- Use consistent hardware for comparisons
