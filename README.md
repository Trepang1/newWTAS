# WTAS — Weighted Threshold Accountable Signatures

> An efficient, pairing-free weighted threshold signature scheme with signer accountability for blockchains.

WTAS supports arbitrary weights and thresholds, compresses Zero-Knowledge accountability proofs to O(log n), and resists ROS attacks via a dual-nonce binding mechanism. Implemented in Rust on Solana.

## Protocol Overview

| Phase | Description |
|-------|-------------|
| **Setup** | Generate Ed25519 signing keys + Ristretto ZK keys for N signers with weights |
| **PSign** | Two-round signing with dual nonces `(r_i, e_i)` and binding factors `ρ_i` |
| **Combine** | Aggregate partial signatures, generate ElGamal ciphertexts + Bulletproofs NIZK proof |
| **Verify** | Ed25519 equation check + Combiner endorsement verification |
| **Trace** | Tracer decrypts ElGamal ciphertexts to identify exact signer set (accountability) |

### Signature Equation

```
s_i = r_i + e_i·ρ_i + c·w_i·sk_i
R_eff = Σ(R_i + [ρ_i]E_i)
[s_agg]·B ≟ R_eff + [c]·K_agg
```
Where `c = SHA-512(R_eff || K_agg || msg)` — standard Ed25519 format, on-chain verifiable.

### Key Features

- **Weighted Thresholds**: Each signer has an arbitrary weight `w_i`, threshold `t` in weight units
- **Accountability**: ElGamal encryption on Ristretto → Tracer can provably identify signers post-dispute
- **Anti-ROS**: Dual-nonce mechanism with binding factors prevents rogue-key and concurrent attacks
- **Succinct NIZK**: Bulletproofs IPA with Super Basis Injection compresses proof to O(log n)
- **Pairing-Free**: Native compatibility with secp256k1 (Bitcoin/Ethereum) and Ed25519 (Solana)

## Repository Structure

```
├── schemes/              # Protocol implementations and benchmarks
│   ├── wtas.rs           # WTAS protocol — dual-nonce signing + ElGamal trace
│   ├── virtual_frost.rs  # Weighted FROST via virtualization (O(Σw))
│   ├── wts_das.rs        # WTS Das et al. (BLS12-381, pairing-based)
│   ├── taps.rs           # TAPS Boneh-Komlo (equal-weight, Sigma NIZK)
│   ├── schnorr.rs        # Schnorr/BIP-340 baseline
│   └── pr_taps.rs        # Ed25519 baseline
├── zk/                   # Bulletproofs NIZK proof system
│   ├── lib.rs            # Core IPA prover/verifier with Super Basis Injection
│   └── main.rs           # Proof system demo
├── cli/                  # Solana DAO wallet — end-to-end demo
│   └── main.rs           # Full flow: setup → sign → verify → ZK → trace
├── time/                 # Fig 1 comprehensive benchmarks
├── programs/aggtest/     # Solana on-chain program (DAO wallet)
└── tests/                # TypeScript integration tests
```

## Quick Start

### Prerequisites
- Rust 1.75+ with `cargo`
- (Optional, for on-chain) Solana CLI + Anchor framework, local test validator

### 1. Run All Tests

```bash
cargo test --bin schemes --release        # 20 unit tests
cargo test --lib -p zk --release          # 7 NIZK proof tests
```

### 2. Full Protocol Benchmark (WTAS)

```bash
cargo run --release --bin schemes -- wtas 32 100
```

Outputs every protocol phase with timings:
```
setup, round1 (dual nonces), coordination (Bctx), round2 (partial sig),
TOTAL sign, verify, combiner verify, ElGamal enc, NIZK prove,
NIZK verify, trace (decrypt), weight_update, communication cost
```

### 3. Figure 1 — Four-Scheme Comparison

```bash
cargo run --release --bin time -- fig1 --sizes "8,16,32,64,128" --iters 100
```

Compares WTAS vs V-FROST vs WTS/Das vs TAPS across sign/write/verify/communication.

### 4. NIZK Proof Demo

```bash
cargo run --release --bin zk
```

### 5. On-Chain DAO Wallet Demo

```bash
# Terminal 1: Start local Solana validator
solana-test-validator

# Terminal 2: Deploy and run
anchor deploy
cargo run --release --bin cli
```

The CLI executes the complete flow:
1. **Setup** — Generate 8 weighted signers
2. **NIZK Proof** — Bulletproofs IPA (672 bytes, O(log n))
3. **Canonical Message** — DAO proposal with ZK hash commitment
4. **Signing** — Dual-nonce protocol + Combiner endorsement σ_C
5. **Local Verification** — Ed25519 equation + Combiner sig check
6. **Tx1** — On-chain CreateProposal + SetNonceAndChallenge
7. **Tx2** — On-chain ExecuteProposal with Ed25519SigVerify precompile
8. **Accountability Trace** — Tracer decrypts ElGamal ciphertexts, identifies signers

### 6. Individual Scheme Benchmarks

```bash
cargo run --release --bin schemes -- wtas 1024 5          # WTAS
cargo run --release --bin schemes -- virtual_frost 32 100 # Weighted FROST
cargo run --release --bin schemes -- wts_das 32 50        # WTS Das et al.
cargo run --release --bin schemes -- taps 32 50           # TAPS Boneh-Komlo
cargo run --release --bin schemes -- bls 1024 5           # BLS baseline
```

### 7. Low-Level Primitives

```bash
cargo run --release --bin ecc_scalar -- -n 10000    # EC scalar/pairing
cargo run --release --bin time -- hash --size 64    # Hash benchmarks
cargo run --release --bin time -- ed25519           # Ed25519 primitives
cargo run --release --bin time -- bls --pairing     # BLS12-381 pairings
```

## Paper Reference

If you use this code, please cite:

```bibtex
@inproceedings{cui2026wtas,
  title     = {Efficient and Practical Weighted Threshold Signatures for Blockchains},
  author    = {Jie Cui and Yuhang Liu and Lu Wei and Ru Li and Jing Zhang and Hong Zhong},
  booktitle = {ESORICS},
  year      = {2026}
}
```

## Reproducibility

- Use `--release` mode (LTO enabled)
- Pin CPU frequency: `cpupower frequency-set -g performance` (Linux)
- Run each benchmark ≥100 iterations
- Use consistent hardware for comparisons
