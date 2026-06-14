# WTAPS — Weighted Threshold Accountable Signatures

An efficient and practical weighted threshold signature scheme with accountability for blockchains.

## Repository Structure

```
├── schemes/          # Protocol implementations and comparative benchmarks
│   ├── wts.rs        # WTAS protocol + BLS baseline
│   ├── virtual_frost.rs  # Weighted FROST (main comparison target)
│   ├── schnorr.rs    # Schnorr/BIP-340 baseline
│   └── pr_taps.rs    # Ed25519 baseline
├── zk/               # NIZK proof system (Bulletproofs-style with Super Basis Injection)
├── time/             # Comprehensive protocol benchmarks (Fig. 1 data)
├── ecc_scalar/       # Low-level EC/scalar primitive benchmarks
├── cli/              # Solana CLI for on-chain DAO wallet transactions
├── programs/aggtest/ # Solana on-chain program (DAO wallet)
└── tests/            # TypeScript integration tests
```

## Quick Start

### Prerequisites
- Rust 1.75+ with `cargo`
- (Optional for on-chain) Solana CLI + Anchor framework

### 1. Run NIZK Proof Simulation

```bash
cargo run --release --bin zk
```

The system supports two verification methods:
- **Standard Verification**: Follows the conventional Bulletproofs iterative folding process.
- **Fast Verification**: Implements the optimized verification algorithm proposed in our paper.

### 2. Reproduce Paper Figure 1 (Comprehensive Protocol Comparison)

This generates CSV data comparing WTAS, Weighted FROST, BLS, and Schnorr across varying signer counts:

```bash
# Default sizes: 8, 16, 32, 64, 128 signers
cargo run --release --bin time -- fig1

# Custom sizes
cargo run --release --bin time -- fig1 --sizes "8,16,32,64,128,256" --iters 100
```

The output is in CSV format (`scheme,n_signers,active_signers,...`) ready for plotting.

### 3. Run Individual Scheme Benchmarks

```bash
# WTAS full protocol benchmark
cargo run --release --bin schemes -- wts full 32 100

# Weighted FROST benchmark
cargo run --release --bin schemes -- virtual_frost 32 100

# BLS baseline benchmark
cargo run --release --bin schemes -- wts 1024 5

# Schnorr/BIP-340 benchmark
cargo run --release --bin schemes -- schnorr 1024 5

# Ed25519 benchmark
cargo run --release --bin schemes -- pr_taps 1024 5
```

### 4. Low-Level Primitive Benchmarks

```bash
# EC scalar multiplication and pairing benchmarks
cargo run --release --bin ecc_scalar -- -n 10000

# Hash function benchmarks
cargo run --release --bin time -- hash --size 64

# Specific curve benchmarks
cargo run --release --bin time -- ed25519
cargo run --release --bin time -- schnorr
cargo run --release --bin time -- bls --pairing
```

## 5. On-Chain Deployment (Solana)

The on-chain DAO wallet is implemented in `programs/aggtest/src/lib.rs`.

1.  **Start Solana Cluster**: Ensure your local Solana blockchain is running.
2.  **Initial Deployment**:
    ```bash
    anchor deploy
    ```
3.  **Update Program ID**:
    - Obtain the generated **Program ID** from the deployment output.
    - Locate the `declare_id!` macro in `programs/aggtest/src/lib.rs`.
    - Replace the existing ID with your new Program ID.
4.  **Redeploy**:
    ```bash
    anchor deploy
    ```
5.  **Execute Transactions** (via CLI):
    ```bash
    cargo run --release --bin cli
    ```

## Paper Reference

If you use this code in your research, please cite:

```
@inproceedings{cui2026wtas,
  title     = {Efficient and Practical Weighted Threshold Signatures for Blockchains},
  author    = {Jie Cui and Yuhang Liu and Lu Wei and Ru Li and Jing Zhang and Hong Zhong},
  booktitle = {ESORICS},
  year      = {2026}
}
```

## Reproducibility

All benchmarks can be reproduced on any machine with Rust installed.
For the most accurate results:

1. Use `--release` mode (LTO + single codegen unit enabled)
2. Pin CPU frequency (Linux: `cpupower frequency-set -g performance`)
3. Use consistent hardware for comparisons
4. Run each benchmark multiple times and take the minimum (as recommended in the paper)

## License

This project is provided for academic and research purposes. See the paper for details.
