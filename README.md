## 1. Smart Contract Deployment (On-chain Logic)

The core on-chain logic of the wallet is implemented in `programs/aggtest/src/lib.rs`. Follow these steps for deployment:

1.  **Start Solana Cluster**: Ensure your local Solana blockchain is running.
2.  **Initial Deployment**: Execute the following command to deploy the program:
    ```bash
    anchor deploy
    ```
3.  **Update Program ID**: 
    - Obtain the generated **Program ID** from the deployment output.
    - Locate the `declare_id!` macro in `programs/aggtest/src/lib.rs`.
    - Replace the existing ID with your new Program ID (e.g., `AZiDFQndT4VdW6o4ywME3XHZ81eY2xUtkohULaxC9rwb`).
4.  **Redeploy**: Run the deployment command again to apply the changes:
    ```bash
    anchor deploy
    ```

## 2. Transaction Execution

The transaction workflow is implemented in `cli/src/main.rs`. To execute transactions via the CLI tool, use the following command:

```bash
cargo run --release --bin cli
```

## 3. Zero-Knowledge Proof (ZKP) Simulation

The ZKP implementation is located in `zk/src/main.rs`. This module simulates the entire lifecycle of proof generation and verification.
To run the simulation:
```bash
cargo run --release --bin zk
```
The system supports two verification methods:
- Standard Verification: Follows the conventional Bulletproofs iterative folding process.
- Fast Verification: Implements the optimized verification algorithm proposed in our research paper.

## 4. Performance Benchmarking

The computational costs and execution times for fundamental operations (Elliptic Curve and Scalar operations) are calculated in `ecc_scalar/src/main.rs`.

To run the benchmarks:

```bash
cargo run --release --bin  ecc_scalar -- -n 10000
```
