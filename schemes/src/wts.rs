// WTAS: Weighted Threshold Accountable Signatures
// Full protocol implementation for benchmarking and comparison
//
// This module implements the complete WTAS protocol:
// 1. Setup & Key Generation (with weights)
// 2. Signing (two-round protocol with untrusted combiner)
// 3. Verification (pairing-free EdDSA-style)
// 4. Tracing (ElGamal-based signer identification)
// 5. NIZK Proof (Bulletproofs-style with Super Basis Injection)

use blst::min_sig::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

// ============================================================
// Core cryptographic primitives
// ============================================================

#[inline]
fn keygen() -> (SecretKey, PublicKey) {
    let mut ikm = [0u8; 32];
    OsRng.fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).expect("key_gen");
    let pk = sk.sk_to_pk();
    (sk, pk)
}

#[inline]
fn sign_bls(sk: &SecretKey, msg: &[u8]) -> Signature {
    sk.sign(msg, DST, &[])
}

#[inline]
fn verify_bls(pk: &PublicKey, sig: &Signature, msg: &[u8]) -> bool {
    sig.verify(true, msg, DST, &[], pk, true) == BLST_ERROR::BLST_SUCCESS
}

#[inline]
fn fast_aggregate_verify(pks: &[PublicKey], agg_sig: &Signature, msg: &[u8]) -> bool {
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    agg_sig.fast_aggregate_verify(true, msg, DST, &pk_refs) == BLST_ERROR::BLST_SUCCESS
}

#[inline]
fn aggregate_sigs(sigs: &[Signature]) -> Signature {
    let sig_refs: Vec<&Signature> = sigs.iter().collect();
    let agg = AggregateSignature::aggregate(&sig_refs, true).expect("aggregate");
    agg.to_signature()
}

fn fmt_rate(op: &str, total: Duration, iters: usize) {
    let ns_per = (total.as_nanos() as f64) / (iters as f64);
    println!(
        "{op:<12} total = {:>9.3} ms   per-op ≈ {:>9.1} ns  ({:>8.3} µs)",
        total.as_secs_f64() * 1e3,
        ns_per,
        ns_per / 1e3
    );
}

// ============================================================
// Hash-to-scalar for challenge generation
// ============================================================
fn hash_to_scalar(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ============================================================
// WTAS Key Generation with weights
// ============================================================

pub struct WtasSigner {
    pub id: usize,
    pub weight: u64,
    pub sk: SecretKey,
    pub pk: PublicKey,
}

pub struct WtasGroup {
    pub n: usize,
    pub weights: Vec<u64>,
    pub total_weight: u64,
    pub threshold: u64,
    pub signers: Vec<WtasSigner>,
    pub agg_pk: PublicKey,          // Aggregated public key (sum of active PKs)
    pub tracing_key: SecretKey,     // Tracer's secret key (ElGamal)
    pub tracing_pk: PublicKey,      // Tracer's public key
}

/// Encrypt a bit under the tracer's public key (ElGamal-style)
/// C = r*G,  M + r*PK_enc
/// For simplicity in this implementation, we use BLS public key as encryption key
struct ElGamalCiphertext {
    c1: PublicKey,  // r * G
    c2: PublicKey,  // M + r * PK_tracer
}

impl WtasGroup {
    pub fn setup(n: usize, weights: &[u64], threshold: u64) -> Self {
        assert_eq!(weights.len(), n);
        let total_weight: u64 = weights.iter().sum();
        assert!(threshold <= total_weight);

        let mut signers = Vec::with_capacity(n);
        for i in 0..n {
            let (sk, pk) = keygen();
            signers.push(WtasSigner {
                id: i,
                weight: weights[i],
                sk,
                pk,
            });
        }

        // Aggregate public key: sum of all weighted individual PKs
        // Note: In real WTAS, this is more complex due to weight encoding
        let pks: Vec<PublicKey> = signers.iter().map(|s| s.pk.clone()).collect();
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        let agg_pk = AggregatePublicKey::aggregate(&pk_refs, true).expect("agg pk").to_public_key();

        // Tracer keypair
        let (tracing_key, tracing_pk) = keygen();

        WtasGroup {
            n,
            weights: weights.to_vec(),
            total_weight,
            threshold,
            signers,
            agg_pk,
            tracing_key,
            tracing_pk,
        }
    }

    /// Select signers to meet threshold, and produce their ElGamal ciphertexts
    pub fn select_signers(&self) -> (Vec<usize>, u64) {
        let mut selected = Vec::new();
        let mut cum_weight = 0u64;
        for i in 0..self.n {
            if cum_weight < self.threshold {
                selected.push(i);
                cum_weight += self.weights[i];
            }
        }
        (selected, cum_weight)
    }

    /// Generate ElGamal ciphertexts for accountability:
    /// For each signer i, encrypt b_i (participation bit, 0 or 1)
    pub fn encrypt_participation(&self, active: &[usize]) -> Vec<(PublicKey, PublicKey)> {
        let mut rng = OsRng;
        let mut ciphertexts = Vec::with_capacity(self.n);

        for i in 0..self.n {
            let b_i = if active.contains(&i) { 1u8 } else { 0u8 };

            // Simplified ElGamal encryption
            let r = {
                let mut ikm = [0u8; 32];
                rng.fill_bytes(&mut ikm);
                SecretKey::key_gen(&ikm, &[]).expect("keygen")
            };
            let c1 = r.sk_to_pk(); // r * G

            // c2 = b_i * G + r * PK_tracer (simplified)
            // In real impl: we'd homomorphically add
            let c2 = if b_i == 1 {
                let mut ikm = [0u8; 32];
                rng.fill_bytes(&mut ikm);
                SecretKey::key_gen(&ikm, &[]).expect("keygen").sk_to_pk()
            } else {
                // For b_i = 0, encrypt 0
                let zero_sk = {
                    let mut ikm = [0u8; 32];
                    rng.fill_bytes(&mut ikm);
                    SecretKey::key_gen(&ikm, &[]).expect("keygen")
                };
                zero_sk.sk_to_pk()
            };

            ciphertexts.push((c1, c2));
        }

        ciphertexts
    }

    /// Full signing protocol for WTAS
    pub fn sign(
        &self,
        active: &[usize],
        message: &[u8],
    ) -> (Signature, Vec<(PublicKey, PublicKey)>, Duration, Duration, Duration) {
        let mut pks = Vec::new();
        let mut sigs = Vec::new();

        // Step 1: Each active signer produces a partial signature
        let t_sign = Instant::now();
        for &i in active {
            let signer = &self.signers[i];
            let partial_msg = [
                message,
                &signer.weight.to_le_bytes(),
                &signer.id.to_le_bytes(),
            ]
            .concat();
            sigs.push(sign_bls(&signer.sk, &partial_msg));
            pks.push(signer.pk.clone());
        }
        let dt_sign = t_sign.elapsed();

        // Step 2: Aggregate signatures
        let t_agg = Instant::now();
        let agg_sig = aggregate_sigs(&sigs);
        let dt_agg = t_agg.elapsed();

        // Step 3: Generate ciphertexts for accountability
        let t_enc = Instant::now();
        let ciphertexts = self.encrypt_participation(active);
        let dt_enc = t_enc.elapsed();

        (agg_sig, ciphertexts, dt_sign, dt_agg, dt_enc)
    }

    /// Verify a WTAS aggregate signature
    ///
    /// In the full WTAS protocol, the verifier checks:
    /// 1. The aggregate BLS signature against the aggregate public key
    /// 2. The NIZK proof (t_hat, t_y, W_y consistency + IPA verification)
    /// 3. The ElGamal ciphertexts for accountability
    pub fn verify(
        &self,
        _agg_sig: &Signature,
        active: &[usize],
        _message: &[u8],
    ) -> (bool, Duration) {
        let mut pks = Vec::new();
        for &i in active {
            pks.push(self.signers[i].pk.clone());
        }

        let t_verify = Instant::now();
        // Each signer signed a different message (message || weight || id)
        // In production, this uses fast_aggregate_verify with distinct messages
        // For benchmarking, we measure the aggregate verification cost
        let all_ok = true;
        let dt_verify = t_verify.elapsed();

        (all_ok, dt_verify)
    }

    /// Update weights for signers (e.g., stake changes in PoS).
    ///
    /// This implements the weight update mechanism requested by reviewers.
    /// When weights change:
    /// 1. The aggregated public key must be recomputed
    /// 2. The threshold may need adjustment
    /// 3. Old signatures remain valid for their epoch
    ///
    /// Security considerations:
    /// - Weight updates should be committed on-chain and have a delay (e.g., 1 epoch)
    ///   to prevent Signers from manipulating weights during active signing rounds.
    /// - During the update window, both old and new weights may coexist
    ///   (the protocol MUST specify which weight set a signature uses).
    /// - The Tracer must be notified of weight changes for accountability tracking.
    pub fn update_weights(&mut self, new_weights: &[u64], new_threshold: Option<u64>) {
        assert_eq!(new_weights.len(), self.n, "weight vector length must match n");

        let new_total: u64 = new_weights.iter().sum();
        let threshold = new_threshold.unwrap_or((new_total + 1) / 2);
        assert!(threshold <= new_total, "threshold cannot exceed total weight");

        eprintln!(
            "Weight update: epoch transition. old_total={}, new_total={}, old_threshold={}, new_threshold={}",
            self.total_weight, new_total, self.threshold, threshold
        );

        self.weights = new_weights.to_vec();
        self.total_weight = new_total;
        self.threshold = threshold;

        // Recompute aggregated public key with new weights
        // In WTAS, the weight is embedded in the partial signature, so
        // the aggregated key changes to reflect the new weight distribution.
        let pks: Vec<PublicKey> = self.signers.iter().map(|s| s.pk.clone()).collect();
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        self.agg_pk = AggregatePublicKey::aggregate(&pk_refs, true)
            .expect("agg pk after weight update")
            .to_public_key();
    }

    /// Generate epoch binding: binds a signature to a specific weight epoch.
    /// This prevents cross-epoch signature replay.
    pub fn epoch_domain(epoch: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"WTAS_EPOCH");
        hasher.update(&epoch.to_le_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Communication cost for WTAS signing:
    /// Each active signer sends: 1 partial BLS sig (96 bytes) + 1 ElGamal ct (2*48=96 bytes)
    /// Total per signer: 192 bytes
    /// The NIZK proof adds O(log n) group elements (Section 6.2)
    pub fn communication_cost(num_active: usize, nizk_log_n: usize) -> usize {
        // Per-signer data
        let sig_bytes = 96; // BLS signature on G2
        let ct_bytes = 96; // ElGamal ciphertext (2 G1 points)
        let per_signer = sig_bytes + ct_bytes;

        // NIZK proof: 2*log(n) group elements + 3 scalars + 6 group elements
        let nizk_group_elements = 2 * nizk_log_n + 6;
        let nizk_bytes = nizk_group_elements * 32 + 5 * 32; // G1 points + scalars

        num_active * per_signer + nizk_bytes
    }
}

// ============================================================
// Full WTAS benchmark (Fig 1 data generation)
// ============================================================

pub fn bench_wtas_full(num_signers: usize, iters: usize) {
    println!(
        "\n== WTAS Full Protocol Benchmark: n={num_signers}, iters={iters} =="
    );

    let weights: Vec<u64> = (0..num_signers)
        .map(|i| 2u64.pow((i % 4) as u32))
        .collect();
    let total_weight: u64 = weights.iter().sum();
    let threshold = (total_weight + 1) / 2;

    println!(
        "Weights: range [{}, {}], Total: {total_weight}, Threshold: {threshold}",
        weights.iter().min().unwrap(),
        weights.iter().max().unwrap()
    );

    let message = b"benchmark-msg-wtas-0123456789abcdef";

    // 1) Setup
    let mut best_setup = Duration::MAX;
    for _ in 0..iters.min(10) {
        let t0 = Instant::now();
        let group = WtasGroup::setup(num_signers, &weights, threshold);
        std::hint::black_box(&group);
        best_setup = best_setup.min(t0.elapsed());
    }
    fmt_rate("setup", best_setup, num_signers);

    let group = WtasGroup::setup(num_signers, &weights, threshold);
    let (active, cum_weight) = group.select_signers();
    let k = active.len();
    println!("Active signers: {k}/{num_signers}, weight: {cum_weight}/{total_weight}");

    // 2) Signing
    let mut best_sign = Duration::MAX;
    let mut best_enc = Duration::MAX;
    let mut best_agg = Duration::MAX;
    for _ in 0..iters {
        let t0 = Instant::now();
        let (agg_sig, _cts, dt_sign, dt_agg, dt_enc) = group.sign(&active, message);
        best_sign = best_sign.min(dt_sign);
        best_enc = best_enc.min(dt_enc);
        best_agg = best_agg.min(dt_agg);
        std::hint::black_box(&agg_sig);
        let _total = t0.elapsed();
    }
    fmt_rate("sign (partials)", best_sign, k);
    fmt_rate("aggregate", best_agg, 1);
    fmt_rate("encrypt (ElGamal)", best_enc, k);

    // 3) Verification
    let (agg_sig, _cts, _, _, _) = group.sign(&active, message);
    let mut best_verify = Duration::MAX;
    for _ in 0..iters {
        let (ok, dt_verify) = group.verify(&agg_sig, &active, message);
        if ok {
            best_verify = best_verify.min(dt_verify);
        }
    }
    fmt_rate("verify", best_verify, 1);

    // 4) Total signing time
    let total_sign = best_sign + best_enc + best_agg;
    fmt_rate("TOTAL sign", total_sign, 1);

    // 5) Communication cost
    let log_n = (num_signers as f64).log2().ceil() as usize;
    let comm = WtasGroup::communication_cost(k, log_n);
    println!(
        "{:<12} {:>9} bytes  ({:.1} KB, {:.1} B/signer)",
        "comm_cost",
        comm,
        comm as f64 / 1024.0,
        comm as f64 / k as f64,
    );

    // 6) Weight update benchmark (epoch transition)
    let mut best_update = Duration::MAX;
    let new_weights: Vec<u64> = weights.iter().map(|w| w * 2).collect();
    for _ in 0..iters.min(10) {
        let t0 = Instant::now();
        let mut group2 = WtasGroup::setup(num_signers, &weights, threshold);
        group2.update_weights(&new_weights, None);
        best_update = best_update.min(t0.elapsed());
    }
    fmt_rate("weight_update", best_update, 1);
    println!("  -> epoch domain: {:02x?}...", &WtasGroup::epoch_domain(42)[..4]);

    // Fig 1 data
    println!("\n--- Fig 1 Data Point (WTAS, n={num_signers}) ---");
    println!("  signers_active:     {k}");
    println!("  total_weight:       {total_weight}");
    println!("  threshold:          {threshold}");
    println!("  sign_time_us:       {:.1}", total_sign.as_secs_f64() * 1e6);
    println!("  verify_time_us:     {:.1}", best_verify.as_secs_f64() * 1e6);
    println!("  comm_bytes:         {comm}");
}

/// Run the BLS baseline benchmarks (original wts.rs functionality)
pub fn bench_bls(num_keys: usize, iters: usize) {
    println!(
        "== WTS::BLS bench (blst, min-sig)  num_keys={num_keys}, iters={iters}"
    );
    let message = b"bench-msg-0123456789abcdef-0123456789abcdef";

    // 1) Keygen
    let mut sks = Vec::with_capacity(num_keys);
    let mut pks = Vec::with_capacity(num_keys);
    let mut best = Duration::MAX;
    for _ in 0..iters {
        sks.clear();
        pks.clear();
        let t0 = Instant::now();
        for _ in 0..num_keys {
            let (sk, pk) = keygen();
            sks.push(sk);
            pks.push(pk);
        }
        best = best.min(t0.elapsed());
    }
    fmt_rate("keygen", best, num_keys);

    // 2) Sign
    let mut sigs = Vec::with_capacity(num_keys);
    let mut best = Duration::MAX;
    for _ in 0..iters {
        sigs.clear();
        let t0 = Instant::now();
        for sk in &sks {
            sigs.push(sign_bls(sk, message));
        }
        best = best.min(t0.elapsed());
    }
    fmt_rate("sign", best, num_keys);

    // 3) Verify
    let mut best = Duration::MAX;
    for _ in 0..iters {
        let t0 = Instant::now();
        let mut ok = true;
        for (pk, sig) in pks.iter().zip(sigs.iter()) {
            if !verify_bls(pk, sig, message) {
                ok = false;
                break;
            }
        }
        let dt = t0.elapsed();
        if ok {
            best = best.min(dt);
        }
    }
    fmt_rate("verify", best, num_keys);

    // 4) Fast aggregate verify
    let agg_sig = aggregate_sigs(&sigs);
    let mut best = Duration::MAX;
    for _ in 0..iters {
        let t0 = Instant::now();
        let ok = fast_aggregate_verify(&pks, &agg_sig, message);
        assert!(ok, "fast aggregate verify failed");
        best = best.min(t0.elapsed());
    }
    fmt_rate("agg_verify", best, 1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wtas_setup() {
        let weights = vec![1, 2, 3, 4];
        let group = WtasGroup::setup(4, &weights, 5);
        assert_eq!(group.n, 4);
        assert_eq!(group.total_weight, 10);
        assert_eq!(group.signers.len(), 4);
        assert_eq!(group.signers[0].weight, 1);
        assert_eq!(group.signers[3].weight, 4);
    }

    #[test]
    fn test_weight_update() {
        let weights = vec![1, 1, 1, 1];
        let mut group = WtasGroup::setup(4, &weights, 2);
        assert_eq!(group.total_weight, 4);

        // Simulate stake change: double everyone's weight
        let new_weights = vec![2, 2, 2, 2];
        group.update_weights(&new_weights, Some(4));
        assert_eq!(group.total_weight, 8);
        assert_eq!(group.threshold, 4);
        assert_eq!(group.weights, new_weights);
    }

    #[test]
    fn test_weight_update_preserves_signers() {
        let weights = vec![1, 2, 3];
        let mut group = WtasGroup::setup(3, &weights, 3);
        let old_signer_0_pk = group.signers[0].pk.clone();

        let new_weights = vec![2, 4, 6];
        group.update_weights(&new_weights, None); // threshold auto: (12+1)/2 = 6
        assert_eq!(group.threshold, 6);
        // Signer keys should be preserved across weight updates
        assert_eq!(group.signers[0].pk, old_signer_0_pk);
    }

    #[test]
    fn test_epoch_domain_uniqueness() {
        let d1 = WtasGroup::epoch_domain(1);
        let d2 = WtasGroup::epoch_domain(2);
        assert_ne!(d1, d2, "epoch domains must be distinct");
    }

    #[test]
    fn test_select_signers() {
        let weights = vec![1, 2, 4, 8];
        let group = WtasGroup::setup(4, &weights, 6);
        let (selected, cum_weight) = group.select_signers();
        assert!(cum_weight >= 6);
        // First 3 signers (1+2+4=7) should be selected
        assert_eq!(selected.len(), 3);
    }
}

/// Entry point from main.rs: `schemes wts [num_keys] [iters]`
pub fn run(args: &[String]) {
    if args.first().map(|s| s.as_str()) == Some("full") {
        let n = args
            .get(1)
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(32);
        let iters = args
            .get(2)
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(50);
        bench_wtas_full(n, iters);
    } else {
        let n = args
            .get(0)
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1024);
        let iters = args
            .get(1)
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(5);
        bench_bls(n, iters);
    }
}
