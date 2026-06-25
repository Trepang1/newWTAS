// WTAS: Weighted Threshold Accountable Signatures
// ===============================================
// Our scheme — EdDSA/Ed25519-based (pairing-free) weighted threshold signatures
// with ElGamal-based signer accountability and Bulletproofs NIZK proof.
//
// Architecture:
//   Signing layer:  Ed25519 Schnorr-style weighted multi-signature (pairing-free)
//   ZK proof layer: Bulletproofs IPA on Ristretto (zk crate)
//   Accountability: ElGamal encryption on Ristretto

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha512};
use std::time::{Duration, Instant};

// NIZK proof system (our accountability layer)
use zk::{PublicInput, PublicParams as ZkParams, SecretWitness, WTAPSProof};

// ============================================================
// Helper: random scalar generation
// ============================================================
fn random_scalar() -> Scalar {
    let mut b = [0u8; 64];
    OsRng.fill_bytes(&mut b);
    Scalar::from_bytes_mod_order_wide(&b)
}

// ============================================================
// Helper: hash to scalar (Fiat-Shamir challenge)
// ============================================================
fn hash_to_scalar(domain: &[u8], r: &CompressedEdwardsY, pk: &CompressedEdwardsY, msg: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(domain);
    h.update(r.as_bytes());
    h.update(pk.as_bytes());
    h.update(msg);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

// ============================================================
// Benchmark output helper
// ============================================================
fn fmt_rate(op: &str, total: Duration, iters: usize) {
    let ns = (total.as_nanos() as f64) / (iters as f64);
    println!(
        "{op:<18} total = {:>9.3} ms   avg {:>9.1} ns  ({:>8.3} µs)",
        total.as_secs_f64() * 1e3,
        ns,
        ns / 1e3
    );
}

// ============================================================
// WTAS Signer
// ============================================================
/// WTAS Signer — holds both Ed25519 signing keys and Ristretto accountability keys.
#[derive(Clone)]
pub struct WtasSigner {
    pub id: usize,
    pub weight: u64,
    // Ed25519 signing keys (Edwards curve, cofactor 8)
    pub sk: Scalar,
    pub pk: EdwardsPoint,
    // Ristretto accountability keys (prime-order group, for NIZK)
    pub sk_ristretto: Scalar,
    pub pk_ristretto: RistrettoPoint,
}

/// WTAS accountability proof (NIZK proof + associated data).
pub struct WtasAccountabilityProof {
    pub zk_proof: WTAPSProof,
    pub proof_bytes: usize,
    pub prove_us: f64,
}

/// WTAS Group — full protocol state with dual-curve architecture.
pub struct WtasGroup {
    pub n: usize,
    pub weights: Vec<u64>,
    pub total_weight: u64,
    pub threshold: u64,
    pub signers: Vec<WtasSigner>,
    pub group_pk: EdwardsPoint,       // Σ w_i * pk_i  (Ed25519)
    // Tracer keys — Ristretto-based ElGamal for accountability
    pub tracer_sk: Scalar,
    pub tracer_pk: RistrettoPoint,
    // NIZK public parameters (generators g,h,G,H,B)
    pub zk_params: ZkParams,
}

// ============================================================
// WTAS signature: (R, s) on Ed25519
// ============================================================
pub struct WtasSignature {
    pub r_agg: EdwardsPoint,    // Σ R_i
    pub s_agg: Scalar,          // Σ s_i
}

impl WtasGroup {
    /// Setup: generate n signers with given weights and threshold.
    /// Each signer gets both Ed25519 (signing) and Ristretto (NIZK) keys.
    pub fn setup(n: usize, weights: &[u64], threshold: u64) -> Self {
        assert_eq!(weights.len(), n);
        let total_weight: u64 = weights.iter().sum();
        assert!(threshold <= total_weight);

        let mut rng = OsRng;
        let zk_params = ZkParams::new(n, &mut rng);

        let mut signers = Vec::with_capacity(n);
        for i in 0..n {
            let sk = random_scalar();
            let pk = ED25519_BASEPOINT_TABLE * &sk;
            // Ristretto keys for accountability layer
            let sk_ristretto = random_scalar();
            let pk_ristretto = zk_params.G * sk_ristretto;
            signers.push(WtasSigner {
                id: i, weight: weights[i],
                sk, pk, sk_ristretto, pk_ristretto,
            });
        }

        // Group public key = Σ w_i * pk_i (Ed25519)
        let mut group_pk = EdwardsPoint::default();
        for s in &signers {
            group_pk += s.pk * Scalar::from(s.weight);
        }

        // Tracer keys on Ristretto (for ElGamal)
        let tracer_sk = random_scalar();
        let tracer_pk = zk_params.G * tracer_sk;

        WtasGroup {
            n, weights: weights.to_vec(), total_weight, threshold,
            signers, group_pk, tracer_sk, tracer_pk, zk_params,
        }
    }

    /// Select first k signers whose cumulative weight meets the threshold.
    pub fn select_signers(&self) -> (Vec<usize>, u64) {
        let mut selected = Vec::new();
        let mut cum = 0u64;
        for i in 0..self.n {
            if cum >= self.threshold { break; }
            selected.push(i);
            cum += self.weights[i];
        }
        (selected, cum)
    }

    // ============================================================
    // Round 1: Each active signer generates a nonce commitment
    // ============================================================
    pub fn round1_nonces(&self, active: &[usize]) -> (Vec<Scalar>, Vec<EdwardsPoint>) {
        let mut nonces = Vec::with_capacity(active.len());
        let mut commitments = Vec::with_capacity(active.len());
        for &i in active {
            let r = random_scalar();
            let R = ED25519_BASEPOINT_TABLE * &r;
            nonces.push(r);
            commitments.push(R);
        }
        (nonces, commitments)
    }

    // ============================================================
    // Round 2: Each active signer produces a partial signature
    // ============================================================
    pub fn round2_partial_sign(
        &self,
        active: &[usize],
        nonces: &[Scalar],
        r_agg: &EdwardsPoint,
        message: &[u8],
    ) -> Vec<Scalar> {
        let active_pk = self.active_group_pk(active);
        let c = hash_to_scalar(
            b"WTAS_challenge",
            &r_agg.compress(),
            &active_pk.compress(),
            message,
        );

        let mut partials = Vec::with_capacity(active.len());
        for (idx, &i) in active.iter().enumerate() {
            let signer = &self.signers[i];
            // s_i = r_i + c * w_i * sk_i
            let s_i = nonces[idx] + c * Scalar::from(signer.weight) * signer.sk;
            partials.push(s_i);
        }
        partials
    }

    // ============================================================
    // Full signing protocol (both rounds + aggregation)
    // ============================================================
    pub fn sign(
        &self,
        active: &[usize],
        message: &[u8],
    ) -> (WtasSignature, Duration, Duration, Duration) {
        // Round 1
        let t1 = Instant::now();
        let (nonces, commitments) = self.round1_nonces(active);
        let dt_round1 = t1.elapsed();

        // Aggregate R = Σ R_i
        let t_agg = Instant::now();
        let mut r_agg = EdwardsPoint::default();
        for R in &commitments {
            r_agg += R;
        }
        let dt_agg = t_agg.elapsed();

        // Round 2
        let t2 = Instant::now();
        let partials = self.round2_partial_sign(active, &nonces, &r_agg, message);
        let dt_round2 = t2.elapsed();

        // Aggregate s = Σ s_i
        let s_agg: Scalar = partials.into_iter().sum();

        (WtasSignature { r_agg, s_agg }, dt_round1, dt_agg, dt_round2)
    }

    // ============================================================
    // Compute active group PK: Σ_{i∈active} w_i * pk_i
    // ============================================================
    pub fn active_group_pk(&self, active: &[usize]) -> EdwardsPoint {
        let mut pk = EdwardsPoint::default();
        for &i in active {
            pk += self.signers[i].pk * Scalar::from(self.weights[i]);
        }
        pk
    }

    // ============================================================
    // Verification: s * B == R + c * PK_active
    //   where PK_active = Σ_{i∈active} w_i * pk_i
    // ============================================================
    pub fn verify(&self, sig: &WtasSignature, active: &[usize], message: &[u8]) -> (bool, Duration) {
        let active_pk = self.active_group_pk(active);

        let c = hash_to_scalar(
            b"WTAS_challenge",
            &sig.r_agg.compress(),
            &active_pk.compress(),
            message,
        );

        let t0 = Instant::now();
        let lhs = ED25519_BASEPOINT_TABLE * &sig.s_agg;
        let rhs = sig.r_agg + active_pk * c;
        let ok = lhs.compress() == rhs.compress();
        (ok, t0.elapsed())
    }

    // ============================================================
    // ElGamal encryption for accountability (Ristretto-based)
    // V_i = r_enc,i * tracer_pk + b_i * B
    // Returns: (ciphertexts, r_enc vector, b vector)
    // ============================================================
    pub fn encrypt_participation_ristretto(
        &self, active: &[usize],
    ) -> (Vec<RistrettoPoint>, Vec<Scalar>, Vec<Scalar>) {
        let mut cts = Vec::with_capacity(self.n);
        let mut r_enc_vec = Vec::with_capacity(self.n);
        let mut b_vec = Vec::with_capacity(self.n);
        for i in 0..self.n {
            let b_i = if active.contains(&i) { Scalar::ONE } else { Scalar::ZERO };
            let r_enc = random_scalar();
            let v_i = self.tracer_pk * r_enc + self.zk_params.B * b_i;
            cts.push(v_i);
            r_enc_vec.push(r_enc);
            b_vec.push(b_i);
        }
        (cts, r_enc_vec, b_vec)
    }

    /// Legacy Ed25519-based ElGamal (kept for backward compat tests).
    pub fn encrypt_participation(&self, active: &[usize]) -> Vec<(EdwardsPoint, EdwardsPoint)> {
        let mut cts = Vec::with_capacity(self.n);
        for i in 0..self.n {
            let b_i = if active.contains(&i) { Scalar::ONE } else { Scalar::ZERO };
            let r = random_scalar();
            let c1 = ED25519_BASEPOINT_TABLE * &r;
            let c2 = ED25519_BASEPOINT_TABLE * &b_i + ED25519_BASEPOINT_TABLE * &(r * self.tracer_sk);
            cts.push((c1, c2));
        }
        cts
    }

    // ============================================================
    // NIZK Accountability Proof (generation)
    // ============================================================
    pub fn prove_accountability(
        &self, active: &[usize],
    ) -> WtasAccountabilityProof {
        let (ciphertexts_v, r_enc_vec, b_vec) = self.encrypt_participation_ristretto(active);

        // Ristretto participant keys (one per signer, for all n signers)
        let participant_keys: Vec<RistrettoPoint> = self.signers.iter()
            .map(|s| s.pk_ristretto).collect();

        // K_agg = Σ_{i∈active} pk_ristretto_i
        let mut k_agg = RistrettoPoint::identity();
        for &i in active {
            k_agg += self.signers[i].pk_ristretto;
        }

        // t = Σ b_i * w_i (actual accumulated weight)
        let w_scalars: Vec<Scalar> = self.weights.iter().map(|w| Scalar::from(*w)).collect();
        let mut t = Scalar::ZERO;
        for i in 0..self.n {
            t += b_vec[i] * w_scalars[i];
        }

        // Weight commitment c_w = ρ_w·H + Σ w_i·h_i
        let rho_w = random_scalar();
        let c_w = RistrettoPoint::multiscalar_mul(
            std::iter::once(&rho_w).chain(w_scalars.iter()),
            std::iter::once(&self.zk_params.H).chain(self.zk_params.h_vec.iter()),
        );

        let w_total = Scalar::from(self.total_weight);

        let public = PublicInput {
            ciphertexts_v,
            k_agg,
            t,
            pk_enc: self.tracer_pk,
            participant_keys,
            c_w,
            w_total,
        };
        let secret = SecretWitness {
            b: b_vec,
            w: w_scalars,
            r_enc: r_enc_vec,
            rho_w,
        };

        let mut rng = OsRng;
        let t0 = Instant::now();
        let zk_proof = WTAPSProof::prove(&self.zk_params, &public, &secret, &mut rng)
            .expect("NIZK proof generation failed");
        let prove_us = t0.elapsed().as_secs_f64() * 1e6;
        let proof_bytes = zk_proof.proof_size_bytes();

        WtasAccountabilityProof { zk_proof, proof_bytes, prove_us }
    }

    // ============================================================
    // NIZK Accountability Proof (verification)
    // ============================================================
    pub fn verify_accountability(
        &self, active: &[usize], proof: &WtasAccountabilityProof,
    ) -> (bool, Duration) {
        let (ciphertexts_v, _r_enc, b_vec) = self.encrypt_participation_ristretto(active);

        let participant_keys: Vec<RistrettoPoint> = self.signers.iter()
            .map(|s| s.pk_ristretto).collect();

        let mut k_agg = RistrettoPoint::identity();
        for &i in active {
            k_agg += self.signers[i].pk_ristretto;
        }

        let w_scalars: Vec<Scalar> = self.weights.iter().map(|w| Scalar::from(*w)).collect();
        let mut t = Scalar::ZERO;
        for i in 0..self.n {
            t += b_vec[i] * w_scalars[i];
        }

        let rho_w = random_scalar(); // Not needed for verify — verifier recomputes c_w
        let c_w = RistrettoPoint::multiscalar_mul(
            std::iter::once(&rho_w).chain(w_scalars.iter()),
            std::iter::once(&self.zk_params.H).chain(self.zk_params.h_vec.iter()),
        );

        let public = PublicInput {
            ciphertexts_v, k_agg, t, pk_enc: self.tracer_pk,
            participant_keys, c_w, w_total: Scalar::from(self.total_weight),
        };

        let t0 = Instant::now();
        let result = proof.zk_proof.verify_fast(&self.zk_params, &public);
        (result.is_ok(), t0.elapsed())
    }

    // ============================================================
    // Weight update (epoch transition for PoS stake changes)
    // ============================================================
    pub fn update_weights(&mut self, new_weights: &[u64], new_threshold: Option<u64>) {
        assert_eq!(new_weights.len(), self.n);
        let new_total: u64 = new_weights.iter().sum();
        let threshold = new_threshold.unwrap_or((new_total + 1) / 2);
        assert!(threshold <= new_total);

        self.weights = new_weights.to_vec();
        self.total_weight = new_total;
        self.threshold = threshold;

        // Recompute group PK with new weights
        self.group_pk = EdwardsPoint::default();
        for s in &self.signers {
            self.group_pk += s.pk * Scalar::from(s.weight);
        }
    }

    /// Generate epoch binding to prevent cross-epoch signature replay.
    pub fn epoch_domain(epoch: u64) -> [u8; 32] {
        let mut h = Sha512::new();
        h.update(b"WTAS_EPOCH");
        h.update(&epoch.to_le_bytes());
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d[..32]);
        out
    }

    // ============================================================
    // Communication cost
    // ============================================================
    pub fn communication_cost(num_active: usize, nizk_log_n: usize) -> usize {
        // Round 1: each signer sends 1 compressed Edwards point = 32 bytes
        // Round 2: each signer sends 1 scalar = 32 bytes
        let per_signer = 64;
        // ElGamal cts (offline/optional): 2 * 32 bytes per signer = 64
        let per_signer_ct = 64;
        // NIZK proof: 2*log(n) L/R points + 6 fixed points + 5 scalars
        let nizk = (2 * nizk_log_n + 6) * 32 + 5 * 32;

        num_active * (per_signer + per_signer_ct) + nizk
    }
}

// ============================================================
// Full WTAS benchmark
// ============================================================
pub fn bench_wtas_full(num_signers: usize, iters: usize) {
    println!("\n== WTAS (Ed25519, pairing-free) n={num_signers}, iters={iters} ==");

    let weights: Vec<u64> = (0..num_signers).map(|i| 2u64.pow((i % 4) as u32)).collect();
    let total_weight: u64 = weights.iter().sum();
    let threshold = (total_weight + 1) / 2;

    println!("Weights: [{}, {}], Total: {total_weight}, Threshold: {threshold}",
        weights.iter().min().unwrap(), weights.iter().max().unwrap());

    let message = b"bench-msg-wtas-0123456789abcdef";

    // Setup
    let mut best_setup = Duration::MAX;
    for _ in 0..iters.min(10) {
        let t0 = Instant::now();
        let g = WtasGroup::setup(num_signers, &weights, threshold);
        std::hint::black_box(&g);
        best_setup = best_setup.min(t0.elapsed());
    }
    fmt_rate("setup", best_setup, num_signers);

    let group = WtasGroup::setup(num_signers, &weights, threshold);
    let (active, cum_weight) = group.select_signers();
    let k = active.len();
    println!("Active signers: {k}/{num_signers}, weight: {cum_weight}/{total_weight}");

    // Sign
    let mut best_round1 = Duration::MAX;
    let mut best_round2 = Duration::MAX;
    let mut best_agg = Duration::MAX;
    for _ in 0..iters {
        let (sig, dt1, dt_agg, dt2) = group.sign(&active, message);
        best_round1 = best_round1.min(dt1);
        best_agg = best_agg.min(dt_agg);
        best_round2 = best_round2.min(dt2);
        std::hint::black_box(&sig);
    }
    fmt_rate("round1 (nonces)", best_round1, k);
    fmt_rate("round2 (partial sig)", best_round2, k);
    let total_sign = best_round1 + best_round2 + best_agg;
    fmt_rate("TOTAL sign", total_sign, 1);

    // Verify
    let (sig, _, _, _) = group.sign(&active, message);
    let mut best_verify = Duration::MAX;
    for _ in 0..iters {
        let (ok, dt) = group.verify(&sig, &active, message);
        if ok { best_verify = best_verify.min(dt); }
    }
    fmt_rate("verify", best_verify, 1);

    // ElGamal encryption (Ristretto)
    let mut best_enc = Duration::MAX;
    for _ in 0..iters {
        let t0 = Instant::now();
        let cts = group.encrypt_participation_ristretto(&active);
        best_enc = best_enc.min(t0.elapsed());
        std::hint::black_box(&cts);
    }
    fmt_rate("ElGamal enc (Ristretto)", best_enc, num_signers);

    // NIZK proof generation
    let acc_proof = group.prove_accountability(&active);
    println!("NIZK prove:          {:>9.1} µs,  {} bytes",
        acc_proof.prove_us, acc_proof.proof_bytes);

    // NIZK proof verification
    let mut best_zk_verify = Duration::MAX;
    for _ in 0..iters.min(5) {
        let (ok, dt) = group.verify_accountability(&active, &acc_proof);
        if ok { best_zk_verify = best_zk_verify.min(dt); }
    }
    fmt_rate("NIZK verify", best_zk_verify, 1);

    // Weight update
    let mut best_update = Duration::MAX;
    let new_weights: Vec<u64> = weights.iter().map(|w| w * 2).collect();
    for _ in 0..iters.min(10) {
        let mut g2 = WtasGroup::setup(num_signers, &weights, threshold);
        let t0 = Instant::now();
        g2.update_weights(&new_weights, None);
        best_update = best_update.min(t0.elapsed());
    }
    fmt_rate("weight_update", best_update, 1);

    // Communication
    let log_n = (num_signers as f64).log2().ceil() as usize;
    let comm = WtasGroup::communication_cost(k, log_n);
    println!("{:<18} {:>9} bytes  ({:.1} KB, {:.0} B/signer)",
        "comm_cost", comm, comm as f64 / 1024.0, comm as f64 / k as f64);

    // Fig 1 data
    println!("\n--- WTAS data (n={num_signers}) ---");
    println!("  n={num_signers}  k={k}  total_w={total_weight}  thr={threshold}");
    println!("  sign_us={:.1}  verify_us={:.1}  comm_bytes={comm}",
        total_sign.as_secs_f64() * 1e6, best_verify.as_secs_f64() * 1e6);
    println!("  prove_us={:.1}  verify_zk_us={:.1}  proof_bytes={}",
        acc_proof.prove_us, best_zk_verify.as_secs_f64() * 1e6, acc_proof.proof_bytes);
}

// ============================================================
// Entry point
// ============================================================
pub fn run(args: &[String]) {
    let n = args.get(0).and_then(|s| s.parse::<usize>().ok()).unwrap_or(32);
    let iters = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(50);
    bench_wtas_full(n, iters);
}

// ============================================================
// Tests
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_and_select() {
        let w = vec![1, 2, 4, 8];
        let g = WtasGroup::setup(4, &w, 6);
        assert_eq!(g.total_weight, 15);
        assert_eq!(g.signers.len(), 4);
        let (sel, cum) = g.select_signers();
        assert!(cum >= 6);
        assert_eq!(sel.len(), 3); // 1+2+4=7 >= 6
    }

    #[test]
    fn test_sign_and_verify() {
        // Single signer, simple case
        let w = vec![1u64];
        let g = WtasGroup::setup(1, &w, 1);
        let msg = b"test";

        // Known keys
        let sk = g.signers[0].sk;
        let pk: EdwardsPoint = ED25519_BASEPOINT_TABLE * &sk;
        let w1 = Scalar::from(1u64);
        // group_pk = w1 * pk = pk (since w1=1)
        eprintln!("pk == group_pk: {}", pk.compress() == g.group_pk.compress());

        // Manual sign
        let r = random_scalar();
        let R: EdwardsPoint = ED25519_BASEPOINT_TABLE * &r;
        let c = hash_to_scalar(b"WTAS_challenge", &R.compress(), &g.group_pk.compress(), msg);
        let s = r + c * w1 * sk;

        // Verify
        let lhs: EdwardsPoint = ED25519_BASEPOINT_TABLE * &s;
        let rhs = R + g.group_pk * c;
        eprintln!("single signer verify: {}", lhs.compress() == rhs.compress());

        // API sign
        let (sig, _, _, _) = g.sign(&[0], msg);
        let (ok, _) = g.verify(&sig, &[0], msg);
        assert!(ok, "sig verification failed");
    }

    #[test]
    fn test_verify_rejects_wrong_message() {
        let w = vec![1, 1];
        let g = WtasGroup::setup(2, &w, 1);
        let (active, _) = g.select_signers();
        let (sig, _, _, _) = g.sign(&active, b"hello");
        let (ok, _) = g.verify(&sig, &active, b"wrong");
        assert!(!ok);
    }

    #[test]
    fn test_weight_update() {
        let w = vec![1, 1, 1, 1];
        let mut g = WtasGroup::setup(4, &w, 2);
        assert_eq!(g.total_weight, 4);
        g.update_weights(&[2, 2, 2, 2], Some(4));
        assert_eq!(g.total_weight, 8);
        assert_eq!(g.threshold, 4);
    }

    #[test]
    fn test_weight_update_preserves_keys() {
        let w = vec![1, 2, 3];
        let mut g = WtasGroup::setup(3, &w, 3);
        let old_pk0 = g.signers[0].pk.compress();
        g.update_weights(&[2, 4, 6], None);
        assert_eq!(g.signers[0].pk.compress(), old_pk0);
    }

    #[test]
    fn test_epoch_domain_unique() {
        assert_ne!(WtasGroup::epoch_domain(1), WtasGroup::epoch_domain(2));
    }

    #[test]
    fn test_encrypt_participation() {
        let w = vec![1, 1, 1, 1];
        let g = WtasGroup::setup(4, &w, 2);
        let cts = g.encrypt_participation(&[0, 1]);
        assert_eq!(cts.len(), 4); // one per signer (active + inactive)
    }

    fn manual_sign_verify(g: &WtasGroup, active: &[usize], msg: &[u8]) -> bool {
        let k = active.len();
        let mut nonces = Vec::with_capacity(k);
        let mut commitments = Vec::with_capacity(k);
        for _ in 0..k {
            let r = random_scalar();
            commitments.push(ED25519_BASEPOINT_TABLE * &r);
            nonces.push(r);
        }
        let mut r_agg = EdwardsPoint::default();
        for R in &commitments { r_agg += R; }
        let active_pk = g.active_group_pk(active);
        let c = hash_to_scalar(b"WTAS_challenge", &r_agg.compress(), &active_pk.compress(), msg);
        let mut s_agg = Scalar::ZERO;
        for (idx, &i) in active.iter().enumerate() {
            s_agg += nonces[idx] + c * Scalar::from(g.weights[i]) * g.signers[i].sk;
        }
        let lhs: EdwardsPoint = ED25519_BASEPOINT_TABLE * &s_agg;
        let rhs = r_agg + active_pk * c;
        lhs.compress() == rhs.compress()
    }

    #[test]
    fn test_sign_verify_various_n() {
        for n in [1usize, 2, 3, 4, 8, 16] {
            let w: Vec<u64> = (0..n).map(|i| 2u64.pow((i % 4) as u32)).collect();
            let total: u64 = w.iter().sum();
            let thr = (total + 1) / 2;
            let g = WtasGroup::setup(n, &w, thr);
            let (active, _) = g.select_signers();
            let msg = b"test";

            // Manual verification
            assert!(manual_sign_verify(&g, &active, msg), "manual n={n} k={}", active.len());

            // API
            let (sig, _, _, _) = g.sign(&active, msg);
            let (ok, _) = g.verify(&sig, &active, msg);
            assert!(ok, "API n={n} k={}", active.len());
        }
    }
}
