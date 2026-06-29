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

/// ElGamal ciphertext pair (U, V) on Ristretto.
/// U = r·G, V = r·tracer_pk + b·B
#[derive(Clone, Debug)]
pub struct ElGamalCiphertext {
    pub u: RistrettoPoint,
    pub v: RistrettoPoint,
}

/// WTAS accountability proof (NIZK proof + associated data).
pub struct WtasAccountabilityProof {
    pub zk_proof: WTAPSProof,
    pub proof_bytes: usize,
    pub prove_us: f64,
    /// Ciphertext V values used during proof generation (for verification reproducibility)
    pub ciphertexts_v: Vec<RistrettoPoint>,
}

/// WTAS Group — full protocol state with dual-curve architecture.
pub struct WtasGroup {
    pub n: usize,
    pub weights: Vec<u64>,
    pub total_weight: u64,
    pub threshold: u64,
    pub signers: Vec<WtasSigner>,
    pub group_pk: EdwardsPoint,       // Σ w_i * pk_i  (Ed25519)
    // Combiner keys — untrusted coordinator (Ed25519)
    pub combiner_sk: Scalar,
    pub combiner_pk: EdwardsPoint,
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

/// Dual nonce pair: (r_i, e_i) with commitments (R_i, E_i).
/// r_i = deterministic nonce, e_i = ephemeral blinding nonce (anti-ROS).
#[derive(Clone, Debug)]
pub struct DualNonce {
    pub r: Scalar,
    pub r_point: EdwardsPoint,
    pub e: Scalar,
    pub e_point: EdwardsPoint,
}

/// Binding context constructed by the Combiner during coordination.
/// Bctx = (j, R_j, E_j, w_j)_{j∈J} plus precomputed aggregates.
#[derive(Clone, Debug)]
pub struct BindingContext {
    /// Per-signer entries: (id, R_j, E_j, w_j, pk_j)
    pub entries: Vec<(usize, EdwardsPoint, EdwardsPoint, u64, EdwardsPoint)>,
    /// Binding factors ρ_j = H1(j, m, Bctx) for each j∈J
    pub binding_factors: Vec<Scalar>,
    /// Effective aggregate commitment: R_eff = Σ(R_j + [ρ_j]E_j)
    pub r_eff: EdwardsPoint,
    /// Weighted aggregate public key: K_agg = Σ[w_j]pk_j
    pub k_agg: EdwardsPoint,
    /// Fiat-Shamir challenge: c = H2(R_eff, K_agg, m)
    pub challenge: Scalar,
}

/// Full WTAS signature including combiner endorsement.
pub struct WtasFullSignature {
    pub sig: WtasSignature,
    pub combiner_sig: [u8; 64],    // Ed25519 combiner endorsement
    pub combiner_pk: EdwardsPoint, // combiner public key
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

        // Combiner keys on Ed25519 (untrusted coordinator)
        let combiner_sk = random_scalar();
        let combiner_pk = ED25519_BASEPOINT_TABLE * &combiner_sk;

        // Tracer keys on Ristretto (for ElGamal)
        let tracer_sk = random_scalar();
        let tracer_pk = zk_params.G * tracer_sk;

        WtasGroup {
            n, weights: weights.to_vec(), total_weight, threshold,
            signers, group_pk, combiner_sk, combiner_pk, tracer_sk, tracer_pk, zk_params,
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
    // Round 1: Each active signer generates dual nonces (r_i, e_i)
    //   r_i — deterministic nonce (from sk_i, prevents key leakage)
    //   e_i — ephemeral blinding nonce (anti-ROS, fresh per session)
    // ============================================================
    pub fn round1_dual_nonces(&self, active: &[usize], message: &[u8]) -> Vec<DualNonce> {
        let mut nonces = Vec::with_capacity(active.len());
        for &i in active {
            let signer = &self.signers[i];
            // Deterministic nonce: r_i = H(HR(sk_i), m)
            let r = {
                let mut h = Sha512::new();
                h.update(b"WTAS_nonce_r");
                h.update(signer.sk.as_bytes());
                h.update(message);
                let mut wide = [0u8; 64];
                wide.copy_from_slice(&h.finalize());
                Scalar::from_bytes_mod_order_wide(&wide)
            };
            let r_point = ED25519_BASEPOINT_TABLE * &r;
            // Ephemeral blinding nonce: e_i ←$ Z_q
            let e = random_scalar();
            let e_point = ED25519_BASEPOINT_TABLE * &e;
            nonces.push(DualNonce { r, r_point, e, e_point });
        }
        nonces
    }

    // ============================================================
    // Combiner coordination: construct binding context Bctx and
    // compute effective aggregate commitment R_eff.
    // ============================================================
    pub fn make_binding_context(
        &self, active: &[usize], nonces: &[DualNonce], message: &[u8],
    ) -> BindingContext {
        // Collect per-signer info for Bctx serialization
        let entries: Vec<(usize, EdwardsPoint, EdwardsPoint, u64, EdwardsPoint)> = active.iter()
            .zip(nonces.iter())
            .map(|(&i, dn)| (i, dn.r_point, dn.e_point, self.weights[i], self.signers[i].pk))
            .collect();

        // Compute binding factors ρ_j = H1(j, m, Bctx_entries)
        let binding_factors: Vec<Scalar> = entries.iter().map(|&(id, rj, ej, wj, pkj)| {
            let mut h = Sha512::new();
            h.update(b"WTAS_binding");
            h.update(&id.to_le_bytes());
            h.update(message);
            h.update(rj.compress().as_bytes());
            h.update(ej.compress().as_bytes());
            h.update(&wj.to_le_bytes());
            h.update(pkj.compress().as_bytes());
            let mut wide = [0u8; 64];
            wide.copy_from_slice(&h.finalize());
            Scalar::from_bytes_mod_order_wide(&wide)
        }).collect();

        // R_eff = Σ(R_j + [ρ_j]E_j)
        let r_eff: EdwardsPoint = entries.iter()
            .zip(binding_factors.iter())
            .map(|(&(_, rj, ej, _, _), rho)| rj + ej * rho)
            .sum();

        // K_agg = Σ[w_j]pk_j
        let k_agg: EdwardsPoint = entries.iter()
            .map(|&(_, _, _, wj, pkj)| pkj * Scalar::from(wj))
            .sum();

        // c = SHA-512(R_eff || K_agg || m) — standard Ed25519, matches precompile
        let challenge = {
            let mut h = Sha512::new();
            h.update(r_eff.compress().as_bytes());
            h.update(k_agg.compress().as_bytes());
            h.update(message);
            let mut wide = [0u8; 64];
            wide.copy_from_slice(&h.finalize());
            Scalar::from_bytes_mod_order_wide(&wide)
        };

        BindingContext { entries, binding_factors, r_eff, k_agg, challenge }
    }

    // ============================================================
    // Round 2: Each active signer produces a weighted partial sig
    //   s_i = r_i + e_i·ρ_i + c·w_i·sk_i   (mod q)
    // ============================================================
    pub fn round2_partial_sign(
        &self, nonces: &[DualNonce], bctx: &BindingContext,
    ) -> Vec<Scalar> {
        let mut partials = Vec::with_capacity(nonces.len());
        for (idx, (dn, rho)) in nonces.iter().zip(bctx.binding_factors.iter()).enumerate() {
            let i = bctx.entries[idx].0;
            let signer = &self.signers[i];
            // s_i = r_i + e_i·ρ_i + c·w_i·sk_i
            let s_i = dn.r + dn.e * rho + bctx.challenge * Scalar::from(signer.weight) * signer.sk;
            partials.push(s_i);
        }
        partials
    }

    // ============================================================
    // Full signing protocol (dual-nonce, both rounds + aggregation)
    // ============================================================
    pub fn sign(
        &self,
        active: &[usize],
        message: &[u8],
    ) -> (WtasFullSignature, Duration, Duration, Duration, Duration) {
        // Round 1: dual nonces
        let t1 = Instant::now();
        let nonces = self.round1_dual_nonces(active, message);
        let dt_round1 = t1.elapsed();

        // Combiner coordination: build binding context
        let t_bctx = Instant::now();
        let bctx = self.make_binding_context(active, &nonces, message);
        let dt_bctx = t_bctx.elapsed();

        // Round 2: weighted partial signatures with binding
        let t2 = Instant::now();
        let partials = self.round2_partial_sign(&nonces, &bctx);
        let dt_round2 = t2.elapsed();

        // Aggregate s = Σ s_i
        let s_agg: Scalar = partials.into_iter().sum();

        // Combiner endorsement: σ_C = EdSign(sk_c, (m, R_eff, S_agg, K_agg))
        let combiner_sig = self.combiner_endorse(message, &bctx, &s_agg);

        (WtasFullSignature {
            sig: WtasSignature { r_agg: bctx.r_eff, s_agg },
            combiner_sig,
            combiner_pk: self.combiner_pk,
        }, dt_round1, dt_bctx, dt_round2, Duration::ZERO)
    }

    /// Combiner endorsement: signs the aggregate payload with its Ed25519 key.
    pub fn combiner_endorse(
        &self, message: &[u8], bctx: &BindingContext, s_agg: &Scalar,
    ) -> [u8; 64] {
        // Build endorsement message: H(m || R_eff || S || K_agg)
        let mut h = Sha512::new();
        h.update(b"WTAS_combiner");
        h.update(message);
        h.update(bctx.r_eff.compress().as_bytes());
        h.update(s_agg.as_bytes());
        h.update(bctx.k_agg.compress().as_bytes());
        let digest = h.finalize();

        // Ed25519 Schnorr-like signing with our keys
        let k = random_scalar();
        let big_r = ED25519_BASEPOINT_TABLE * &k;
        let c = {
            let mut h2 = Sha512::new();
            h2.update(b"WTAS_combiner_challenge");
            h2.update(big_r.compress().as_bytes());
            h2.update(self.combiner_pk.compress().as_bytes());
            h2.update(&digest);
            let mut wide = [0u8; 64];
            wide.copy_from_slice(&h2.finalize());
            Scalar::from_bytes_mod_order_wide(&wide)
        };
        let s = k + c * self.combiner_sk;

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(big_r.compress().as_bytes());
        sig[32..].copy_from_slice(s.as_bytes());
        sig
    }

    /// Verify combiner endorsement on payload (m, R_eff, S, K_agg).
    pub fn verify_combiner_endorsement(
        combiner_pk: &EdwardsPoint, message: &[u8],
        r_eff: &EdwardsPoint, k_agg: &EdwardsPoint,
        s_agg: &Scalar, combiner_sig: &[u8; 64],
    ) -> bool {
        let big_r = match CompressedEdwardsY::from_slice(&combiner_sig[..32]) {
            Ok(compressed) => match compressed.decompress() {
                Some(p) => p, None => return false,
            },
            Err(_) => return false,
        };
        let s_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b.copy_from_slice(&combiner_sig[32..64]);
            b
        };
        let s = match Scalar::from_canonical_bytes(s_bytes).into() {
            Some(sc) => sc, None => return false,
        };

        let mut h = Sha512::new();
        h.update(b"WTAS_combiner");
        h.update(message);
        h.update(r_eff.compress().as_bytes());
        h.update(s_agg.as_bytes());
        h.update(k_agg.compress().as_bytes());
        let digest = h.finalize();

        let c = {
            let mut h2 = Sha512::new();
            h2.update(b"WTAS_combiner_challenge");
            h2.update(big_r.compress().as_bytes());
            h2.update(combiner_pk.compress().as_bytes());
            h2.update(&digest);
            let mut wide = [0u8; 64];
            wide.copy_from_slice(&h2.finalize());
            Scalar::from_bytes_mod_order_wide(&wide)
        };

        let lhs = ED25519_BASEPOINT_TABLE * &s;
        let rhs = big_r + combiner_pk * c;
        lhs.compress() == rhs.compress()
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
    // Verification: [s]B == R_eff + [c]K_agg
    //   where K_agg = Σ_{i∈active} w_i · pk_i
    //   c = H2(R_eff, K_agg, m)  — derived from public values only
    // ============================================================
    pub fn verify(&self, full_sig: &WtasFullSignature, active: &[usize], message: &[u8]) -> (bool, Duration) {
        let sig = &full_sig.sig;
        let t0 = Instant::now();

        // Compute K_agg and challenge from public inputs
        // c = SHA-512(R_eff || K_agg || m) — standard Ed25519, matches precompile
        let k_agg = self.active_group_pk(active);
        let c = {
            let mut h = Sha512::new();
            h.update(sig.r_agg.compress().as_bytes());
            h.update(k_agg.compress().as_bytes());
            h.update(message);
            let mut wide = [0u8; 64];
            wide.copy_from_slice(&h.finalize());
            Scalar::from_bytes_mod_order_wide(&wide)
        };

        // 1. Verify core EdDSA equation: [s]B == R_eff + [c]K_agg
        let lhs = ED25519_BASEPOINT_TABLE * &sig.s_agg;
        let rhs = sig.r_agg + k_agg * c;
        if lhs.compress() != rhs.compress() {
            return (false, t0.elapsed());
        }

        // 2. Verify combiner endorsement on (m, R_eff, s_agg, K_agg)
        if !Self::verify_combiner_endorsement(
            &full_sig.combiner_pk, message, &sig.r_agg, &k_agg,
            &sig.s_agg, &full_sig.combiner_sig,
        ) {
            return (false, t0.elapsed());
        }

        (true, t0.elapsed())
    }

    /// Verify signature with pre-computed binding context (for benchmarks).
    pub fn verify_with_bctx(&self, sig: &WtasSignature, bctx: &BindingContext) -> (bool, Duration) {
        let t0 = Instant::now();
        let lhs = ED25519_BASEPOINT_TABLE * &sig.s_agg;
        let rhs = sig.r_agg + bctx.k_agg * bctx.challenge;
        let ok = lhs.compress() == rhs.compress();
        (ok, t0.elapsed())
    }

    // ============================================================
    // ElGamal encryption for accountability (Ristretto-based)
    // C_i = (U_i, V_i) where:
    //   U_i = r_enc,i · G
    //   V_i = r_enc,i · tracer_pk + b_i · B
    // Returns: (ciphertexts, r_enc vector, b vector)
    // ============================================================
    pub fn encrypt_participation_ristretto(
        &self, active: &[usize],
    ) -> (Vec<ElGamalCiphertext>, Vec<Scalar>, Vec<Scalar>) {
        let mut cts = Vec::with_capacity(self.n);
        let mut r_enc_vec = Vec::with_capacity(self.n);
        let mut b_vec = Vec::with_capacity(self.n);
        for i in 0..self.n {
            let b_i = if active.contains(&i) { Scalar::ONE } else { Scalar::ZERO };
            let r_enc = random_scalar();
            let u_i = self.zk_params.G * r_enc;
            let v_i = self.tracer_pk * r_enc + self.zk_params.B * b_i;
            cts.push(ElGamalCiphertext { u: u_i, v: v_i });
            r_enc_vec.push(r_enc);
            b_vec.push(b_i);
        }
        (cts, r_enc_vec, b_vec)
    }

    /// Get just the V_i values from ciphertexts (for NIZK proof input).
    pub fn ciphertexts_v_only(cts: &[ElGamalCiphertext]) -> Vec<RistrettoPoint> {
        cts.iter().map(|c| c.v).collect()
    }

    // ============================================================
    // Trace: decrypt ElGamal ciphertexts to identify active signers.
    // For each i: compute M_i = V_i - tsk · U_i
    //   If M_i == B → b_i = 1 (participated)
    //   If M_i == O → b_i = 0 (absent)
    // ============================================================
    pub fn trace(
        &self, cts: &[ElGamalCiphertext],
    ) -> Vec<usize> {
        let mut active_signers = Vec::new();
        for i in 0..self.n {
            let m_i = cts[i].v - cts[i].u * self.tracer_sk;
            if m_i == self.zk_params.B {
                active_signers.push(i);
            } else if m_i != RistrettoPoint::identity() {
                // Ciphertext is malformed — skip this signer
                continue;
            }
        }
        active_signers
    }

    /// Trace and verify: compare trace result with expected active set.
    pub fn trace_and_verify(
        &self, cts: &[ElGamalCiphertext], expected: &[usize],
    ) -> bool {
        let traced = self.trace(cts);
        if traced.len() != expected.len() { return false; }
        for &i in expected {
            if !traced.contains(&i) { return false; }
        }
        true
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
        let (ciphertexts, r_enc_vec, b_vec) = self.encrypt_participation_ristretto(active);
        let ciphertexts_v = Self::ciphertexts_v_only(&ciphertexts);

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
        let cts_for_proof = ciphertexts_v.clone();

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

        WtasAccountabilityProof { zk_proof, proof_bytes, prove_us, ciphertexts_v: cts_for_proof }
    }

    // ============================================================
    // NIZK Accountability Proof (verification)
    // ============================================================
    pub fn verify_accountability(
        &self, active: &[usize], proof: &WtasAccountabilityProof,
    ) -> (bool, Duration) {
        let ciphertexts_v = proof.ciphertexts_v.clone();

        let participant_keys: Vec<RistrettoPoint> = self.signers.iter()
            .map(|s| s.pk_ristretto).collect();

        let mut k_agg = RistrettoPoint::identity();
        for &i in active {
            k_agg += self.signers[i].pk_ristretto;
        }

        // Build b_vec from active set (used in prover to compute t = Σ b_i·w_i)
        let w_scalars: Vec<Scalar> = self.weights.iter().map(|w| Scalar::from(*w)).collect();
        let mut b_vec = vec![Scalar::ZERO; self.n];
        for &i in active { b_vec[i] = Scalar::ONE; }
        let mut t = Scalar::ZERO;
        for i in 0..self.n {
            t += b_vec[i] * w_scalars[i];
        }

        let rho_w = random_scalar();
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
    let mut best_bctx = Duration::MAX;
    for _ in 0..iters {
        let (sig, dt1, dt_bctx, dt2, _) = group.sign(&active, message);
        best_round1 = best_round1.min(dt1);
        best_bctx = best_bctx.min(dt_bctx);
        best_round2 = best_round2.min(dt2);
        std::hint::black_box(&sig);
    }
    fmt_rate("round1 (dual nonces)", best_round1, k);
    fmt_rate("coordination (Bctx)", best_bctx, k);
    fmt_rate("round2 (partial sig)", best_round2, k);
    let total_sign = best_round1 + best_round2 + best_bctx;
    fmt_rate("TOTAL sign", total_sign, 1);

    // Verify
    let (sig, _, _, _, _) = group.sign(&active, message);
    let mut best_verify = Duration::MAX;
    for _ in 0..iters {
        let (ok, dt) = group.verify(&sig, &active, message);
        if ok { best_verify = best_verify.min(dt); }
    }
    fmt_rate("verify", best_verify, 1);

    // Combiner endorsement
    let k_agg = group.active_group_pk(&active);
    let mut best_combine = Duration::MAX;
    for _ in 0..iters {
        let t0 = Instant::now();
        let ok = WtasGroup::verify_combiner_endorsement(
            &sig.combiner_pk, message,
            &sig.sig.r_agg, &k_agg,
            &sig.sig.s_agg, &sig.combiner_sig,
        );
        best_combine = best_combine.min(t0.elapsed());
        std::hint::black_box(&ok);
    }
    fmt_rate("combiner verify", best_combine, 1);

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

    // Trace: decrypt ElGamal ciphertexts to identify signers
    let (trace_cts, _, _) = group.encrypt_participation_ristretto(&active);
    let mut best_trace = Duration::MAX;
    for _ in 0..iters.min(50) {
        let t0 = Instant::now();
        let traced = group.trace(&trace_cts);
        best_trace = best_trace.min(t0.elapsed());
        std::hint::black_box(&traced);
    }
    fmt_rate("trace (decrypt)", best_trace, num_signers);
    let traced = group.trace(&trace_cts);
    let trace_ok = group.trace_and_verify(&trace_cts, &active);
    println!("Trace result: {} signers identified, match={}",
        traced.len(), if trace_ok { "✓" } else { "✗" });

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

        // API sign with full dual-nonce protocol
        let (full_sig, _, _, _, _) = g.sign(&[0], msg);
        let (ok, _) = g.verify(&full_sig, &[0], msg);
        assert!(ok, "sig verification failed");

        // Verify combiner endorsement
        let k_agg = g.active_group_pk(&[0]);
        assert!(WtasGroup::verify_combiner_endorsement(
            &full_sig.combiner_pk, msg,
            &full_sig.sig.r_agg, &k_agg,
            &full_sig.sig.s_agg, &full_sig.combiner_sig,
        ), "combiner sig invalid");
    }

    #[test]
    fn test_verify_rejects_wrong_message() {
        let w = vec![1, 1];
        let g = WtasGroup::setup(2, &w, 1);
        let (active, _) = g.select_signers();
        let (full_sig, _, _, _, _) = g.sign(&active, b"hello");
        let (ok, _) = g.verify(&full_sig, &active, b"wrong");
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

    #[test]
    fn test_trace_decrypt_identifies_active_signers() {
        let w = vec![1, 2, 3, 4];
        let g = WtasGroup::setup(4, &w, 6);
        let active = vec![0, 1, 2]; // weight 1+2+3=6 ≥ 6
        let (cts, _, _) = g.encrypt_participation_ristretto(&active);
        let traced = g.trace(&cts);
        assert_eq!(traced.len(), active.len());
        for i in &active {
            assert!(traced.contains(i), "Signer {i} should be traced as active");
        }
    }

    #[test]
    fn test_trace_all_active() {
        let w = vec![1, 1, 1, 1];
        let g = WtasGroup::setup(4, &w, 4);
        let active = vec![0, 1, 2, 3];
        let (cts, _, _) = g.encrypt_participation_ristretto(&active);
        assert!(g.trace_and_verify(&cts, &active));
    }

    #[test]
    fn test_trace_none_active() {
        let w = vec![1, 1, 1, 1];
        let g = WtasGroup::setup(4, &w, 1);
        let active: Vec<usize> = vec![];
        let (cts, _, _) = g.encrypt_participation_ristretto(&active);
        let traced = g.trace(&cts);
        assert!(traced.is_empty());
    }

    #[test]
    fn test_trace_does_not_include_inactive() {
        let w = vec![1, 2, 3, 4, 5];
        let g = WtasGroup::setup(5, &w, 4);
        let active = vec![0, 3]; // weight 1+4=5 ≥ 4
        let (cts, _, _) = g.encrypt_participation_ristretto(&active);
        let traced = g.trace(&cts);
        // signers 1, 2, 4 should NOT be in traced
        for &inactive in &[1, 2, 4] {
            assert!(!traced.contains(&inactive),
                "Signer {inactive} should NOT be traced as active");
        }
    }

    /// Manual end-to-end verification using full dual-nonce protocol.
    fn manual_sign_verify(g: &WtasGroup, active: &[usize], msg: &[u8]) -> bool {
        let nonces = g.round1_dual_nonces(active, msg);
        let bctx = g.make_binding_context(active, &nonces, msg);
        let partials = g.round2_partial_sign(&nonces, &bctx);
        let s_agg: Scalar = partials.into_iter().sum();
        let lhs: EdwardsPoint = ED25519_BASEPOINT_TABLE * &s_agg;
        let rhs = bctx.r_eff + bctx.k_agg * bctx.challenge;
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

            // Manual verification with dual-nonce protocol
            assert!(manual_sign_verify(&g, &active, msg), "manual n={n} k={}", active.len());

            // API
            let (full_sig, _, _, _, _) = g.sign(&active, msg);
            let (ok, _) = g.verify(&full_sig, &active, msg);
            assert!(ok, "API n={n} k={}", active.len());
        }
    }

    #[test]
    fn test_combiner_endorsement_rejects_wrong_key() {
        let w = vec![1, 2, 3];
        let g = WtasGroup::setup(3, &w, 5);
        let msg = b"test";
        let (full_sig, _, _, _, _) = g.sign(&[0, 1, 2], msg);
        // Use a wrong combiner public key
        let wrong_pk = ED25519_BASEPOINT_TABLE * &random_scalar();
        let k_agg = g.active_group_pk(&[0, 1, 2]);
        assert!(!WtasGroup::verify_combiner_endorsement(
            &wrong_pk, msg,
            &full_sig.sig.r_agg, &k_agg,
            &full_sig.sig.s_agg, &full_sig.combiner_sig,
        ));
    }
}
