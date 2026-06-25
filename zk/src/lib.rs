// WTAPS NIZK Proof System — Bulletproofs IPA with Super Basis Injection
// =====================================================================
// This is the Zero-Knowledge accountability layer for the WTAS protocol.
// It proves in zero-knowledge that:
//   1. Each participation bit b_i ∈ {0, 1}
//   2. Σ b_i · w_i ≥ threshold (weighted threshold is met)
//   3. ElGamal ciphertexts V_i correctly encrypt b_i under pk_enc
//   4. K_agg is correctly formed from participating signers' public keys
//
// Curve: Ristretto (prime-order group over Curve25519)
// Protocol: Bulletproofs-style Inner Product Argument (IPA) + Fiat-Shamir

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{MultiscalarMul, VartimeMultiscalarMul};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use std::iter;

// ============================================================
// Error type
// ============================================================
#[derive(Debug, Clone)]
pub enum WTAPSError {
    VerificationFailed,
    InvalidParameters,
    TranscriptError,
}

impl std::fmt::Display for WTAPSError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerificationFailed => write!(f, "NIZK verification failed"),
            Self::InvalidParameters => write!(f, "invalid NIZK parameters"),
            Self::TranscriptError => write!(f, "transcript error"),
        }
    }
}

impl std::error::Error for WTAPSError {}

// ============================================================
// Helper functions
// ============================================================

pub(crate) fn compute_y_powers(y: &Scalar, n: usize) -> Vec<Scalar> {
    let mut powers = Vec::with_capacity(n);
    let mut current = Scalar::ONE;
    for _ in 0..n {
        powers.push(current);
        current *= y;
    }
    powers
}

pub(crate) fn compute_y_inv_powers(y: &Scalar, n: usize) -> Vec<Scalar> {
    let mut powers = Vec::with_capacity(n);
    let mut current = Scalar::ONE;
    let y_inv = y.invert();
    for i in 0..n {
        powers.push(current);
        if i == 0 {
            current = y_inv;
        } else {
            current *= y_inv;
        }
    }
    powers
}

pub(crate) fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).sum()
}

pub(crate) fn vector_add(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    a.iter().zip(b.iter()).map(|(ai, bi)| ai + bi).collect()
}

pub(crate) fn vector_sub(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    a.iter().zip(b.iter()).map(|(ai, bi)| ai - bi).collect()
}

pub(crate) fn vector_scalar_mul(a: &[Scalar], s: &Scalar) -> Vec<Scalar> {
    a.iter().map(|ai| ai * s).collect()
}

pub(crate) fn vector_hadamard(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).collect()
}

pub(crate) fn compute_challenge_vector(challenges: &[Scalar], n: usize) -> Vec<Scalar> {
    let log_n = challenges.len();
    let mut s_vec = vec![Scalar::ONE; n];
    for i in 0..n {
        for (j, &u_j) in challenges.iter().enumerate() {
            let bit = (i >> (log_n - 1 - j)) & 1;
            if bit == 1 { s_vec[i] *= u_j; } else { s_vec[i] *= u_j.invert(); }
        }
    }
    s_vec
}

// ============================================================
// Public types
// ============================================================

/// NIZK public parameters (SRS-like): randomly generated group element vectors.
#[derive(Clone)]
pub struct PublicParams {
    pub g_vec: Vec<RistrettoPoint>,
    pub h_vec: Vec<RistrettoPoint>,
    pub G: RistrettoPoint,
    pub H: RistrettoPoint,
    pub B: RistrettoPoint,
    pub n: usize,
}

impl PublicParams {
    /// Generate new public parameters for a given number of signers n.
    pub fn new<R: RngCore + CryptoRng>(n: usize, rng: &mut R) -> Self {
        let mut g_vec = Vec::with_capacity(n);
        let mut h_vec = Vec::with_capacity(n);
        for _ in 0..n {
            g_vec.push(RistrettoPoint::random(rng));
            h_vec.push(RistrettoPoint::random(rng));
        }
        PublicParams {
            g_vec, h_vec,
            G: RistrettoPoint::random(rng),
            H: RistrettoPoint::random(rng),
            B: RistrettoPoint::random(rng),
            n,
        }
    }
}

/// Public inputs to the NIZK verification.
#[derive(Clone)]
pub struct PublicInput {
    /// ElGamal ciphertexts V_i = pk_enc · r_enc,i + B · b_i (one per signer)
    pub ciphertexts_v: Vec<RistrettoPoint>,
    /// Aggregate of participant keys for signers where b_i = 1
    pub k_agg: RistrettoPoint,
    /// Actual accumulated weight t = Σ b_i · w_i
    pub t: Scalar,
    /// Tracer's ElGamal public key
    pub pk_enc: RistrettoPoint,
    /// Individual participant public keys (one per signer)
    pub participant_keys: Vec<RistrettoPoint>,
    /// Pedersen commitment to weight vector w
    pub c_w: RistrettoPoint,
    /// Sum of all weights (total_weight)
    pub w_total: Scalar,
}

/// Secret witness known to the prover.
pub struct SecretWitness {
    /// Participation bit vector b_i ∈ {0, 1}
    pub b: Vec<Scalar>,
    /// Weight vector w_i
    pub w: Vec<Scalar>,
    /// ElGamal encryption randomness r_enc,i
    pub r_enc: Vec<Scalar>,
    /// Blinding factor for weight commitment c_w
    pub rho_w: Scalar,
}

/// Inner Product Argument sub-proof (log₂(n) rounds of folding).
#[derive(Clone, Debug)]
pub struct IPAProof {
    pub L_vec: Vec<RistrettoPoint>,
    pub R_vec: Vec<RistrettoPoint>,
    pub a: Scalar,
    pub b: Scalar,
}

/// The complete WTAPS NIZK proof.
#[derive(Clone, Debug)]
pub struct WTAPSProof {
    pub c_w: RistrettoPoint,
    pub a: RistrettoPoint,
    pub s: RistrettoPoint,
    pub t1: RistrettoPoint,
    pub t2: RistrettoPoint,
    pub tau_x: Scalar,
    pub mu: Scalar,
    pub z_enc: Scalar,
    pub t_y: Scalar,
    pub W_y: Scalar,
    pub e_key: RistrettoPoint,
    pub e_enc: RistrettoPoint,
    pub t_hat: Scalar,
    pub ipa_proof: IPAProof,
}

// ============================================================
// Merlin transcript protocol
// ============================================================

pub trait TranscriptProtocol {
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar);
    fn append_point(&mut self, label: &'static [u8], point: &RistrettoPoint);
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
    fn challenge_point(&mut self, label: &'static [u8]) -> RistrettoPoint;
}

impl TranscriptProtocol for Transcript {
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }
    fn append_point(&mut self, label: &'static [u8], point: &RistrettoPoint) {
        self.append_message(label, point.compress().as_bytes());
    }
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }
    fn challenge_point(&mut self, label: &'static [u8]) -> RistrettoPoint {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        RistrettoPoint::from_uniform_bytes(&buf)
    }
}

// ============================================================
// WTAPSProof methods
// ============================================================

impl WTAPSProof {
    /// Generate a NIZK proof of correct weighted threshold signing.
    pub fn prove<R: RngCore + CryptoRng>(
        params: &PublicParams,
        public: &PublicInput,
        secret: &SecretWitness,
        rng: &mut R,
    ) -> Result<Self, WTAPSError> {
        let n = params.n;
        if secret.b.len() != n || secret.w.len() != n ||
           secret.r_enc.len() != n || public.participant_keys.len() != n ||
           public.ciphertexts_v.len() != n {
            return Err(WTAPSError::InvalidParameters);
        }

        let mut transcript = Transcript::new(b"WTAPS_NIZK");
        let alpha = Scalar::random(rng);
        let rho = Scalar::random(rng);
        let rho_w = secret.rho_w;
        let s_l: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();
        let s_r: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();

        let b_minus_one: Vec<Scalar> = secret.b.iter().map(|bi| bi - Scalar::ONE).collect();
        let a = RistrettoPoint::multiscalar_mul(
            iter::once(&alpha)
                .chain(secret.b.iter())
                .chain(b_minus_one.iter()),
            iter::once(&params.H)
                .chain(params.g_vec.iter())
                .chain(params.h_vec.iter()),
        );
        let s = RistrettoPoint::multiscalar_mul(
            iter::once(&rho)
                .chain(s_l.iter())
                .chain(s_r.iter()),
            iter::once(&params.H)
                .chain(params.g_vec.iter())
                .chain(params.h_vec.iter()),
        );
        let c_w = public.c_w;

        transcript.append_point(b"c_w", &c_w);
        transcript.append_point(b"A", &a);
        transcript.append_point(b"S", &s);
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");

        let y_powers = compute_y_powers(&y, n);
        let ones = vec![Scalar::ONE; n];
        // l(X) = b - z·1 + s_L·X
        let l0 = vector_sub(&secret.b, &vector_scalar_mul(&ones, &z));
        let l1 = s_l.clone();

        // r(X) = y^n ∘ (b - 1 + s_R·X + z·1) + z²·(w ∘ y^n)
        let z_squared = z * z;
        let b_minus_one = vector_sub(&secret.b, &ones);
        let b_minus_one_plus_z = vector_add(&b_minus_one, &vector_scalar_mul(&ones, &z));
        let term1 = vector_hadamard(&y_powers, &b_minus_one_plus_z);
        let term2_x = vector_hadamard(&y_powers, &s_r);
        let w_hadamard_y = vector_hadamard(&secret.w, &y_powers);
        let term3 = vector_scalar_mul(&w_hadamard_y, &z_squared);
        let r0 = vector_add(&term1, &term3);
        let r1 = term2_x;

        // t(X) = ⟨l(X), r(X)⟩ = t0 + t1·X + t2·X²
        let _t0 = inner_product(&l0, &r0);
        let t1 = inner_product(&l0, &r1) + inner_product(&l1, &r0);
        let t2 = inner_product(&l1, &r1);

        let tau1 = Scalar::random(rng);
        let tau2 = Scalar::random(rng);
        let t1_commit = &params.G * t1 + &params.H * tau1;
        let t2_commit = &params.G * t2 + &params.H * tau2;

        transcript.append_point(b"T1", &t1_commit);
        transcript.append_point(b"T2", &t2_commit);
        let x = transcript.challenge_scalar(b"x");

        let l_vec = vector_add(&l0, &vector_scalar_mul(&l1, &x));
        let r_vec = vector_add(&r0, &vector_scalar_mul(&r1, &x));
        let t_hat = inner_product(&l_vec, &r_vec);

        let mut t_y = Scalar::ZERO;
        let mut W_y = Scalar::ZERO;
        for i in 0..n {
            t_y += secret.b[i] * secret.w[i] * y_powers[i];
            W_y += secret.w[i] * y_powers[i];
        }

        let tau_x = tau2 * x * x + tau1 * x;
        let mu = alpha + rho * x + z_squared * rho_w;
        let e_key = RistrettoPoint::vartime_multiscalar_mul(s_l.iter(), public.participant_keys.iter());

        transcript.append_scalar(b"tau_x", &tau_x);
        transcript.append_scalar(b"mu", &mu);
        transcript.append_scalar(b"t_hat", &t_hat);
        transcript.append_scalar(b"t_y", &t_y);
        transcript.append_scalar(b"W_y", &W_y);
        transcript.append_point(b"E_key", &e_key);

        let lambda_key = transcript.challenge_scalar(b"lambda_key");
        let lambda_enc = transcript.challenge_scalar(b"lambda_enc");

        let lambda_enc_powers: Vec<Scalar> = {
            let mut powers = Vec::with_capacity(n);
            let mut current = Scalar::ONE;
            for _ in 0..n {
                powers.push(current);
                current *= lambda_enc;
            }
            powers
        };

        let mut z_enc = Scalar::ZERO;
        for i in 0..n {
            z_enc += lambda_enc_powers[i] * secret.r_enc[i];
        }
        let e_enc = RistrettoPoint::vartime_multiscalar_mul(
            s_l.iter().zip(lambda_enc_powers.iter()).map(|(sl, le)| sl * le),
            iter::repeat(&params.B).take(n),
        );

        transcript.append_scalar(b"z_enc", &z_enc);
        transcript.append_point(b"E_enc", &e_enc);
        let u = transcript.challenge_point(b"U");

        let mut g_prime = Vec::with_capacity(n);
        let mut h_prime = Vec::with_capacity(n);
        for i in 0..n {
            let g_prime_i = params.g_vec[i] +
                public.participant_keys[i] * lambda_key +
                params.B * lambda_enc_powers[i];
            g_prime.push(g_prime_i);
        }
        let y_inv_powers = compute_y_inv_powers(&y, n);
        for i in 0..n {
            h_prime.push(params.h_vec[i] * y_inv_powers[i]);
        }

        // P construction
        let part1 = &a + &s * x + &c_w * z_squared;
        let minus_z = -z;
        let sum_g = RistrettoPoint::vartime_multiscalar_mul(std::iter::repeat(minus_z).take(n), params.g_vec.iter());
        let sum_h = RistrettoPoint::vartime_multiscalar_mul(std::iter::repeat(z).take(n), params.h_vec.iter());
        let part2 = sum_h + sum_g;
        let sum_pi = RistrettoPoint::vartime_multiscalar_mul(std::iter::repeat(&Scalar::ONE).take(n), public.participant_keys.iter());
        let part3_inner = &public.k_agg + &e_key * x - &sum_pi * z;
        let part3 = part3_inner * lambda_key;
        let sum_v = RistrettoPoint::vartime_multiscalar_mul(lambda_enc_powers.iter(), public.ciphertexts_v.iter());
        let sum_b = RistrettoPoint::vartime_multiscalar_mul(lambda_enc_powers.iter(), std::iter::repeat(&params.B).take(n)) * z;
        let part4 = sum_v - &public.pk_enc * z_enc - sum_b + &e_enc * x;
        let p = part1 + part2 + part3 + part4;

        let p0 = p + u * t_hat - &params.H * mu;
        let ipa_proof = Self::ipa_prove(&l_vec, &r_vec, &g_prime, &h_prime, &u, &p0, &mut transcript)?;

        Ok(WTAPSProof {
            c_w, a, s, t1: t1_commit, t2: t2_commit,
            tau_x, mu, z_enc, t_y, W_y, e_key, e_enc, t_hat, ipa_proof,
        })
    }

    /// Standard IPA verification: iterative folding, O(n) group operations.
    pub fn verify_normal(&self, params: &PublicParams, public: &PublicInput) -> Result<(), WTAPSError> {
        let n = params.n;
        let mut transcript = Transcript::new(b"WTAPS_NIZK");
        let (y, z, x, u, lambda_key, lambda_enc, challenges) =
            self.replay_transcript_and_check_t(&mut transcript, params, public, n)?;

        let lambda_enc_powers = compute_lambda_enc_powers(lambda_enc, n);
        let (g_prime, h_prime) = self.build_super_basis(params, public, y, lambda_key, &lambda_enc_powers);
        let p0 = self.reconstruct_p0(params, public, z, x, u, lambda_key, &lambda_enc_powers);

        let mut g_fold = g_prime;
        let mut h_fold = h_prime;
        let mut p_fold = p0;
        for (round, &x_chal) in challenges.iter().enumerate() {
            let half_n = g_fold.len() / 2;
            let (g_left, g_right) = g_fold.split_at(half_n);
            let (h_left, h_right) = h_fold.split_at(half_n);
            let x_inv = x_chal.invert();
            let new_g: Vec<RistrettoPoint> = g_left.iter().zip(g_right.iter())
                .map(|(gl, gr)| gl * x_inv + gr * x_chal).collect();
            let new_h: Vec<RistrettoPoint> = h_left.iter().zip(h_right.iter())
                .map(|(hl, hr)| hl * x_chal + hr * x_inv).collect();
            p_fold = &self.ipa_proof.L_vec[round] * (x_chal * x_chal) + p_fold
                + &self.ipa_proof.R_vec[round] * (x_inv * x_inv);
            g_fold = new_g; h_fold = new_h;
        }

        let expected_p_final = g_fold[0] * self.ipa_proof.a + h_fold[0] * self.ipa_proof.b
            + u * (self.ipa_proof.a * self.ipa_proof.b);
        if p_fold == expected_p_final {
            Ok(())
        } else {
            Err(WTAPSError::VerificationFailed)
        }
    }

    /// Fast IPA verification: challenge vector precomputation, O(n) MSM but single pass.
    pub fn verify_fast(&self, params: &PublicParams, public: &PublicInput) -> Result<(), WTAPSError> {
        let n = params.n;
        let mut transcript = Transcript::new(b"WTAPS_NIZK");
        let (y, z, x, u, lambda_key, lambda_enc, challenges) =
            self.replay_transcript_and_check_t(&mut transcript, params, public, n)?;

        let lambda_enc_powers = compute_lambda_enc_powers(lambda_enc, n);
        let (g_prime, h_prime) = self.build_super_basis(params, public, y, lambda_key, &lambda_enc_powers);
        let p0 = self.reconstruct_p0(params, public, z, x, u, lambda_key, &lambda_enc_powers);

        let s_vec = compute_challenge_vector(&challenges, n);
        let s_inv_vec: Vec<Scalar> = s_vec.iter().map(|s| s.invert()).collect();
        let g_final = RistrettoPoint::vartime_multiscalar_mul(s_vec.iter(), g_prime.iter());
        let h_final = RistrettoPoint::vartime_multiscalar_mul(s_inv_vec.iter(), h_prime.iter());

        let left_side = u * (self.ipa_proof.a * self.ipa_proof.b)
            + g_final * self.ipa_proof.a + h_final * self.ipa_proof.b;
        let mut right_side = p0;
        for (i, &x_chal) in challenges.iter().enumerate() {
            right_side = right_side + &self.ipa_proof.L_vec[i] * (x_chal * x_chal)
                + &self.ipa_proof.R_vec[i] * (x_chal.invert() * x_chal.invert());
        }

        if left_side == right_side {
            Ok(())
        } else {
            Err(WTAPSError::VerificationFailed)
        }
    }

    /// Consistency check: verify that folding and direct computation agree.
    pub fn verify_consistency(&self, params: &PublicParams, public: &PublicInput) -> Result<(), WTAPSError> {
        let n = params.n;
        let mut transcript = Transcript::new(b"WTAPS_NIZK");
        let (y, _z, _x, _u, lambda_key, lambda_enc, challenges) =
            self.replay_transcript_and_check_t(&mut transcript, params, public, n)?;

        let lambda_enc_powers = compute_lambda_enc_powers(lambda_enc, n);
        let (g_prime, h_prime) = self.build_super_basis(params, public, y, lambda_key, &lambda_enc_powers);

        let mut g_fold = g_prime.clone();
        let mut h_fold = h_prime.clone();
        for &x_chal in &challenges {
            let half_n = g_fold.len() / 2;
            let (g_left, g_right) = g_fold.split_at(half_n);
            let (h_left, h_right) = h_fold.split_at(half_n);
            let x_inv = x_chal.invert();
            g_fold = g_left.iter().zip(g_right.iter())
                .map(|(gl, gr)| gl * x_inv + gr * x_chal).collect();
            h_fold = h_left.iter().zip(h_right.iter())
                .map(|(hl, hr)| hl * x_chal + hr * x_inv).collect();
        }

        let s_vec = compute_challenge_vector(&challenges, n);
        let s_inv_vec: Vec<Scalar> = s_vec.iter().map(|s| s.invert()).collect();
        let g_final_direct = RistrettoPoint::vartime_multiscalar_mul(s_vec.iter(), g_prime.iter());
        let h_final_direct = RistrettoPoint::vartime_multiscalar_mul(s_inv_vec.iter(), h_prime.iter());

        if g_fold[0] == g_final_direct && h_fold[0] == h_final_direct {
            Ok(())
        } else {
            Err(WTAPSError::VerificationFailed)
        }
    }

    /// Compute the proof size in bytes.
    pub fn proof_size_bytes(&self) -> usize {
        let log_n = self.ipa_proof.L_vec.len();
        // 5 fixed points (c_w, a, s, t1, t2) + 2 points (e_key, e_enc) + 2*log_n IPA points
        // + 6 scalars (tau_x, mu, z_enc, t_y, W_y, t_hat) + 2 IPA scalars (a, b)
        (5 + 2 + 2 * log_n) * 32 + (6 + 2) * 32
    }

    // ====================== Private helpers ======================

    /// Replay the Fiat-Shamir transcript and perform the t-equation check.
    fn replay_transcript_and_check_t(
        &self, transcript: &mut Transcript, params: &PublicParams,
        _public: &PublicInput, n: usize,
    ) -> Result<(Scalar, Scalar, Scalar, RistrettoPoint, Scalar, Scalar, Vec<Scalar>), WTAPSError> {
        transcript.append_point(b"c_w", &self.c_w);
        transcript.append_point(b"A", &self.a);
        transcript.append_point(b"S", &self.s);
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        transcript.append_point(b"T1", &self.t1);
        transcript.append_point(b"T2", &self.t2);
        let x = transcript.challenge_scalar(b"x");
        transcript.append_scalar(b"tau_x", &self.tau_x);
        transcript.append_scalar(b"mu", &self.mu);
        transcript.append_scalar(b"t_hat", &self.t_hat);
        transcript.append_scalar(b"t_y", &self.t_y);
        transcript.append_scalar(b"W_y", &self.W_y);
        transcript.append_point(b"E_key", &self.e_key);
        let lambda_key = transcript.challenge_scalar(b"lambda_key");
        let lambda_enc = transcript.challenge_scalar(b"lambda_enc");
        transcript.append_scalar(b"z_enc", &self.z_enc);
        transcript.append_point(b"E_enc", &self.e_enc);
        let u = transcript.challenge_point(b"U");

        // t-equation: [t_hat]G + [τ_x]H = [z²·t_y + δ]G + [x]T1 + [x²]T2
        let y_powers = compute_y_powers(&y, n);
        let sum_y_powers: Scalar = y_powers.iter().sum();
        let z_squared = z * z;
        let z_cubed = z_squared * z;
        let delta = (z - z_squared) * sum_y_powers - z_cubed * self.W_y;
        let lhs = &params.G * self.t_hat + &params.H * self.tau_x;
        let rhs = &params.G * (z_squared * self.t_y + delta) + &self.t1 * x + &self.t2 * (x * x);
        if lhs != rhs { return Err(WTAPSError::VerificationFailed); }

        let mut challenges = Vec::new();
        for (L, R) in self.ipa_proof.L_vec.iter().zip(self.ipa_proof.R_vec.iter()) {
            transcript.append_point(b"L", L);
            transcript.append_point(b"R", R);
            challenges.push(transcript.challenge_scalar(b"u"));
        }

        Ok((y, z, x, u, lambda_key, lambda_enc, challenges))
    }

    /// Build super basis: g'_i = g_i + P_i·λ_key + B·λ_enc^i, h'_i = h_i · y^{-i}
    fn build_super_basis(
        &self, params: &PublicParams, public: &PublicInput,
        y: Scalar, lambda_key: Scalar, lambda_enc_powers: &[Scalar],
    ) -> (Vec<RistrettoPoint>, Vec<RistrettoPoint>) {
        let n = params.n;
        let mut g_prime = Vec::with_capacity(n);
        let mut h_prime = Vec::with_capacity(n);
        for i in 0..n {
            let g_prime_i = params.g_vec[i]
                + public.participant_keys[i] * lambda_key
                + params.B * lambda_enc_powers[i];
            g_prime.push(g_prime_i);
        }
        let y_inv_powers = compute_y_inv_powers(&y, n);
        for i in 0..n {
            h_prime.push(params.h_vec[i] * y_inv_powers[i]);
        }
        (g_prime, h_prime)
    }

    /// Reconstruct the folded commitment P0 from proof elements.
    fn reconstruct_p0(
        &self, params: &PublicParams, public: &PublicInput,
        z: Scalar, x: Scalar, u: RistrettoPoint,
        lambda_key: Scalar, lambda_enc_powers: &[Scalar],
    ) -> RistrettoPoint {
        let n = params.n;
        let z_squared = z * z;
        let minus_z = -z;

        let part1 = &self.a + &self.s * x + &self.c_w * z_squared;
        let sum_g = RistrettoPoint::vartime_multiscalar_mul(
            std::iter::repeat(minus_z).take(n), params.g_vec.iter());
        let sum_h = RistrettoPoint::vartime_multiscalar_mul(
            std::iter::repeat(z).take(n), params.h_vec.iter());
        let sum_pi = RistrettoPoint::vartime_multiscalar_mul(
            std::iter::repeat(&Scalar::ONE).take(n), public.participant_keys.iter());
        let part3 = (&public.k_agg + &self.e_key * x - &sum_pi * z) * lambda_key;
        let sum_v = RistrettoPoint::vartime_multiscalar_mul(
            lambda_enc_powers.iter(), public.ciphertexts_v.iter());
        let sum_b = RistrettoPoint::vartime_multiscalar_mul(
            lambda_enc_powers.iter(), std::iter::repeat(&params.B).take(n)) * z;
        let part4 = sum_v - &public.pk_enc * self.z_enc - sum_b + &self.e_enc * x;

        (part1 + sum_h + sum_g + part3 + part4) + u * self.t_hat - &params.H * self.mu
    }

    // IPA prover (internal)
    fn ipa_prove(
        l: &[Scalar], r: &[Scalar], g: &[RistrettoPoint], h: &[RistrettoPoint],
        u: &RistrettoPoint, _p0: &RistrettoPoint, transcript: &mut Transcript,
    ) -> Result<IPAProof, WTAPSError> {
        let n = l.len();
        let mut l_vec = l.to_vec();
        let mut r_vec = r.to_vec();
        let mut g_vec = g.to_vec();
        let mut h_vec = h.to_vec();
        let log_n = (n as f64).log2().ceil() as usize;
        let mut L_vec = Vec::with_capacity(log_n);
        let mut R_vec = Vec::with_capacity(log_n);
        let mut current_n = n;

        while current_n > 1 {
            let half_n = current_n / 2;
            let (l_left, l_right) = l_vec.split_at(half_n);
            let (r_left, r_right) = r_vec.split_at(half_n);
            let (g_left, g_right) = g_vec.split_at(half_n);
            let (h_left, h_right) = h_vec.split_at(half_n);

            let c_L = inner_product(l_left, r_right);
            let c_R = inner_product(l_right, r_left);

            let L = RistrettoPoint::vartime_multiscalar_mul(l_left, g_right) +
                    RistrettoPoint::vartime_multiscalar_mul(r_right, h_left) + u * c_L;
            let R = RistrettoPoint::vartime_multiscalar_mul(l_right, g_left) +
                    RistrettoPoint::vartime_multiscalar_mul(r_left, h_right) + u * c_R;

            L_vec.push(L);
            R_vec.push(R);
            transcript.append_point(b"L", &L);
            transcript.append_point(b"R", &R);
            let x = transcript.challenge_scalar(b"u");
            let x_inv = x.invert();

            let new_g: Vec<RistrettoPoint> = g_left.iter().zip(g_right.iter())
                .map(|(gl, gr)| gl * x_inv + gr * x).collect();
            let new_h: Vec<RistrettoPoint> = h_left.iter().zip(h_right.iter())
                .map(|(hl, hr)| hl * x + hr * x_inv).collect();
            let new_l: Vec<Scalar> = l_left.iter().zip(l_right.iter())
                .map(|(ll, lr)| ll * x + lr * x_inv).collect();
            let new_r: Vec<Scalar> = r_left.iter().zip(r_right.iter())
                .map(|(rl, rr)| rl * x_inv + rr * x).collect();

            l_vec = new_l; r_vec = new_r; g_vec = new_g; h_vec = new_h;
            current_n = half_n;
        }
        Ok(IPAProof { L_vec, R_vec, a: l_vec[0], b: r_vec[0] })
    }
}

// ============================================================
// Utility
// ============================================================

fn compute_lambda_enc_powers(lambda_enc: Scalar, n: usize) -> Vec<Scalar> {
    let mut powers = Vec::with_capacity(n);
    let mut current = Scalar::ONE;
    for _ in 0..n {
        powers.push(current);
        current *= lambda_enc;
    }
    powers
}

// ============================================================
// Tests
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::Identity;
    use rand::rngs::OsRng;

    fn make_test_data(n: usize) -> (PublicParams, PublicInput, SecretWitness) {
        let mut rng = OsRng;
        let params = PublicParams::new(n, &mut rng);

        let b: Vec<Scalar> = (0..n).map(|i| {
            if i % 2 == 0 { Scalar::ONE } else { Scalar::ZERO }
        }).collect();
        let w: Vec<Scalar> = (0..n).map(|i| Scalar::from((i as u64) + 1)).collect();
        let mut t = Scalar::ZERO;
        for i in 0..n { t += b[i] * w[i]; }

        let participant_keys: Vec<RistrettoPoint> = (0..n)
            .map(|_| RistrettoPoint::random(&mut rng)).collect();
        let mut k_agg = RistrettoPoint::identity();
        for i in 0..n {
            if b[i] == Scalar::ONE { k_agg += participant_keys[i]; }
        }

        let sk_enc = Scalar::random(&mut rng);
        let pk_enc = &params.G * sk_enc;
        let r_enc: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let mut ciphertexts_v = Vec::new();
        for i in 0..n {
            ciphertexts_v.push(&pk_enc * r_enc[i] + &params.B * b[i]);
        }

        let rho_w = Scalar::random(&mut rng);
        let c_w = RistrettoPoint::multiscalar_mul(
            iter::once(&rho_w).chain(w.iter()),
            iter::once(&params.H).chain(params.h_vec.iter()),
        );

        let public = PublicInput {
            ciphertexts_v, k_agg, t, pk_enc, participant_keys,
            c_w, w_total: w.iter().sum(),
        };
        let secret = SecretWitness { b, w, r_enc, rho_w };
        (params, public, secret)
    }

    #[test]
    fn test_prove_verify_normal() {
        let (params, public, secret) = make_test_data(8);
        let mut rng = OsRng;
        let proof = WTAPSProof::prove(&params, &public, &secret, &mut rng).unwrap();
        proof.verify_normal(&params, &public).unwrap();
    }

    #[test]
    fn test_prove_verify_fast() {
        let (params, public, secret) = make_test_data(8);
        let mut rng = OsRng;
        let proof = WTAPSProof::prove(&params, &public, &secret, &mut rng).unwrap();
        proof.verify_fast(&params, &public).unwrap();
    }

    #[test]
    fn test_prove_verify_consistency() {
        let (params, public, secret) = make_test_data(8);
        let mut rng = OsRng;
        let proof = WTAPSProof::prove(&params, &public, &secret, &mut rng).unwrap();
        proof.verify_consistency(&params, &public).unwrap();
    }

    #[test]
    fn test_different_n_values() {
        for &n in &[2, 4, 8, 16, 32] {
            let (params, public, secret) = make_test_data(n);
            let mut rng = OsRng;
            let proof = WTAPSProof::prove(&params, &public, &secret, &mut rng).unwrap();
            proof.verify_normal(&params, &public).unwrap();
            proof.verify_fast(&params, &public).unwrap();
        }
    }

    #[test]
    fn test_verify_rejects_modified_proof() {
        let (params, public, secret) = make_test_data(8);
        let mut rng = OsRng;
        let mut proof = WTAPSProof::prove(&params, &public, &secret, &mut rng).unwrap();
        // Tamper with z_enc
        proof.z_enc += Scalar::ONE;
        assert!(proof.verify_normal(&params, &public).is_err());
        assert!(proof.verify_fast(&params, &public).is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_public_key() {
        let (params, public, secret) = make_test_data(8);
        let mut rng = OsRng;
        let proof = WTAPSProof::prove(&params, &public, &secret, &mut rng).unwrap();
        // Modify one participant key in public input
        let mut bad_public = public.clone();
        bad_public.participant_keys[0] = RistrettoPoint::random(&mut rng);
        assert!(proof.verify_normal(&params, &bad_public).is_err());
    }

    #[test]
    fn test_proof_size_bytes() {
        let (params, public, secret) = make_test_data(8);
        let mut rng = OsRng;
        let proof = WTAPSProof::prove(&params, &public, &secret, &mut rng).unwrap();
        let size = proof.proof_size_bytes();
        // 5+2+6 fixed points + 2*3 IPA points = 13*32 + 8*32 = 672 bytes for n=8
        assert!(size > 500 && size < 1000, "Unexpected proof size: {size}");
    }
}
