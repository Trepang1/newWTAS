use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul, VartimeMultiscalarMul};
use merlin::Transcript;
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_512};
use std::iter;

#[derive(Debug, Clone)]
pub enum WTAPSError {
    VerificationFailed,
    InvalidParameters,
    TranscriptError,
}

fn compute_y_powers(y: &Scalar, n: usize) -> Vec<Scalar> {
    let mut powers = Vec::with_capacity(n);
    let mut current = Scalar::ONE;
    for _ in 0..n {
        powers.push(current);
        current *= y;
    }
    powers
}

fn compute_y_inv_powers(y: &Scalar, n: usize) -> Vec<Scalar> {
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

fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).sum()
}

fn vector_add(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    a.iter().zip(b.iter()).map(|(ai, bi)| ai + bi).collect()
}

fn vector_sub(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    a.iter().zip(b.iter()).map(|(ai, bi)| ai - bi).collect()
}

fn vector_scalar_mul(a: &[Scalar], s: &Scalar) -> Vec<Scalar> {
    a.iter().map(|ai| ai * s).collect()
}

fn vector_hadamard(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).collect()
}

pub struct PublicParams {
    pub g_vec: Vec<RistrettoPoint>,
    pub h_vec: Vec<RistrettoPoint>,
    pub G: RistrettoPoint,
    pub H: RistrettoPoint,
    pub B: RistrettoPoint,
    pub n: usize,
}

impl PublicParams {
    pub fn new<R: RngCore + CryptoRng>(n: usize, rng: &mut R) -> Self {
        let mut g_vec = Vec::with_capacity(n);
        let mut h_vec = Vec::with_capacity(n);
        for _ in 0..n {
            g_vec.push(RistrettoPoint::random(rng));
            h_vec.push(RistrettoPoint::random(rng));
        }
        PublicParams {
            g_vec,
            h_vec,
            G: RistrettoPoint::random(rng),
            H: RistrettoPoint::random(rng),
            B: RistrettoPoint::random(rng),
            n,
        }
    }
}

#[derive(Clone)]
pub struct PublicInput {
    pub ciphertexts_v: Vec<RistrettoPoint>,
    pub k_agg: RistrettoPoint,
    pub t: Scalar,
    pub pk_enc: RistrettoPoint,
    pub participant_keys: Vec<RistrettoPoint>,
    pub c_w: RistrettoPoint,
    pub w_total: Scalar,
}

pub struct SecretWitness {
    pub b: Vec<Scalar>,
    pub w: Vec<Scalar>,
    pub r_enc: Vec<Scalar>,
    pub rho_w: Scalar,
}

pub struct IPAProof {
    pub L_vec: Vec<RistrettoPoint>,
    pub R_vec: Vec<RistrettoPoint>,
    pub a: Scalar,
    pub b: Scalar,
}

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

impl WTAPSProof {
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
        let t0 = inner_product(&l0, &r0);
        let t1 = inner_product(&l0, &r1) + inner_product(&l1, &r0);
        let t2 = inner_product(&l1, &r1);
        
        let tau1 = Scalar::random(rng);
        let tau2 = Scalar::random(rng);
        // T1 = G·t1 + H·τ1
        let t1_commit = &params.G * t1 + &params.H * tau1;
        // T2 = G·t2 + H·τ2
        let t2_commit = &params.G * t2 + &params.H * tau2;
        
        transcript.append_point(b"T1", &t1_commit);
        transcript.append_point(b"T2", &t2_commit);
        let x = transcript.challenge_scalar(b"x");
        
        let l_vec = vector_add(&l0, &vector_scalar_mul(&l1, &x));
        let r_vec = vector_add(&r0, &vector_scalar_mul(&r1, &x));
        let t_hat = inner_product(&l_vec, &r_vec);
        
        // t_y = Σ b_i·w_i·y^i-1
        // W_y = Σ w_i·y^i-1
        let mut t_y = Scalar::ZERO;
        let mut W_y = Scalar::ZERO;
        for i in 0..n {
            t_y += secret.b[i] * secret.w[i] * y_powers[i];
            W_y += secret.w[i] * y_powers[i];
        }
        
        // τ_x = τ2·x² + τ1·x
        // μ = α + ρ·x + z²·ρ_w
        let tau_x = tau2 * x * x + tau1 * x;
        let mu = alpha + rho * x + z_squared * rho_w;
        // E_key = Σ s_L,i·P_i
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
        
        // z_enc = Σ λ_enc^i·r_enc,i
        let mut z_enc = Scalar::ZERO;
        for i in 0..n {
            z_enc += lambda_enc_powers[i] * secret.r_enc[i];
        }
        // E_enc = Σ s_L,i·λ_enc^i·B
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
        
        // P = A + x·S + z²·C_W - z·⟨1, g⟩ + z·⟨1, h⟩ + λ_key·(K_agg - z·Σ P_i + x·E_key) + Σ λ_enc^i·V_i - z_enc·pk_enc - z·Σ λ_enc^i·B + x·E_enc
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
        
        // P0 = P - μ·H + t_hat·U
        let p0 = p + u * t_hat - &params.H * mu;
        
        let ipa_proof = Self::ipa_prove(&l_vec, &r_vec, &g_prime, &h_prime, &u, &p0, &mut transcript)?;
        
        Ok(WTAPSProof {
            c_w, a, s, t1: t1_commit, t2: t2_commit,
            tau_x, mu, z_enc, t_y, W_y, e_key, e_enc, t_hat, ipa_proof,
        })
    }

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

            // L = ⟨l_left, g_right⟩ + ⟨r_right, h_left⟩ + c_L·U
            let L = RistrettoPoint::vartime_multiscalar_mul(l_left, g_right) + 
                    RistrettoPoint::vartime_multiscalar_mul(r_right, h_left) + u * c_L;
            // R = ⟨l_right, g_left⟩ + ⟨r_left, h_right⟩ + c_R·U
            let R = RistrettoPoint::vartime_multiscalar_mul(l_right, g_left) + 
                    RistrettoPoint::vartime_multiscalar_mul(r_left, h_right) + u * c_R;

            L_vec.push(L);
            R_vec.push(R);
            transcript.append_point(b"L", &L);
            transcript.append_point(b"R", &R);
            let x = transcript.challenge_scalar(b"u");
            let x_inv = x.invert();

            // g' = g_left^{x^{-1}} ∘ g_right^{x}
            // h' = h_left^{x} ∘ h_right^{x^{-1}}
            let new_g: Vec<RistrettoPoint> = g_left.iter().zip(g_right.iter()).map(|(gl, gr)| gl * x_inv + gr * x).collect();
            let new_h: Vec<RistrettoPoint> = h_left.iter().zip(h_right.iter()).map(|(hl, hr)| hl * x + hr * x_inv).collect();
            // a' = a_left·x + a_right·x^{-1}
            // b' = b_left·x^{-1} + b_right·x
            let new_l: Vec<Scalar> = l_left.iter().zip(l_right.iter()).map(|(ll, lr)| ll * x + lr * x_inv).collect();
            let new_r: Vec<Scalar> = r_left.iter().zip(r_right.iter()).map(|(rl, rr)| rl * x_inv + rr * x).collect();

            l_vec = new_l; r_vec = new_r; g_vec = new_g; h_vec = new_h;
            current_n = half_n;
        }
        Ok(IPAProof { L_vec, R_vec, a: l_vec[0], b: r_vec[0] })
    }

    pub fn verify_normal(&self, params: &PublicParams, public: &PublicInput) -> Result<(), WTAPSError> {
        let n = params.n;
        let mut transcript = Transcript::new(b"WTAPS_NIZK");
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

        // [t_hat]G + [τ_x]H = [z²·t_y + δ(y,z)]G + [x]T1 + [x²]T2
        let y_powers = compute_y_powers(&y, n);
        let sum_y_powers: Scalar = y_powers.iter().sum();
        let z_squared = z * z;
        let z_cubed = z_squared * z;
        let delta = (z - z_squared) * sum_y_powers - z_cubed * self.W_y;
        let lhs = &params.G * self.t_hat + &params.H * self.tau_x;
        let rhs = &params.G * (z_squared * self.t_y + delta) + &self.t1 * x + &self.t2 * (x * x);
        if lhs != rhs { return Err(WTAPSError::VerificationFailed); }

        let lambda_enc_powers: Vec<Scalar> = {
            let mut powers = Vec::with_capacity(n);
            let mut current = Scalar::ONE;
            for _ in 0..n {
                powers.push(current);
                current *= lambda_enc;
            }
            powers
        };
        let mut g_prime = Vec::with_capacity(n);
        let mut h_prime = Vec::with_capacity(n);
        for i in 0..n {
            let g_prime_i = params.g_vec[i] + public.participant_keys[i] * lambda_key + params.B * lambda_enc_powers[i];
            g_prime.push(g_prime_i);
        }
        let y_inv_powers = compute_y_inv_powers(&y, n);
        for i in 0..n { h_prime.push(params.h_vec[i] * y_inv_powers[i]); }

        let part1 = &self.a + &self.s * x + &self.c_w * z_squared;
        let minus_z = -z;
        let sum_g = RistrettoPoint::vartime_multiscalar_mul(std::iter::repeat(minus_z).take(n), params.g_vec.iter());
        let sum_h = RistrettoPoint::vartime_multiscalar_mul(std::iter::repeat(z).take(n), params.h_vec.iter());
        let sum_pi = RistrettoPoint::vartime_multiscalar_mul(std::iter::repeat(&Scalar::ONE).take(n), public.participant_keys.iter());
        let part3 = (&public.k_agg + &self.e_key * x - &sum_pi * z) * lambda_key;
        let sum_v = RistrettoPoint::vartime_multiscalar_mul(lambda_enc_powers.iter(), public.ciphertexts_v.iter());
        let sum_b = RistrettoPoint::vartime_multiscalar_mul(lambda_enc_powers.iter(), std::iter::repeat(&params.B).take(n)) * z;
        let part4 = sum_v - &public.pk_enc * self.z_enc - sum_b + &self.e_enc * x;
        let p0 = (part1 + sum_h + sum_g + part3 + part4) + u * self.t_hat - &params.H * self.mu;

        let mut challenges = Vec::new();
        for (L, R) in self.ipa_proof.L_vec.iter().zip(self.ipa_proof.R_vec.iter()) {
            transcript.append_point(b"L", L);
            transcript.append_point(b"R", R);
            challenges.push(transcript.challenge_scalar(b"u"));
        }

        let mut g_fold = g_prime;
        let mut h_fold = h_prime;
        let mut p_fold = p0;
        for (round, &x_chal) in challenges.iter().enumerate() {
            let half_n = g_fold.len() / 2;
            let (g_left, g_right) = g_fold.split_at(half_n);
            let (h_left, h_right) = h_fold.split_at(half_n);
            let x_inv = x_chal.invert();
            let new_g: Vec<RistrettoPoint> = g_left.iter().zip(g_right.iter()).map(|(gl, gr)| gl * x_inv + gr * x_chal).collect();
            let new_h: Vec<RistrettoPoint> = h_left.iter().zip(h_right.iter()).map(|(hl, hr)| hl * x_chal + hr * x_inv).collect();
            p_fold = &self.ipa_proof.L_vec[round] * (x_chal * x_chal) + p_fold + &self.ipa_proof.R_vec[round] * (x_inv * x_inv);
            g_fold = new_g; h_fold = new_h;
        }

        // P_final = g^a h^b u^c
        let expected_p_final = g_fold[0] * self.ipa_proof.a + h_fold[0] * self.ipa_proof.b + u * (self.ipa_proof.a * self.ipa_proof.b);
        if p_fold == expected_p_final {
            println!("Verification successful (Standard)");
            Ok(())
        } else {
            Err(WTAPSError::VerificationFailed)
        }
    }
}

fn compute_challenge_vector(challenges: &[Scalar], n: usize) -> Vec<Scalar> {
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

impl WTAPSProof {
    pub fn verify_fast(&self, params: &PublicParams, public: &PublicInput) -> Result<(), WTAPSError> {
        let n = params.n;
        let mut transcript = Transcript::new(b"WTAPS_NIZK");
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

        let y_powers = compute_y_powers(&y, n);
        let sum_y_powers: Scalar = y_powers.iter().sum();
        let z_squared = z * z;
        let z_cubed = z_squared * z;
        let delta = (z - z_squared) * sum_y_powers - z_cubed * self.W_y;
        let lhs = &params.G * self.t_hat + &params.H * self.tau_x;
        let rhs = &params.G * (z_squared * self.t_y + delta) + &self.t1 * x + &self.t2 * (x * x);
        if lhs != rhs { return Err(WTAPSError::VerificationFailed); }

        let lambda_enc_powers: Vec<Scalar> = {
            let mut powers = Vec::with_capacity(n);
            let mut current = Scalar::ONE;
            for _ in 0..n {
                powers.push(current);
                current *= lambda_enc;
            }
            powers
        };
        let mut g_prime = Vec::with_capacity(n);
        let mut h_prime = Vec::with_capacity(n);
        for i in 0..n {
            let g_prime_i = params.g_vec[i] + public.participant_keys[i] * lambda_key + params.B * lambda_enc_powers[i];
            g_prime.push(g_prime_i);
        }
        let y_inv_powers = compute_y_inv_powers(&y, n);
        for i in 0..n { h_prime.push(params.h_vec[i] * y_inv_powers[i]); }

        let part1 = &self.a + &self.s * x + &self.c_w * z_squared;
        let minus_z = -z;
        let sum_g = RistrettoPoint::vartime_multiscalar_mul(std::iter::repeat(minus_z).take(n), params.g_vec.iter());
        let sum_h = RistrettoPoint::vartime_multiscalar_mul(std::iter::repeat(z).take(n), params.h_vec.iter());
        let sum_pi = RistrettoPoint::vartime_multiscalar_mul(std::iter::repeat(&Scalar::ONE).take(n), public.participant_keys.iter());
        let part3 = (&public.k_agg + &self.e_key * x - &sum_pi * z) * lambda_key;
        let sum_v = RistrettoPoint::vartime_multiscalar_mul(lambda_enc_powers.iter(), public.ciphertexts_v.iter());
        let sum_b = RistrettoPoint::vartime_multiscalar_mul(lambda_enc_powers.iter(), std::iter::repeat(&params.B).take(n)) * z;
        let part4 = sum_v - &public.pk_enc * self.z_enc - sum_b + &self.e_enc * x;
        let p0 = (part1 + sum_h + sum_g + part3 + part4) + u * self.t_hat - &params.H * self.mu;

        let mut challenges = Vec::new();
        for (L, R) in self.ipa_proof.L_vec.iter().zip(self.ipa_proof.R_vec.iter()) {
            transcript.append_point(b"L", L);
            transcript.append_point(b"R", R);
            challenges.push(transcript.challenge_scalar(b"u"));
        }

        let s_vec = compute_challenge_vector(&challenges, n);
        let s_inv_vec: Vec<Scalar> = s_vec.iter().map(|s| s.invert()).collect();
        // G'_final = Σ s_i * g'_i
        let g_final = RistrettoPoint::vartime_multiscalar_mul(s_vec.iter(), g_prime.iter());
        // H'_final = Σ s_i⁻¹ * h'_i
        let h_final = RistrettoPoint::vartime_multiscalar_mul(s_inv_vec.iter(), h_prime.iter());

        // [ab]U + [a]G'_final + [b]H'_final = P_0 + Σ([u_k²]L_k + [u_k^{-2}]R_k)
        let left_side = u * (self.ipa_proof.a * self.ipa_proof.b) + g_final * self.ipa_proof.a + h_final * self.ipa_proof.b;
        let mut right_side = p0;
        for (i, &x_chal) in challenges.iter().enumerate() {
            right_side = right_side + &self.ipa_proof.L_vec[i] * (x_chal * x_chal) + &self.ipa_proof.R_vec[i] * (x_chal.invert() * x_chal.invert());
        }

        if left_side == right_side {
            println!("Verification successful (Fast)");
            Ok(())
        } else {
            Err(WTAPSError::VerificationFailed)
        }
    }

    pub fn verify_consistency(&self, params: &PublicParams, public: &PublicInput) -> Result<(), WTAPSError> {
        let n = params.n;
        let mut transcript = Transcript::new(b"WTAPS_NIZK");
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
        let _u = transcript.challenge_point(b"U");

        let lambda_enc_powers: Vec<Scalar> = {
            let mut powers = Vec::with_capacity(n);
            let mut current = Scalar::ONE;
            for _ in 0..n {
                powers.push(current);
                current *= lambda_enc;
            }
            powers
        };
        let mut g_prime = Vec::with_capacity(n);
        let mut h_prime = Vec::with_capacity(n);
        for i in 0..n {
            let g_prime_i = params.g_vec[i] + public.participant_keys[i] * lambda_key + params.B * lambda_enc_powers[i];
            g_prime.push(g_prime_i);
        }
        let y_inv_powers = compute_y_inv_powers(&y, n);
        for i in 0..n { h_prime.push(params.h_vec[i] * y_inv_powers[i]); }

        let mut challenges = Vec::new();
        for (L, R) in self.ipa_proof.L_vec.iter().zip(self.ipa_proof.R_vec.iter()) {
            transcript.append_point(b"L", L);
            transcript.append_point(b"R", R);
            challenges.push(transcript.challenge_scalar(b"u"));
        }

        let mut g_fold = g_prime.clone();
        let mut h_fold = h_prime.clone();
        for &x_chal in &challenges {
            let half_n = g_fold.len() / 2;
            let (g_left, g_right) = g_fold.split_at(half_n);
            let (h_left, h_right) = h_fold.split_at(half_n);
            let x_inv = x_chal.invert();
            g_fold = g_left.iter().zip(g_right.iter()).map(|(gl, gr)| gl * x_inv + gr * x_chal).collect();
            h_fold = h_left.iter().zip(h_right.iter()).map(|(hl, hr)| hl * x_chal + hr * x_inv).collect();
        }

        let s_vec = compute_challenge_vector(&challenges, n);
        let s_inv_vec: Vec<Scalar> = s_vec.iter().map(|s| s.invert()).collect();
        let g_final_direct = RistrettoPoint::vartime_multiscalar_mul(s_vec.iter(), g_prime.iter());
        let h_final_direct = RistrettoPoint::vartime_multiscalar_mul(s_inv_vec.iter(), h_prime.iter());

        if g_fold[0] == g_final_direct && h_fold[0] == h_final_direct {
            println!("Consistency check successful");
            Ok(())
        } else {
            Err(WTAPSError::VerificationFailed)
        }
    }
}

fn main() {
    let mut rng = OsRng;
    let n = 8;
    let params = PublicParams::new(n, &mut rng);
    let b = vec![Scalar::ONE, Scalar::ZERO, Scalar::ONE, Scalar::ONE, Scalar::ZERO, Scalar::ONE, Scalar::ZERO, Scalar::ONE];
    let w = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64), Scalar::from(4u64), Scalar::from(5u64), Scalar::from(6u64), Scalar::from(7u64), Scalar::from(8u64)];
    
    let mut t = Scalar::ZERO;
    for i in 0..n { t += b[i] * w[i]; }
    let participant_keys: Vec<RistrettoPoint> = (0..n).map(|_| RistrettoPoint::random(&mut rng)).collect();
    let mut k_agg = RistrettoPoint::identity();
    for i in 0..n { if b[i] == Scalar::ONE { k_agg += participant_keys[i]; } }
    
    let sk_enc = Scalar::random(&mut rng);
    let pk_enc = &params.G * sk_enc;
    let r_enc: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    let mut ciphertexts_v = Vec::new();
    for i in 0..n { ciphertexts_v.push(&pk_enc * r_enc[i] + &params.B * b[i]); }
    
    let rho_w = Scalar::random(&mut rng);
    let c_w = RistrettoPoint::multiscalar_mul(iter::once(&rho_w).chain(w.iter()), iter::once(&params.H).chain(params.h_vec.iter()));
    
    let public_input = PublicInput { ciphertexts_v, k_agg, t, pk_enc, participant_keys, c_w, w_total: w.iter().sum() };
    let secret_witness = SecretWitness { b, w, r_enc, rho_w };

    let proof = WTAPSProof::prove(&params, &public_input, &secret_witness, &mut rng).expect("Proof generation failed");
    proof.verify_normal(&params, &public_input).expect("Normal verification failed");
    proof.verify_fast(&params, &public_input).expect("Fast verification failed");
    proof.verify_consistency(&params, &public_input).expect("Consistency check failed");
}
