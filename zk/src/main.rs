// src/main.rs
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul, VartimeMultiscalarMul};
use merlin::Transcript;
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_512};
use std::iter;

// =========================================================================
// 错误类型
// =========================================================================

#[derive(Debug, Clone)]
pub enum WTAPSError {
    VerificationFailed,
    InvalidParameters,
    TranscriptError,
}

// =========================================================================
// 辅助函数
// =========================================================================

fn scalar_to_string(s: &Scalar) -> String {
    let bytes = s.as_bytes();
    let mut is_small = true;
    for i in 1..bytes.len() {
        if bytes[i] != 0 {
            is_small = false;
            break;
        }
    }
    
    if is_small {
        format!("{}", bytes[0] as u64)
    } else {
        hex::encode(&bytes[0..4]) + "..."
    }
}

fn scalars_to_string(scalars: &[Scalar], max_display: usize) -> String {
    if scalars.len() <= max_display {
        scalars.iter().map(scalar_to_string).collect::<Vec<_>>().join(", ")
    } else {
        let first = scalars[0..max_display/2].iter().map(scalar_to_string).collect::<Vec<_>>().join(", ");
        let last = scalars[scalars.len()-max_display/2..].iter().map(scalar_to_string).collect::<Vec<_>>().join(", ");
        format!("{}, ..., {}", first, last)
    }
}

fn binary_vector_to_string(scalars: &[Scalar], max_display: usize) -> String {
    let to_bit = |s: &Scalar| {
        let bytes = s.as_bytes();
        if bytes[0] == 1 && bytes[1..].iter().all(|&b| b == 0) {
            "1"
        } else if bytes[0] == 0 && bytes[1..].iter().all(|&b| b == 0) {
            "0"
        } else {
            "?"
        }
    };
    
    if scalars.len() <= max_display {
        scalars.iter().map(to_bit).collect::<Vec<_>>().join("")
    } else {
        let first = scalars[0..max_display/2].iter().map(to_bit).collect::<String>();
        let last = scalars[scalars.len()-max_display/2..].iter().map(to_bit).collect::<String>();
        format!("{}...{} (共{}位)", first, last, scalars.len())
    }
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

// =========================================================================
// 数据结构
// =========================================================================

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

// =========================================================================
// Transcript 协议扩展
// =========================================================================

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

// =========================================================================
// 证明生成（根据论文实现）
// =========================================================================

impl WTAPSProof {
    pub fn prove<R: RngCore + CryptoRng>(
        params: &PublicParams,
        public: &PublicInput,
        secret: &SecretWitness,
        rng: &mut R,
    ) -> Result<Self, WTAPSError> {
        println!("\n=== 开始生成证明 ===");
        let n = params.n;
        
        // 验证输入
        if secret.b.len() != n || secret.w.len() != n || 
           secret.r_enc.len() != n || public.participant_keys.len() != n ||
           public.ciphertexts_v.len() != n {
            return Err(WTAPSError::InvalidParameters);
        }
        
        for (i, &bi) in secret.b.iter().enumerate() {
            if bi != Scalar::ZERO && bi != Scalar::ONE {
                println!("❌ 错误: b[{}] = {} 不是有效的二进制值", i, scalar_to_string(&bi));
                return Err(WTAPSError::InvalidParameters);
            }
        }
        
        let computed_t: Scalar = secret.b.iter().zip(secret.w.iter())
            .map(|(bi, wi)| bi * wi)
            .sum();
        if computed_t != public.t {
            println!("❌ 错误: 加权阈值不匹配");
            println!("  计算值: {}", scalar_to_string(&computed_t));
            println!("  期望值: {}", scalar_to_string(&public.t));
            return Err(WTAPSError::InvalidParameters);
        }
        
        let mut transcript = Transcript::new(b"WTAPS_NIZK");
        
        println!("\n--- Step 1: 生成承诺 ---");
        let alpha = Scalar::random(rng);
        let rho = Scalar::random(rng);
        let rho_w = secret.rho_w;
        
        let s_l: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();
        let s_r: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();
        
        println!("随机数:");
        println!("  α = {}", scalar_to_string(&alpha));
        println!("  ρ = {}", scalar_to_string(&rho));
        println!("  ρ_w = {}", scalar_to_string(&rho_w));
        
        println!("\n计算承诺 A:");
        let b_minus_one: Vec<Scalar> = secret.b.iter().map(|bi| bi - Scalar::ONE).collect();
        
        let a = RistrettoPoint::multiscalar_mul(
            iter::once(&alpha)
                .chain(secret.b.iter())
                .chain(b_minus_one.iter()),
            iter::once(&params.H)
                .chain(params.g_vec.iter())
                .chain(params.h_vec.iter()),
        );
        println!("  A = {:?}", a.compress());
        
        println!("\n计算承诺 S:");
        let s = RistrettoPoint::multiscalar_mul(
            iter::once(&rho)
                .chain(s_l.iter())
                .chain(s_r.iter()),
            iter::once(&params.H)
                .chain(params.g_vec.iter())
                .chain(params.h_vec.iter()),
        );
        println!("  S = {:?}", s.compress());
        
        let c_w = public.c_w;
        println!("C_W = {:?}", c_w.compress());
        
        println!("\n--- Step 2: 生成挑战 y, z ---");
        transcript.append_point(b"c_w", &c_w);
        transcript.append_point(b"A", &a);
        transcript.append_point(b"S", &s);
        
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        
        println!("挑战 y = {}", scalar_to_string(&y));
        println!("挑战 z = {}", scalar_to_string(&z));
        
        println!("\n--- Step 3: 构造多项式 l(X), r(X) ---");
        let y_powers = compute_y_powers(&y, n);
        let ones = vec![Scalar::ONE; n];
        
        println!("构造 l(X):");
        println!("  公式: l(X) = b - z·1 + s_L·X");
        let l0 = vector_sub(&secret.b, &vector_scalar_mul(&ones, &z));
        let l1 = s_l.clone();
        
        println!("构造 r(X):");
        println!("  公式: r(X) = y^n ∘ (b - 1 + s_R·X + z·1) + z²·(w ∘ y^n)");
        
        let z_squared = z * z;
        
        let b_minus_one = vector_sub(&secret.b, &ones);
        let b_minus_one_plus_z = vector_add(&b_minus_one, &vector_scalar_mul(&ones, &z));
        
        let term1 = vector_hadamard(&y_powers, &b_minus_one_plus_z);
        let term2_x = vector_hadamard(&y_powers, &s_r);
        let w_hadamard_y = vector_hadamard(&secret.w, &y_powers);
        let term3 = vector_scalar_mul(&w_hadamard_y, &z_squared);
        
        let r0 = vector_add(&term1, &term3);
        let r1 = term2_x;
        
        println!("\n--- Step 4: 计算多项式系数 ---");
        println!("  公式: t(X) = ⟨l(X), r(X)⟩ = t0 + t1·X + t2·X²");
        
        let t0 = inner_product(&l0, &r0);
        let t1 = inner_product(&l0, &r1) + inner_product(&l1, &r0);
        let t2 = inner_product(&l1, &r1);
        
        println!("  系数值:");
        println!("    t0 = ⟨l0, r0⟩ = {}", scalar_to_string(&t0));
        println!("    t1 = ⟨l0, r1⟩ + ⟨l1, r0⟩ = {}", scalar_to_string(&t1));
        println!("    t2 = ⟨l1, r1⟩ = {}", scalar_to_string(&t2));
        
        println!("\n--- Step 5: 提交系数 T1, T2 ---");
        let tau1 = Scalar::random(rng);
        let tau2 = Scalar::random(rng);
        
        let t1_commit = &params.G * t1 + &params.H * tau1;
        let t2_commit = &params.G * t2 + &params.H * tau2;
        
        println!("随机数: τ1 = {}, τ2 = {}", scalar_to_string(&tau1), scalar_to_string(&tau2));
        println!("承诺:");
        println!("  T1 = G·t1 + H·τ1 = {:?}", t1_commit.compress());
        println!("  T2 = G·t2 + H·τ2 = {:?}", t2_commit.compress());
        
        transcript.append_point(b"T1", &t1_commit);
        transcript.append_point(b"T2", &t2_commit);
        
        let x = transcript.challenge_scalar(b"x");
        println!("\n挑战 x = {}", scalar_to_string(&x));
        
        println!("\n--- Step 6: 在点 x 处评估多项式 ---");
        println!("评估 l(x): l(x) = l0 + l1·x");
        let l_vec = vector_add(&l0, &vector_scalar_mul(&l1, &x));
        
        println!("评估 r(x): r(x) = r0 + r1·x");
        let r_vec = vector_add(&r0, &vector_scalar_mul(&r1, &x));
        
        println!("计算内积 t_hat = ⟨l(x), r(x)⟩");
        let t_hat = inner_product(&l_vec, &r_vec);
        println!("  t_hat = {}", scalar_to_string(&t_hat));
        
        let t_hat_check = t0 + t1 * x + t2 * x * x;
        if t_hat != t_hat_check {
            println!("❌ 多项式评估验证失败！");
            println!("  计算值: {}", scalar_to_string(&t_hat));
            println!("  期望值: {}", scalar_to_string(&t_hat_check));
            return Err(WTAPSError::InvalidParameters);
        }
        println!("✅ 多项式评估验证通过");
        
        println!("\n计算 t_y 和 W_y:");
        let mut t_y = Scalar::ZERO;
        let mut W_y = Scalar::ZERO;
        
        for i in 0..n {
            t_y += secret.b[i] * secret.w[i] * y_powers[i];
            W_y += secret.w[i] * y_powers[i];
        }
        println!("  t_y = Σ b_i·w_i·y^i-1 = {}", scalar_to_string(&t_y));
        println!("  W_y = Σ w_i·y^i-1 = {}", scalar_to_string(&W_y));
        
        let tau_x = tau2 * x * x + tau1 * x;
        let mu = alpha + rho * x + z_squared * rho_w;
        
        let e_key = RistrettoPoint::vartime_multiscalar_mul(
            s_l.iter(),
            public.participant_keys.iter(),
        );
        
        println!("\n计算聚合值:");
        println!("  τ_x = τ2·x² + τ1·x = {}", scalar_to_string(&tau_x));
        println!("  μ = α + ρ·x + z²·ρ_w = {}", scalar_to_string(&mu));
        println!("  E_key = Σ s_L,i·P_i = {:?}", e_key.compress());
        
        transcript.append_scalar(b"tau_x", &tau_x);
        transcript.append_scalar(b"mu", &mu);
        transcript.append_scalar(b"t_hat", &t_hat);
        transcript.append_scalar(b"t_y", &t_y);
        transcript.append_scalar(b"W_y", &W_y);
        transcript.append_point(b"E_key", &e_key);
        
        println!("\n--- Step 7: 生成额外挑战 ---");
        let lambda_key = transcript.challenge_scalar(b"lambda_key");
        let lambda_enc = transcript.challenge_scalar(b"lambda_enc");
        println!("  λ_key = {}", scalar_to_string(&lambda_key));
        println!("  λ_enc = {}", scalar_to_string(&lambda_enc));
        
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
        
        println!("  z_enc = Σ λ_enc^i·r_enc,i = {}", scalar_to_string(&z_enc));
        println!("  E_enc = Σ s_L,i·λ_enc^i·B = {:?}", e_enc.compress());
        
        transcript.append_scalar(b"z_enc", &z_enc);
        transcript.append_point(b"E_enc", &e_enc);
        
        let u = transcript.challenge_point(b"U");
        println!("  U = {:?}", u.compress());
        
        println!("\n--- Step 8: 构建 Super Basis 和目标承诺 P ---");
        
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
        
        println!("  构建目标承诺 P:");
        println!("  公式: P = A + x·S + z²·C_W - z·⟨1, g⟩ + z·⟨1, h⟩");
        println!("        + λ_key·(K_agg - z·Σ P_i + x·E_key)");
        println!("        + Σ λ_enc^i·V_i - z_enc·pk_enc - z·Σ λ_enc^i·B + x·E_enc");
        
        let z_squared = z * z;
        
        let part1 = &a + &s * x + &c_w * z_squared;
        
        let minus_z = -z;
        let sum_g = RistrettoPoint::vartime_multiscalar_mul(
            std::iter::repeat(minus_z).take(n),
            params.g_vec.iter(),
        );
        let sum_h = RistrettoPoint::vartime_multiscalar_mul(
            std::iter::repeat(z).take(n),
            params.h_vec.iter(),
        );
        let part2 = sum_h + sum_g;
        
        let sum_pi = RistrettoPoint::vartime_multiscalar_mul(
            std::iter::repeat(&Scalar::ONE).take(n),
            public.participant_keys.iter(),
        );
        let part3_inner = &public.k_agg + &e_key * x - &sum_pi * z;
        let part3 = part3_inner * lambda_key;
        
        let sum_v = RistrettoPoint::vartime_multiscalar_mul(
            lambda_enc_powers.iter(),
            public.ciphertexts_v.iter(),
        );
        let sum_b = RistrettoPoint::vartime_multiscalar_mul(
            lambda_enc_powers.iter(),
            std::iter::repeat(&params.B).take(n),
        ) * z;
        let part4 = sum_v - &public.pk_enc * z_enc - sum_b + &e_enc * x;
        
        let p = part1 + part2 + part3 + part4;
        println!("  P = {:?}", p.compress());
        
        let p0 = p + u * t_hat - &params.H * mu;
        println!("  P0 = P - μ·H + t_hat·U = {:?}", p0.compress());
        
        let l_g_prime = RistrettoPoint::vartime_multiscalar_mul(
            l_vec.iter(),
            g_prime.iter(),
        );
        let r_h_prime = RistrettoPoint::vartime_multiscalar_mul(
            r_vec.iter(),
            h_prime.iter(),
        );
        let check_value = l_g_prime + r_h_prime + u * t_hat;
        
        println!("  内部一致性检查:");
        println!("  ⟨l, g'⟩ + ⟨r, h'⟩ + t_hat·U = {:?}", check_value.compress());
        println!("  P + t_hat·U - μ·H = {:?}", (p + u * t_hat - &params.H * mu).compress());
        
        if check_value != p + u * t_hat - &params.H * mu {
            println!("❌ 内部一致性检查失败！");
            return Err(WTAPSError::InvalidParameters);
        }
        println!("✅ 内部一致性检查通过");
        
        println!("\n--- Step 9: 生成IPA证明 ---");
        let ipa_proof = Self::ipa_prove(
            &l_vec,
            &r_vec,
            &g_prime,
            &h_prime,
            &u,
            &p0,
            &mut transcript,
        )?;
        
        println!("\n=== 证明生成完成 ===");
        
        Ok(WTAPSProof {
            c_w,
            a,
            s,
            t1: t1_commit,
            t2: t2_commit,
            tau_x,
            mu,
            z_enc,
            t_y,
            W_y,
            e_key,
            e_enc,
            t_hat,
            ipa_proof,
        })
    }
    
    fn ipa_prove(
        l: &[Scalar],
        r: &[Scalar],
        g: &[RistrettoPoint],
        h: &[RistrettoPoint],
        u: &RistrettoPoint,
        p0: &RistrettoPoint,
        transcript: &mut Transcript,
    ) -> Result<IPAProof, WTAPSError> {
        let n = l.len();
        println!("  开始IPA证明，向量长度 n = {}", n);
        
        let mut l_vec = l.to_vec();
        let mut r_vec = r.to_vec();
        let mut g_vec = g.to_vec();
        let mut h_vec = h.to_vec();
        let mut p_current = *p0;
        
        let log_n = (n as f64).log2().ceil() as usize;
        
        let mut L_vec = Vec::with_capacity(log_n);
        let mut R_vec = Vec::with_capacity(log_n);
        let mut challenges = Vec::with_capacity(log_n);
        
        let mut current_n = n;
        
        while current_n > 1 {
            println!("\n  IPA折叠轮次，当前长度: {}", current_n);
            let half_n = current_n / 2;
            
            // 分割向量（根据图片中的协议）
            let (l_left, l_right) = l_vec.split_at(half_n);
            let (r_left, r_right) = r_vec.split_at(half_n);
            let (g_left, g_right) = g_vec.split_at(half_n);
            let (h_left, h_right) = h_vec.split_at(half_n);
            
            // 计算交叉项 c_L 和 c_R（根据图片公式20-21）
            let c_L = inner_product(l_left, r_right);
            let c_R = inner_product(l_right, r_left);
            
            // 计算 L 和 R（根据图片公式22-23）
            let L_part1 = RistrettoPoint::vartime_multiscalar_mul(l_left, g_right);
            let L_part2 = RistrettoPoint::vartime_multiscalar_mul(r_right, h_left);
            let L = L_part1 + L_part2 + u * c_L;
            
            let R_part1 = RistrettoPoint::vartime_multiscalar_mul(l_right, g_left);
            let R_part2 = RistrettoPoint::vartime_multiscalar_mul(r_left, h_right);
            let R = R_part1 + R_part2 + u * c_R;
            
            L_vec.push(L);
            R_vec.push(R);
            
            println!("    生成 L = {:?}", L.compress());
            println!("    生成 R = {:?}", R.compress());
            
            // 生成挑战（根据图片公式25）
            transcript.append_point(b"L", &L);
            transcript.append_point(b"R", &R);
            let x = transcript.challenge_scalar(b"u"); // 对应图片中的x
            challenges.push(x);
            
            println!("    挑战 x = {}", scalar_to_string(&x));
            
            // 计算新的基底 g' 和 h'（根据图片公式28-29）
            let x_inv = x.invert();
            let x_squared = x * x;
            let x_inv_squared = x_inv * x_inv;
            
            // g' = g_left^{x^{-1}} ∘ g_right^{x}
            let new_g: Vec<RistrettoPoint> = g_left.iter()
                .zip(g_right.iter())
                .map(|(gl, gr)| gl * x_inv + gr * x)
                .collect();
            
            // h' = h_left^{x} ∘ h_right^{x^{-1}}
            let new_h: Vec<RistrettoPoint> = h_left.iter()
                .zip(h_right.iter())
                .map(|(hl, hr)| hl * x + hr * x_inv)
                .collect();
            
            // 计算新的承诺 P'（根据图片公式30）
            // P' = L^{x^2} · P · R^{x^{-2}}
            p_current = L * x_squared + p_current + R * x_inv_squared;
            
            // 计算新的向量 a' 和 b'（根据图片公式32-33）
            // a' = a_left·x + a_right·x^{-1}
            let new_l: Vec<Scalar> = l_left.iter()
                .zip(l_right.iter())
                .map(|(ll, lr)| ll * x + lr * x_inv)
                .collect();
            
            // b' = b_left·x^{-1} + b_right·x
            let new_r: Vec<Scalar> = r_left.iter()
                .zip(r_right.iter())
                .map(|(rl, rr)| rl * x_inv + rr * x)
                .collect();
            
            // 更新为折叠后的向量
            l_vec = new_l;
            r_vec = new_r;
            g_vec = new_g;
            h_vec = new_h;
            current_n = half_n;
        }
        
        println!("\n  IPA折叠完成，最终标量:");
        println!("    a = {}", scalar_to_string(&l_vec[0]));
        println!("    b = {}", scalar_to_string(&r_vec[0]));
        
        Ok(IPAProof {
            L_vec,
            R_vec,
            a: l_vec[0],
            b: r_vec[0],
        })
    }
}

// =========================================================================
// 验证函数 - 普通验证（递归折叠方法）
// =========================================================================

impl WTAPSProof {
    pub fn verify_normal(
        &self,
        params: &PublicParams,
        public: &PublicInput,
    ) -> Result<(), WTAPSError> {
        println!("\n=== 开始普通验证（递归折叠方法）===");
        let n = params.n;
        
        // 初始化transcript - 严格按照证明阶段的顺序
        let mut transcript = Transcript::new(b"WTAPS_NIZK");
        
        println!("\n--- Step 1: 重建挑战 ---");
        transcript.append_point(b"c_w", &self.c_w);
        transcript.append_point(b"A", &self.a);
        transcript.append_point(b"S", &self.s);
        
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        println!("挑战 y = {}", scalar_to_string(&y));
        println!("挑战 z = {}", scalar_to_string(&z));
        
        transcript.append_point(b"T1", &self.t1);
        transcript.append_point(b"T2", &self.t2);
        
        let x = transcript.challenge_scalar(b"x");
        println!("挑战 x = {}", scalar_to_string(&x));
        
        transcript.append_scalar(b"tau_x", &self.tau_x);
        transcript.append_scalar(b"mu", &self.mu);
        transcript.append_scalar(b"t_hat", &self.t_hat);
        transcript.append_scalar(b"t_y", &self.t_y);
        transcript.append_scalar(b"W_y", &self.W_y);
        transcript.append_point(b"E_key", &self.e_key);
        
        let lambda_key = transcript.challenge_scalar(b"lambda_key");
        let lambda_enc = transcript.challenge_scalar(b"lambda_enc");
        println!("额外挑战:");
        println!("  λ_key = {}", scalar_to_string(&lambda_key));
        println!("  λ_enc = {}", scalar_to_string(&lambda_enc));
        
        transcript.append_scalar(b"z_enc", &self.z_enc);
        transcript.append_point(b"E_enc", &self.e_enc);
        
        let u = transcript.challenge_point(b"U");
        println!("  U = {:?}", u.compress());
        
        // Check 1: 阈值一致性检查（根据论文公式）
        println!("\n--- Step 2: 阈值一致性检查 ---");
        println!("公式: [t_hat]G + [τ_x]H = [z²·t_y + δ(y,z)]G + [x]T1 + [x²]T2");
        
        let y_powers = compute_y_powers(&y, n);
        let sum_y_powers: Scalar = y_powers.iter().sum();
        
        let z_squared = z * z;
        let z_cubed = z_squared * z;
        let delta = (z - z_squared) * sum_y_powers - z_cubed * self.W_y;
        
        let lhs = &params.G * self.t_hat + &params.H * self.tau_x;
        let rhs = &params.G * (z_squared * self.t_y + delta) + &self.t1 * x + &self.t2 * (x * x);
        
        if lhs != rhs {
            println!("❌ 阈值一致性检查失败！");
            println!("  差值 = {:?}", (lhs - rhs).compress());
            return Err(WTAPSError::VerificationFailed);
        }
        println!("✅ 阈值一致性检查通过！");
        
        // Check 2: IPA验证
        println!("\n--- Step 3: 构建Super Basis ---");
        
        // 构建 Super Basis
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
            let g_prime_i = params.g_vec[i] + 
                public.participant_keys[i] * lambda_key + 
                params.B * lambda_enc_powers[i];
            g_prime.push(g_prime_i);
        }
        
        let y_inv_powers = compute_y_inv_powers(&y, n);
        for i in 0..n {
            h_prime.push(params.h_vec[i] * y_inv_powers[i]);
        }
        
        // 重建目标承诺 P
        let z_squared = z * z;
        
        let part1 = &self.a + &self.s * x + &self.c_w * z_squared;
        
        let minus_z = -z;
        let sum_g = RistrettoPoint::vartime_multiscalar_mul(
            std::iter::repeat(minus_z).take(n),
            params.g_vec.iter(),
        );
        let sum_h = RistrettoPoint::vartime_multiscalar_mul(
            std::iter::repeat(z).take(n),
            params.h_vec.iter(),
        );
        let part2 = sum_h + sum_g;
        
        let sum_pi = RistrettoPoint::vartime_multiscalar_mul(
            std::iter::repeat(&Scalar::ONE).take(n),
            public.participant_keys.iter(),
        );
        let part3_inner = &public.k_agg + &self.e_key * x - &sum_pi * z;
        let part3 = part3_inner * lambda_key;
        
        let sum_v = RistrettoPoint::vartime_multiscalar_mul(
            lambda_enc_powers.iter(),
            public.ciphertexts_v.iter(),
        );
        let sum_b = RistrettoPoint::vartime_multiscalar_mul(
            lambda_enc_powers.iter(),
            std::iter::repeat(&params.B).take(n),
        ) * z;
        let part4 = sum_v - &public.pk_enc * self.z_enc - sum_b + &self.e_enc * x;
        
        let p = part1 + part2 + part3 + part4;
        
        // 计算 P0
        let p0 = p + u * self.t_hat - &params.H * self.mu;
        println!("  初始 P0 = {:?}", p0.compress());
        
        println!("\n--- Step 4: 重新折叠验证IPA ---");
        
        // 重建折叠挑战
        let mut challenges = Vec::new();
        for (i, (L, R)) in self.ipa_proof.L_vec.iter().zip(self.ipa_proof.R_vec.iter()).enumerate() {
            transcript.append_point(b"L", L);
            transcript.append_point(b"R", R);
            let x_chal = transcript.challenge_scalar(b"u");
            challenges.push(x_chal);
            println!("  重建挑战 x{} = {}", i + 1, scalar_to_string(&x_chal));
        }
        
        // 初始化折叠状态
        let mut g_fold = g_prime.clone();
        let mut h_fold = h_prime.clone();
        let mut p_fold = p0;
        
        // 按照图片中的协议进行递归折叠
        for (round, &x_chal) in challenges.iter().enumerate() {
            println!("\n  第{}轮折叠，挑战 x = {}", round + 1, scalar_to_string(&x_chal));
            
            let half_n = g_fold.len() / 2;
            let (g_left, g_right) = g_fold.split_at(half_n);
            let (h_left, h_right) = h_fold.split_at(half_n);
            
            let L = &self.ipa_proof.L_vec[round];
            let R = &self.ipa_proof.R_vec[round];
            
            // 计算折叠参数
            let x_inv = x_chal.invert();
            let x_squared = x_chal * x_chal;
            let x_inv_squared = x_inv * x_inv;
            
            // 折叠基底（根据图片公式28-29）
            let new_g: Vec<RistrettoPoint> = g_left.iter()
                .zip(g_right.iter())
                .map(|(gl, gr)| gl * x_inv + gr * x_chal)
                .collect();
            
            let new_h: Vec<RistrettoPoint> = h_left.iter()
                .zip(h_right.iter())
                .map(|(hl, hr)| hl * x_chal + hr * x_inv)
                .collect();
            
            // 折叠承诺（根据图片公式30）
            p_fold = L * x_squared + p_fold + R * x_inv_squared;
            
            // 更新为折叠后的基底
            g_fold = new_g;
            h_fold = new_h;
            
            println!("    折叠后长度: {}", g_fold.len());
            println!("    折叠后 P' = {:?}", p_fold.compress());
        }
        
        // 最终验证（根据图片公式14）
        println!("\n--- Step 5: 最终验证 ---");
        println!("最终折叠结果:");
        println!("  g_final = {:?}", g_fold[0].compress());
        println!("  h_final = {:?}", h_fold[0].compress());
        println!("  P_final = {:?}", p_fold.compress());
        
        // 检查 P = g^a h^b u^c
        let c = self.ipa_proof.a * self.ipa_proof.b;
        let expected_p_final = g_fold[0] * self.ipa_proof.a + 
                              h_fold[0] * self.ipa_proof.b + 
                              u * c;
        
        println!("预期 P_final = g^a h^b u^c = {:?}", expected_p_final.compress());
        println!("实际 P_final = {:?}", p_fold.compress());
        
        if p_fold == expected_p_final {
            println!("✅ 普通验证通过！");
        } else {
            println!("❌ 普通验证失败！");
            println!("  差值 = {:?}", (p_fold - expected_p_final).compress());
            return Err(WTAPSError::VerificationFailed);
        }
        
        println!("\n=== 普通验证完成 ===");
        
        Ok(())
    }
}

// =========================================================================
// 计算挑战向量s的辅助函数
// =========================================================================

/*fn compute_challenge_vector(challenges: &[Scalar], n: usize) -> Vec<Scalar> {
    let log_n = challenges.len();
    let mut s_vec = vec![Scalar::ONE; n];
    
    for i in 0..n {
        let mut s_i = Scalar::ONE;
        let mut index = i;
        
        // 对于每个挑战u_k，根据i-1的二进制表示决定使用u_k还是u_k^{-1}
        for (k, &u_k) in challenges.iter().enumerate() {
            let bit = (index & 1) as i32; // 当前最低位
            index >>= 1; // 右移一位
            
            if bit == 1 {
                // 如果该位为1，乘以u_k
                s_i = s_i * u_k;
            } else {
                // 如果该位为0，乘以u_k^{-1}
                s_i = s_i * u_k.invert();
            }
        }
        
        s_vec[i] = s_i;
    }
    
    s_vec
}*/

fn compute_challenge_vector(challenges: &[Scalar], n: usize) -> Vec<Scalar> {
    let log_n = challenges.len();
    let mut s_vec = vec![Scalar::ONE; n];
    
    for i in 0..n {
        for (j, &u_j) in challenges.iter().enumerate() {
            // 关键：第 j 轮挑战 (u_j) 对应二进制从高到低的第 j 位
            // 例如 n=8, j=0 (u1) 检查的是 2^2 位 (i >> 2)
            // j=1 (u2) 检查的是 2^1 位 (i >> 1)
            let bit = (i >> (log_n - 1 - j)) & 1;
            
            if bit == 1 {
                s_vec[i] *= u_j;
            } else {
                s_vec[i] *= u_j.invert();
            }
        }
    }
    s_vec
}
// =========================================================================
// 验证函数 - 快速验证（使用图片中的公式）
// =========================================================================

impl WTAPSProof {
    pub fn verify_fast(
        &self,
        params: &PublicParams,
        public: &PublicInput,
    ) -> Result<(), WTAPSError> {
        println!("\n=== 开始快速验证（使用挑战向量s）===");
        let n = params.n;
        
        // 初始化transcript - 严格按照证明阶段的顺序
        let mut transcript = Transcript::new(b"WTAPS_NIZK");
        
        println!("\n--- Step 1: 重建挑战 ---");
        transcript.append_point(b"c_w", &self.c_w);
        transcript.append_point(b"A", &self.a);
        transcript.append_point(b"S", &self.s);
        
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        println!("挑战 y = {}", scalar_to_string(&y));
        println!("挑战 z = {}", scalar_to_string(&z));
        
        transcript.append_point(b"T1", &self.t1);
        transcript.append_point(b"T2", &self.t2);
        
        let x = transcript.challenge_scalar(b"x");
        println!("挑战 x = {}", scalar_to_string(&x));
        
        transcript.append_scalar(b"tau_x", &self.tau_x);
        transcript.append_scalar(b"mu", &self.mu);
        transcript.append_scalar(b"t_hat", &self.t_hat);
        transcript.append_scalar(b"t_y", &self.t_y);
        transcript.append_scalar(b"W_y", &self.W_y);
        transcript.append_point(b"E_key", &self.e_key);
        
        let lambda_key = transcript.challenge_scalar(b"lambda_key");
        let lambda_enc = transcript.challenge_scalar(b"lambda_enc");
        println!("额外挑战:");
        println!("  λ_key = {}", scalar_to_string(&lambda_key));
        println!("  λ_enc = {}", scalar_to_string(&lambda_enc));
        
        transcript.append_scalar(b"z_enc", &self.z_enc);
        transcript.append_point(b"E_enc", &self.e_enc);
        
        let u = transcript.challenge_point(b"U");
        println!("  U = {:?}", u.compress());
        
        // 阈值一致性检查（与普通验证相同）
        println!("\n--- Step 2: 阈值一致性检查 ---");
        let y_powers = compute_y_powers(&y, n);
        let sum_y_powers: Scalar = y_powers.iter().sum();
        
        let z_squared = z * z;
        let z_cubed = z_squared * z;
        let delta = (z - z_squared) * sum_y_powers - z_cubed * self.W_y;
        
        let lhs = &params.G * self.t_hat + &params.H * self.tau_x;
        let rhs = &params.G * (z_squared * self.t_y + delta) + &self.t1 * x + &self.t2 * (x * x);
        
        if lhs != rhs {
            println!("❌ 阈值一致性检查失败！");
            return Err(WTAPSError::VerificationFailed);
        }
        println!("✅ 阈值一致性检查通过！");
        
        println!("\n--- Step 3: 构建Super Basis ---");
        
        // 构建 Super Basis
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
            let g_prime_i = params.g_vec[i] + 
                public.participant_keys[i] * lambda_key + 
                params.B * lambda_enc_powers[i];
            g_prime.push(g_prime_i);
        }
        
        let y_inv_powers = compute_y_inv_powers(&y, n);
        for i in 0..n {
            h_prime.push(params.h_vec[i] * y_inv_powers[i]);
        }
        
        // 重建目标承诺 P
        let z_squared = z * z;
        
        let part1 = &self.a + &self.s * x + &self.c_w * z_squared;
        
        let minus_z = -z;
        let sum_g = RistrettoPoint::vartime_multiscalar_mul(
            std::iter::repeat(minus_z).take(n),
            params.g_vec.iter(),
        );
        let sum_h = RistrettoPoint::vartime_multiscalar_mul(
            std::iter::repeat(z).take(n),
            params.h_vec.iter(),
        );
        let part2 = sum_h + sum_g;
        
        let sum_pi = RistrettoPoint::vartime_multiscalar_mul(
            std::iter::repeat(&Scalar::ONE).take(n),
            public.participant_keys.iter(),
        );
        let part3_inner = &public.k_agg + &self.e_key * x - &sum_pi * z;
        let part3 = part3_inner * lambda_key;
        
        let sum_v = RistrettoPoint::vartime_multiscalar_mul(
            lambda_enc_powers.iter(),
            public.ciphertexts_v.iter(),
        );
        let sum_b = RistrettoPoint::vartime_multiscalar_mul(
            lambda_enc_powers.iter(),
            std::iter::repeat(&params.B).take(n),
        ) * z;
        let part4 = sum_v - &public.pk_enc * self.z_enc - sum_b + &self.e_enc * x;
        
        let p = part1 + part2 + part3 + part4;
        
        // 计算 P0
        let p0 = p + u * self.t_hat - &params.H * self.mu;
        println!("  初始 P0 = {:?}", p0.compress());
        
        println!("\n--- Step 4: 重建挑战并计算挑战向量s ---");
        
        // 重建IPA挑战
        let mut challenges = Vec::new();
        for (i, (L, R)) in self.ipa_proof.L_vec.iter().zip(self.ipa_proof.R_vec.iter()).enumerate() {
            transcript.append_point(b"L", L);
            transcript.append_point(b"R", R);
            let x_chal = transcript.challenge_scalar(b"u");
            challenges.push(x_chal);
            println!("  挑战 u{} = {}", i + 1, scalar_to_string(&x_chal));
        }
        
        // 计算挑战向量 s = (s₁, ..., s_N)
        let s_vec = compute_challenge_vector(&challenges, n);
        println!("  挑战向量 s 计算完成，长度: {}", s_vec.len());
        println!("  前几个s值: {}", scalars_to_string(&s_vec[0..std::cmp::min(4, n)], n));
        
        // 计算 s_i 的逆向量
        let s_inv_vec: Vec<Scalar> = s_vec.iter().map(|s| s.invert()).collect();
        
        println!("\n--- Step 5: 直接计算G'_final和H'_final ---");
        println!("公式: G'_final = Σ s_i * g'_i");
        println!("      H'_final = Σ s_i⁻¹ * h'_i");
        
        // 计算 G'_final = Σ s_i * g'_i
        let G_final = RistrettoPoint::vartime_multiscalar_mul(
            s_vec.iter(),
            g_prime.iter(),
        );
        
        // 计算 H'_final = Σ s_i⁻¹ * h'_i
        let H_final = RistrettoPoint::vartime_multiscalar_mul(
            s_inv_vec.iter(),
            h_prime.iter(),
        );
        
        println!("  G'_final = {:?}", G_final.compress());
        println!("  H'_final = {:?}", H_final.compress());
        
        println!("\n--- Step 6: 验证图片中的公式 ---");
        println!("公式: [ab]U + [a]G'_final + [b]H'_final = P_0 + Σ([u_k²]L_k + [u_k{{-2}}]R_k)");
        
        // 计算左边: [ab]U + [a]G'_final + [b]H'_final
        let ab = self.ipa_proof.a * self.ipa_proof.b;
        let left_side = u * ab + G_final * self.ipa_proof.a + H_final * self.ipa_proof.b;
        
        println!("  左边计算:");
        println!("    a = {}, b = {}, ab = {}", 
            scalar_to_string(&self.ipa_proof.a),
            scalar_to_string(&self.ipa_proof.b),
            scalar_to_string(&ab));
        println!("    [ab]U = {:?}", (u * ab).compress());
        println!("    [a]G'_final = {:?}", (G_final * self.ipa_proof.a).compress());
        println!("    [b]H'_final = {:?}", (H_final * self.ipa_proof.b).compress());
        println!("    左边总和 = {:?}", left_side.compress());
        
        // 计算右边: P_0 + Σ([u_k²]L_k + [u_k^{-2}]R_k)
        let mut right_side = p0;
        println!("\n  右边计算:");
        println!("    初始 P0 = {:?}", right_side.compress());
        
        for (i, &x_chal) in challenges.iter().enumerate() {
            let x_squared = x_chal * x_chal;
            let x_inv_squared = x_chal.invert() * x_chal.invert();
            
            let L = &self.ipa_proof.L_vec[i];
            let R = &self.ipa_proof.R_vec[i];
            
            println!("    第{}轮:", i+1);
            println!("      [u{}²]L{} = {:?}", i+1, i+1, (L * x_squared).compress());
            println!("      [u{}{{-2}}]R{} = {:?}", i+1, i+1, (R * x_inv_squared).compress());
            
            right_side = right_side + L * x_squared + R * x_inv_squared;
            println!("      当前右边值 = {:?}", right_side.compress());
        }
        
        println!("\n--- Step 7: 比较左右两边 ---");
        println!("  左边: {:?}", left_side.compress());
        println!("  右边: {:?}", right_side.compress());
        
        if left_side == right_side {
            println!("✅ 快速验证通过！");
            println!("  [ab]U + [a]G'_final + [b]H'_final = P_0 + Σ([u_k²]L_k + [u_k{{-2}}]R_k)");
        } else {
            println!("❌ 快速验证失败！");
            println!("  差值 = {:?}", (left_side - right_side).compress());
            return Err(WTAPSError::VerificationFailed);
        }
        
        println!("\n=== 快速验证完成 ===");
        
        Ok(())
    }
}
// =========================================================================
// 验证函数 - 快速验证（使用图片中的公式）- 修正版
// =========================================================================

// =========================================================================
// 验证两种方法的一致性
// =========================================================================

impl WTAPSProof {
    pub fn verify_consistency(
        &self,
        params: &PublicParams,
        public: &PublicInput,
    ) -> Result<(), WTAPSError> {
        println!("\n=== 验证两种方法的一致性 ===");
        
        // 首先，我们需要重建所有挑战来计算s向量
        let mut transcript = Transcript::new(b"WTAPS_NIZK");
        let n = params.n;
        
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
        
        // 构建Super Basis
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
            let g_prime_i = params.g_vec[i] + 
                public.participant_keys[i] * lambda_key + 
                params.B * lambda_enc_powers[i];
            g_prime.push(g_prime_i);
        }
        
        let y_inv_powers = compute_y_inv_powers(&y, n);
        for i in 0..n {
            h_prime.push(params.h_vec[i] * y_inv_powers[i]);
        }
        
        // 重建IPA挑战
        let mut challenges = Vec::new();
        for (L, R) in self.ipa_proof.L_vec.iter().zip(self.ipa_proof.R_vec.iter()) {
            transcript.append_point(b"L", L);
            transcript.append_point(b"R", R);
            let x_chal = transcript.challenge_scalar(b"u");
            challenges.push(x_chal);
        }
        
        println!("挑战数量: {}", challenges.len());
        
        // 方法1: 递归折叠计算最终的g_final和h_final
        let mut g_fold = g_prime.clone();
        let mut h_fold = h_prime.clone();
        
        for &x_chal in &challenges {
            let half_n = g_fold.len() / 2;
            let (g_left, g_right) = g_fold.split_at(half_n);
            let (h_left, h_right) = h_fold.split_at(half_n);
            
            let x_inv = x_chal.invert();
            
            let new_g: Vec<RistrettoPoint> = g_left.iter()
                .zip(g_right.iter())
                .map(|(gl, gr)| gl * x_inv + gr * x_chal)
                .collect();
            
            let new_h: Vec<RistrettoPoint> = h_left.iter()
                .zip(h_right.iter())
                .map(|(hl, hr)| hl * x_chal + hr * x_inv)
                .collect();
            
            g_fold = new_g;
            h_fold = new_h;
        }
        
        let g_final_recursive = g_fold[0];
        let h_final_recursive = h_fold[0];
        
        println!("递归折叠结果:");
        println!("  g_final_recursive = {:?}", g_final_recursive.compress());
        println!("  h_final_recursive = {:?}", h_final_recursive.compress());
        
        // 方法2: 使用挑战向量s直接计算
        let s_vec = compute_challenge_vector(&challenges, n);
        let s_inv_vec: Vec<Scalar> = s_vec.iter().map(|s| s.invert()).collect();
        
        let g_final_direct = RistrettoPoint::vartime_multiscalar_mul(
            s_vec.iter(),
            g_prime.iter(),
        );
        
        let h_final_direct = RistrettoPoint::vartime_multiscalar_mul(
            s_inv_vec.iter(),
            h_prime.iter(),
        );
        
        println!("\n直接计算结果:");
        println!("  g_final_direct = {:?}", g_final_direct.compress());
        println!("  h_final_direct = {:?}", h_final_direct.compress());
        
        // 比较两种方法的结果
        if g_final_recursive == g_final_direct && h_final_recursive == h_final_direct {
            println!("\n✅ 两种方法计算的G'_final和H'_final完全一致！");
            println!("  递归折叠方法 ≡ 直接计算方法");
            
            // 进一步验证图片中的公式
            let ab = self.ipa_proof.a * self.ipa_proof.b;
            let left_side = u * ab + g_final_direct * self.ipa_proof.a + h_final_direct * self.ipa_proof.b;
            
            // 计算P0
            let z_squared = z * z;
            let minus_z = -z;
            
            let sum_g = RistrettoPoint::vartime_multiscalar_mul(
                std::iter::repeat(minus_z).take(n),
                params.g_vec.iter(),
            );
            let sum_h = RistrettoPoint::vartime_multiscalar_mul(
                std::iter::repeat(z).take(n),
                params.h_vec.iter(),
            );
            
            let sum_pi = RistrettoPoint::vartime_multiscalar_mul(
                std::iter::repeat(&Scalar::ONE).take(n),
                public.participant_keys.iter(),
            );
            let part3_inner = &public.k_agg + &self.e_key * x - &sum_pi * z;
            let part3 = part3_inner * lambda_key;
            
            let sum_v = RistrettoPoint::vartime_multiscalar_mul(
                lambda_enc_powers.iter(),
                public.ciphertexts_v.iter(),
            );
            let sum_b = RistrettoPoint::vartime_multiscalar_mul(
                lambda_enc_powers.iter(),
                std::iter::repeat(&params.B).take(n),
            ) * z;
            let part4 = sum_v - &public.pk_enc * self.z_enc - sum_b + &self.e_enc * x;
            
            let p = &self.a + &self.s * x + &self.c_w * z_squared + 
                    sum_h + sum_g + part3 + part4;
            
            let p0 = p + u * self.t_hat - &params.H * self.mu;
            
            // 计算右边
            let mut right_side = p0;
            for (i, &x_chal) in challenges.iter().enumerate() {
                let x_squared = x_chal * x_chal;
                let x_inv_squared = x_chal.invert() * x_chal.invert();
                
                let L = &self.ipa_proof.L_vec[i];
                let R = &self.ipa_proof.R_vec[i];
                
                right_side = right_side + L * x_squared + R * x_inv_squared;
            }
            
            if left_side == right_side {
                println!("✅ 图片中的公式验证通过！");
            } else {
                println!("❌ 图片中的公式验证失败！");
                return Err(WTAPSError::VerificationFailed);
            }
        } else {
            println!("\n❌ 两种方法计算的G'_final和H'_final不一致！");
            println!("  g_final_recursive ≠ g_final_direct: {}", 
                g_final_recursive != g_final_direct);
            println!("  h_final_recursive ≠ h_final_direct: {}", 
                h_final_recursive != h_final_direct);
            return Err(WTAPSError::VerificationFailed);
        }
        
        Ok(())
    }
}

// =========================================================================
// 主函数
// =========================================================================

fn main() {
    println!("==========================================");
    println!("      WTAPS NIZK 协议实现");
    println!("      测试普通验证与快速验证");
    println!("==========================================");
    
    let mut rng = OsRng;
    let n = 8; // 使用更大的n以测试多轮折叠
    
    println!("\n[1] 生成公共参数");
    let params = PublicParams::new(n, &mut rng);
    
    println!("\n[2] 准备测试数据");
    
    let b = vec![
        Scalar::ONE,
        Scalar::ZERO,
        Scalar::ONE,
        Scalar::ONE,
        Scalar::ZERO,
        Scalar::ONE,
        Scalar::ZERO,
        Scalar::ONE,
    ];
    
    let w = vec![
        Scalar::from(1u64),
        Scalar::from(2u64),
        Scalar::from(3u64),
        Scalar::from(4u64),
        Scalar::from(5u64),
        Scalar::from(6u64),
        Scalar::from(7u64),
        Scalar::from(8u64),
    ];
    
    println!("二进制向量 b: {}", binary_vector_to_string(&b, n));
    println!("权重向量 w: [{}]", scalars_to_string(&w, n));
    
    let mut t = Scalar::ZERO;
    for i in 0..n {
        t += b[i] * w[i];
    }
    println!("阈值 t = ⟨b, w⟩ = {}", scalar_to_string(&t));
    
    let participant_keys: Vec<RistrettoPoint> = 
        (0..n).map(|_| RistrettoPoint::random(&mut rng)).collect();
    
    let mut k_agg = RistrettoPoint::identity();
    for i in 0..n {
        if b[i] == Scalar::ONE {
            k_agg += participant_keys[i];
        }
    }
    
    let sk_enc = Scalar::random(&mut rng);
    let pk_enc = &params.G * sk_enc;
    
    let r_enc: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    let mut ciphertexts_v = Vec::new();
    
    for i in 0..n {
        let v_i = &pk_enc * r_enc[i] + &params.B * b[i];
        ciphertexts_v.push(v_i);
    }
    
    let rho_w = Scalar::random(&mut rng);
    let c_w = RistrettoPoint::multiscalar_mul(
        iter::once(&rho_w).chain(w.iter()),
        iter::once(&params.H).chain(params.h_vec.iter()),
    );
    
    let w_total: Scalar = w.iter().sum();
    
    let public_input = PublicInput {
        ciphertexts_v,
        k_agg,
        t,
        pk_enc,
        participant_keys,
        c_w,
        w_total,
    };
    
    let secret_witness = SecretWitness {
        b,
        w,
        r_enc,
        rho_w,
    };
    
    println!("\n[3] 开始生成证明");
    println!("==========================================");
    
    let proof = match WTAPSProof::prove(
        &params,
        &public_input,
        &secret_witness,
        &mut rng,
    ) {
        Ok(p) => {
            println!("✅ 证明生成成功！");
            p
        }
        Err(e) => {
            println!("❌ 证明生成失败: {:?}", e);
            return;
        }
    };
    
    println!("\n[4] 开始普通验证（递归折叠方法）");
    println!("==========================================");
    
    match proof.verify_normal(&params, &public_input) {
        Ok(_) => {
            println!("\n==========================================");
            println!("          ✅ 普通验证成功！");
            println!("==========================================");
        }
        Err(e) => {
            println!("\n==========================================");
            println!("          ❌ 普通验证失败: {:?}", e);
            println!("==========================================");
            return;
        }
    }
    
    println!("\n[5] 开始快速验证（使用挑战向量s）");
    println!("==========================================");
    
    match proof.verify_fast(&params, &public_input) {
        Ok(_) => {
            println!("\n==========================================");
            println!("          ✅ 快速验证成功！");
            println!("==========================================");
        }
        Err(e) => {
            println!("\n==========================================");
            println!("          ❌ 快速验证失败: {:?}", e);
            println!("==========================================");
            return;
        }
    }
    
    println!("\n[6] 验证两种方法的一致性");
    println!("==========================================");
    
    match proof.verify_consistency(&params, &public_input) {
        Ok(_) => {
            println!("\n==========================================");
            println!("          ✅ 一致性验证成功！");
            println!("==========================================");
        }
        Err(e) => {
            println!("\n==========================================");
            println!("          ❌ 一致性验证失败: {:?}", e);
            println!("==========================================");
        }
    }
    
    println!("\n==========================================");
    println!("         测试完成");
    println!("==========================================");
}