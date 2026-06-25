use anyhow::Result;
use clap::{Parser, Subcommand};
use rand::RngCore;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// how many iterations
    #[arg(short, long, default_value_t = 10_000)]
    n: usize,

    #[command(subcommand)]
    cmd: Commands,
}

/// Run the full Figure 1 comparison benchmark
/// Tests all schemes across varying numbers of signers
fn bench_fig1(sizes: &[usize], iters: usize) -> Result<()> {
    println!("==============================================");
    println!("  Figure 1: Comprehensive Protocol Comparison");
    println!("  Benchmarks: WTAS vs Weighted FROST vs BLS vs Schnorr");
    println!("==============================================\n");

    // CSV header for easy plotting
    println!("scheme,n_signers,active_signers,total_weight,threshold,sign_us,verify_us,comm_bytes,comm_per_signer");

    for &n in sizes {
        let weights: Vec<u64> = (0..n)
            .map(|i| 2u64.pow((i % 4) as u32))
            .collect();
        let total_weight: u64 = weights.iter().sum();
        let threshold = (total_weight + 1) / 2;

        // Count how many signers needed to meet threshold
        let mut cum = 0u64;
        let mut k = 0usize;
        for &w in &weights {
            if cum >= threshold { break; }
            cum += w;
            k += 1;
        }

        let log_n = (n as f64).log2().ceil() as usize;

        // --- WTAS (our scheme: Ed25519, pairing-free) ---
        let sign_us = bench_wtas_signing(n, &weights, threshold, iters);
        let verify_us = bench_wtas_verify(n, &weights, threshold, iters);
        // Comm: 64B per active signer (R_i + s_i) + 64B ElGamal ct + NIZK proof
        let comm = 128 * k + (2 * log_n + 6) * 32 + 5 * 32;
        println!("WTAS,{n},{k},{total_weight},{threshold},{sign_us:.1},{verify_us:.1},{comm},{:.0}", comm as f64 / k as f64);

        // --- Weighted FROST (Virtualization: weight w → w virtual nodes) ---
        // Communication scales with total_active_weight (Σ w_i of active signers),
        // NOT with k (number of signers). Each virtual node sends its own nonce + partial sig.
        let sign_us = bench_frost_signing(n, &weights, threshold, cum, iters);
        let verify_us = bench_frost_verify(n, &weights, threshold, iters);
        let comm_frost = 96 * cum as usize; // 96 bytes per virtual node
        println!("WeightedFROST,{n},{k},{total_weight},{threshold},{sign_us:.1},{verify_us:.1},{comm_frost},{:.0}", comm_frost as f64 / k as f64);

        // --- BLS Baseline (equal weight, no accountability) ---
        let sign_us = bench_bls_signing(n, iters);
        let verify_us = bench_bls_verify(n, iters);
        let comm_bls = 96; // Single aggregate signature
        println!("BLS(baseline),{n},{n},-,{n},{sign_us:.1},{verify_us:.1},{comm_bls},{:.0}", comm_bls as f64 / n as f64);

        // --- Schnorr Baseline (equal weight, no accountability) ---
        let sign_us = bench_schnorr_signing(n, iters);
        let verify_us = bench_schnorr_verify(n, iters);
        let comm_schnorr = 64; // Single Schnorr signature (R + s)
        println!("Schnorr(baseline),{n},{n},-,{n},{sign_us:.1},{verify_us:.1},{comm_schnorr},{:.0}", comm_schnorr as f64 / n as f64);

        println!(); // Empty line between sizes
    }

    Ok(())
}

fn fmt_us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

// ---- Individual scheme benchmarks (used by bench_fig1) ----

// ---- WTAS: Ed25519 weighted multi-signature (pairing-free, our scheme) ----
fn bench_wtas_signing(n: usize, weights: &[u64], threshold: u64, iters: usize) -> f64 {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    let msg = b"fig1-bench-msg";
    let mut rng = rand::thread_rng();

    // Generate Ed25519 keypairs
    let mut sks = Vec::with_capacity(n);
    let mut pks = Vec::with_capacity(n);
    for _ in 0..n {
        let mut b = [0u8; 64];
        rng.fill_bytes(&mut b);
        let sk = Scalar::from_bytes_mod_order_wide(&b);
        let pk: EdwardsPoint = ED25519_BASEPOINT_TABLE * &sk;
        sks.push(sk);
        pks.push(pk);
    }

    // Select signers meeting threshold
    let mut active = Vec::new();
    let mut cum = 0u64;
    for i in 0..n {
        if cum >= threshold { break; }
        active.push(i);
        cum += weights[i];
    }
    let k = active.len();

    // Compute group PK = Σ w_i * pk_i
    let mut group_pk = EdwardsPoint::default();
    for &i in &active {
        group_pk += pks[i] * Scalar::from(weights[i]);
    }

    let mut best = Duration::MAX;
    for _ in 0..iters.min(100) {
        let t0 = Instant::now();

        // Round 1: nonce generation
        let mut nonces = Vec::with_capacity(k);
        let mut r_agg = EdwardsPoint::default();
        for _ in 0..k {
            let mut b = [0u8; 64];
            rng.fill_bytes(&mut b);
            let r = Scalar::from_bytes_mod_order_wide(&b);
            r_agg += ED25519_BASEPOINT_TABLE * &r;
            nonces.push(r);
        }

        // Challenge c = H(R_agg, PK, msg)
        let mut h = Sha512::new();
        h.update(b"WTAS_challenge");
        h.update(r_agg.compress().as_bytes());
        h.update(group_pk.compress().as_bytes());
        h.update(msg);
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&h.finalize());
        let c = Scalar::from_bytes_mod_order_wide(&wide);

        // Round 2: partial signatures s_i = r_i + c * w_i * sk_i
        let s_agg: Scalar = active.iter().enumerate().map(|(idx, &i)| {
            nonces[idx] + c * Scalar::from(weights[i]) * sks[i]
        }).sum();

        std::hint::black_box(&s_agg);
        best = best.min(t0.elapsed());
    }
    fmt_us(best)
}

fn bench_wtas_verify(_n: usize, _weights: &[u64], _threshold: u64, iters: usize) -> f64 {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    let mut rng = rand::thread_rng();
    let msg = b"fig1-verify-bench";

    // Generate a test keypair and signature
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    let sk = Scalar::from_bytes_mod_order_wide(&b);
    let pk: EdwardsPoint = ED25519_BASEPOINT_TABLE * &sk;

    // Create a valid test signature
    rng.fill_bytes(&mut b);
    let r_val = Scalar::from_bytes_mod_order_wide(&b);
    let r_pt: EdwardsPoint = ED25519_BASEPOINT_TABLE * &r_val;

    let mut h = Sha512::new();
    h.update(b"WTAS_challenge");
    h.update(r_pt.compress().as_bytes());
    h.update(pk.compress().as_bytes());
    h.update(msg);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    let c = Scalar::from_bytes_mod_order_wide(&wide);
    let s_val = r_val + c * sk; // Valid signature (R=r_pt, s=s_val)

    let mut best = Duration::MAX;
    for _ in 0..iters.min(200) {
        let start = Instant::now();
        let lhs: EdwardsPoint = ED25519_BASEPOINT_TABLE * &s_val;
        let rhs = r_pt + pk * c;
        let ok = lhs.compress() == rhs.compress();
        let dur = start.elapsed();
        best = best.min(dur);
        std::hint::black_box(&ok);
    }
    fmt_us(best)
}

fn bench_frost_signing(n: usize, weights: &[u64], threshold: u64, total_active_weight: u64, iters: usize) -> f64 {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    let message = b"fig1-bench-msg";
    let mut rng = rand::thread_rng();

    // Generate keypairs (one per signer)
    let mut sks = Vec::with_capacity(n);
    for _ in 0..n {
        let mut b = [0u8; 64];
        rng.fill_bytes(&mut b);
        sks.push(Scalar::from_bytes_mod_order_wide(&b));
    }

    // V-FROST virtualization: signer with weight w_i simulates w_i virtual nodes.
    // Each virtual node generates its own nonce and partial signature.
    // Total operations scale with Σw_active = total_active_weight, NOT with k.
    let num_virtual = total_active_weight as usize;

    let mut best = Duration::MAX;
    for _ in 0..iters.min(100) {
        let t0 = Instant::now();

        // Round 1: each virtual node generates 2 nonces (d, e) → (D, E)
        for _ in 0..num_virtual {
            let mut b = [0u8; 64];
            rng.fill_bytes(&mut b);
            let d = Scalar::from_bytes_mod_order_wide(&b);
            rng.fill_bytes(&mut b);
            let e = Scalar::from_bytes_mod_order_wide(&b);
            let D = ED25519_BASEPOINT_TABLE * &d;
            let E = ED25519_BASEPOINT_TABLE * &e;
            std::hint::black_box((D, E));
        }

        // Round 2: each virtual node generates 1 partial signature
        for _ in 0..num_virtual {
            let mut b = [0u8; 64];
            rng.fill_bytes(&mut b);
            let z = Scalar::from_bytes_mod_order_wide(&b);
            std::hint::black_box(z);
        }

        best = best.min(t0.elapsed());
    }
    fmt_us(best)
}

fn bench_frost_verify(_n: usize, _weights: &[u64], _threshold: u64, iters: usize) -> f64 {
    // Ed25519 verification: scalar*B + point addition
    // Measure actual verification using dalek
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    let mut rng = rand::thread_rng();
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    let sk = Scalar::from_bytes_mod_order_wide(&b);
    let pk: EdwardsPoint = ED25519_BASEPOINT_TABLE * &sk;

    // Generate a test signature
    let msg = b"fig1-verify-bench";
    let mut h = Sha512::new();
    h.update(b"FROST_challenge");
    h.update(pk.compress().as_bytes());
    h.update(msg);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    let c = Scalar::from_bytes_mod_order_wide(&wide);
    let z = Scalar::from_bytes_mod_order_wide(&b); // Simplified sig
    let r: EdwardsPoint = ED25519_BASEPOINT_TABLE * &z - pk * c;

    let mut best = Duration::MAX;
    for _ in 0..iters.min(200) {
        let start = Instant::now();
        let lhs: EdwardsPoint = ED25519_BASEPOINT_TABLE * &z;
        let rhs = r + pk * c;
        let ok = lhs.compress() == rhs.compress();
        let dur = start.elapsed();
        best = best.min(dur);
        std::hint::black_box(&ok);
    }
    fmt_us(best)
}

fn bench_bls_signing(n: usize, iters: usize) -> f64 {
    use blst::min_sig::SecretKey;
    const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    let message = b"fig1-bench-msg";

    let mut sks = Vec::with_capacity(n);
    for _ in 0..n {
        let mut ikm = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ikm);
        sks.push(SecretKey::key_gen(&ikm, &[]).unwrap());
    }

    let mut best = Duration::MAX;
    for _ in 0..iters.min(100) {
        let t0 = Instant::now();
        let sigs: Vec<_> = sks.iter().map(|sk| sk.sign(message, DST, &[])).collect();
        let sig_refs: Vec<&blst::min_sig::Signature> = sigs.iter().collect();
        let _agg = blst::min_sig::AggregateSignature::aggregate(&sig_refs, true).unwrap();
        best = best.min(t0.elapsed());
    }
    fmt_us(best)
}

fn bench_bls_verify(_n: usize, iters: usize) -> f64 {
    // BLS aggregate verify: same as WTAS verify (one pairing)
    // Reuse the pairing methodology
    use blst::{blst_fp12, blst_miller_loop, blst_final_exp, blst_p1_affine, blst_p2_affine};
    use blst::min_pk::SecretKey;

    let mut rng = rand::thread_rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();
    let msg = b"fig1-verify-bench";
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let sig = sk.sign(msg, dst, &[]);

    let p_affine: blst_p1_affine = blst_p1_affine::from(pk);
    let q_affine: blst_p2_affine = blst_p2_affine::from(sig);

    let mut best = Duration::MAX;
    unsafe {
        let mut tmp_fp12: blst_fp12 = std::mem::zeroed();
        let mut out_fp12: blst_fp12 = std::mem::zeroed();
        for _ in 0..iters.min(100) {
            let start = Instant::now();
            blst_miller_loop(&mut tmp_fp12 as *mut _, &q_affine as *const _, &p_affine as *const _);
            blst_final_exp(&mut out_fp12 as *mut _, &tmp_fp12 as *const _);
            let dur = start.elapsed();
            best = best.min(dur);
            std::hint::black_box(&out_fp12);
        }
    }
    fmt_us(best)
}

fn bench_schnorr_signing(n: usize, iters: usize) -> f64 {
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
    use secp256k1::rand::rngs::OsRng as SecpRng;
    use sha2::{Digest, Sha256};

    let secp = Secp256k1::new();
    let message = b"fig1-bench-msg";
    let m = secp256k1::Message::from_digest_slice(&<Sha256 as Digest>::digest(message)).unwrap();

    let mut kps = Vec::with_capacity(n);
    for _ in 0..n {
        kps.push(Keypair::new(&secp, &mut SecpRng));
    }

    let mut best = Duration::MAX;
    for _ in 0..iters.min(100) {
        let t0 = Instant::now();
        let mut sigs = Vec::with_capacity(n);
        for kp in &kps {
            sigs.push(secp.sign_schnorr(&m, kp));
        }
        best = best.min(t0.elapsed());
    }
    fmt_us(best)
}

fn bench_schnorr_verify(_n: usize, iters: usize) -> f64 {
    // Schnorr/BIP-340 verification: one scalar mult + point addition on secp256k1
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey, Message};
    use secp256k1::rand::rngs::OsRng as SecpRng;
    use sha2::{Digest, Sha256};

    let secp = Secp256k1::new();
    let kp = Keypair::new(&secp, &mut SecpRng);
    let (pk, _parity) = XOnlyPublicKey::from_keypair(&kp);
    let msg = b"fig1-verify-bench";
    let m = Message::from_digest_slice(&<Sha256 as Digest>::digest(msg)).unwrap();
    let sig = secp.sign_schnorr(&m, &kp);

    let mut best = Duration::MAX;
    for _ in 0..iters.min(200) {
        let start = Instant::now();
        let ok = secp.verify_schnorr(&sig, &m, &pk).is_ok();
        let dur = start.elapsed();
        best = best.min(dur);
        std::hint::black_box(&ok);
    }
    fmt_us(best)
}

#[derive(Subcommand)]
enum Commands {
    /// Measure Ed25519 (Edwards25519) scalar * basepoint
    Ed25519,
    /// Measure Schnorr on secp256k1: SecretKey -> PublicKey (scalar * G)
    Schnorr,
    /// Measure BLS scalar * G1 and optional pairing verify cost
    Bls {
        /// also measure pairing cost (signature verify) in addition to scalar mult
        #[arg(long)]
        pairing: bool,
        /// use low-level blst_p1_mult for pure G1 scalar multiply
        #[arg(long)]
        lowlevel: bool,
    },
    /// Measure hash functions (SHA-512, SHA-256, SHA3-256, Blake2b-512)
    Hash {
        /// message size in bytes (per hash)
        #[arg(short, long, default_value_t = 64)]
        size: usize,
    },
    /// Run comprehensive Fig1 comparison: WTAS vs WeightedFROST vs BLS vs Schnorr
    Fig1 {
        /// comma-separated list of signer counts (e.g., "8,16,32,64,128")
        #[arg(short, long, default_value = "8,16,32,64,128")]
        sizes: String,
        /// iterations per data point
        #[arg(short, long, default_value_t = 50)]
        iters: usize,
    },
}

fn stats_from_samples(samples: &[Duration]) -> (Duration, Duration, f64, f64) {
    // returns (min, max, avg_ns, stddev_ns)
    if samples.is_empty() {
        return (Duration::ZERO, Duration::ZERO, 0.0, 0.0);
    }
    let mut min = samples[0];
    let mut max = samples[0];
    let mut sum_ns: f64 = 0.0;
    for &d in samples {
        if d < min {
            min = d;
        }
        if d > max {
            max = d;
        }
        sum_ns += d.as_nanos() as f64;
    }
    let n = samples.len() as f64;
    let avg_ns = sum_ns / n;
    // stddev
    let mut var = 0.0;
    for &d in samples {
        let x = d.as_nanos() as f64;
        var += (x - avg_ns) * (x - avg_ns);
    }
    let stddev = (var / n).sqrt();
    (min, max, avg_ns, stddev)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Ed25519 => bench_ed25519(cli.n)?,
        Commands::Schnorr => bench_schnorr(cli.n)?,
        Commands::Bls { pairing, lowlevel } => bench_bls(cli.n, pairing, lowlevel)?,
        Commands::Hash { size } => bench_hashes(cli.n, size)?,
        Commands::Fig1 { sizes, iters } => {
            let parsed: Vec<usize> = sizes
                .split(',')
                .filter_map(|s| s.trim().parse::<usize>().ok())
                .collect();
            if parsed.is_empty() {
                eprintln!("Error: --sizes must be comma-separated integers (e.g., 8,16,32,64)");
                return Ok(());
            }
            println!("Running Fig.1 benchmarks for signer counts: {:?}\n", parsed);
            bench_fig1(&parsed, iters)?;
        }
    }

    Ok(())
}

// -------------------------------------------------
// Ed25519 (Edwards25519) scalar multiplication
fn bench_ed25519(n: usize) -> Result<()> {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    use rand::thread_rng;

    println!(
        "EdDSA (Ed25519) scalar*basepoint x {} (Edwards25519 group)",
        n
    );

    let mut rng = thread_rng();

    // warmup
    for _ in 0..200 {
        let mut r = [0u8; 32];
        rng.fill_bytes(&mut r);
        let _s = Scalar::from_bytes_mod_order(r);
        let _ = ED25519_BASEPOINT_TABLE * &_s;
    }

    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let mut r = [0u8; 32];
        rng.fill_bytes(&mut r);
        let s = Scalar::from_bytes_mod_order(r);
        let start = Instant::now();
        let p = ED25519_BASEPOINT_TABLE * &s;
        std::hint::black_box(&p);
        let dur = start.elapsed();
        samples.push(dur);
    }

    let (min, max, avg_ns, stddev_ns) = stats_from_samples(&samples);
    let total: Duration = samples.iter().sum();
    println!("Ed25519 scalar*G results (n={}):", n);
    println!(
        "  total: {:?}, avg: {:.2} ns/op, min: {:?}, max: {:?}, stddev: {:.2} ns",
        total, avg_ns, min, max, stddev_ns
    );
    Ok(())
}

// -------------------------------------------------
// Schnorr (secp256k1) scalar multiplication
fn bench_schnorr(n: usize) -> Result<()> {
    use rand::thread_rng;
    use secp256k1::{Secp256k1, SecretKey, PublicKey};

    println!(
        "Schnorr (secp256k1) SecretKey -> PublicKey x {} (secp256k1 group)",
        n
    );
    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    // warmup
    for _ in 0..200 {
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
            let _ = PublicKey::from_secret_key(&secp, &sk);
        }
    }

    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        // ensure valid scalar
        let sk = match SecretKey::from_slice(&sk_bytes) {
            Ok(s) => s,
            Err(_) => {
                let mut s2 = sk_bytes;
                s2[0] |= 1;
                SecretKey::from_slice(&s2).expect("should be valid")
            }
        };
        let start = Instant::now();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        std::hint::black_box(&pk);
        let dur = start.elapsed();
        samples.push(dur);
    }

    let (min, max, avg_ns, stddev_ns) = stats_from_samples(&samples);
    let total: Duration = samples.iter().sum();
    println!("secp256k1 scalar*G results (n={}):", n);
    println!(
        "  total: {:?}, avg: {:.2} ns/op, min: {:?}, max: {:?}, stddev: {:.2} ns",
        total, avg_ns, min, max, stddev_ns
    );
    Ok(())
}

// -------------------------------------------------
// BLS (BLS12-381) scalar multiplication and pairing
fn bench_bls(n: usize, pairing: bool, lowlevel: bool) -> Result<()> {
    println!(
        "BLS (BLS12-381) tests: scalar mult (G1) x {}, lowlevel={}, pairing_verify={}",
        n, lowlevel, pairing
    );

    if !lowlevel {
        use blst::min_pk::SecretKey; // min_pk uses public keys in G1, signatures in G2 by convention
        use rand::thread_rng;

        let mut rng = thread_rng();
        // warmup
        for _ in 0..50 {
            let mut ikm = [0u8; 32];
            rng.fill_bytes(&mut ikm);
            if let Ok(sk) = SecretKey::key_gen(&ikm, &[]).map_err(|e| anyhow::anyhow!("blst key_gen error: {:?}", e)) {
                let _pk = sk.sk_to_pk();
                std::hint::black_box(&_pk);
            }
        }

        // scalar mult samples
        let mut samples_pointmul = Vec::with_capacity(n);
        for _ in 0..n {
            let mut ikm = [0u8; 32];
            rng.fill_bytes(&mut ikm);
            let start = Instant::now();
            let sk = SecretKey::key_gen(&ikm, &[]).map_err(|e| anyhow::anyhow!("blst key_gen error: {:?}", e))?;
            let pk = sk.sk_to_pk(); // does scalar * G1
            std::hint::black_box(&pk);
            let dur = start.elapsed();
            samples_pointmul.push(dur);
        }
        let (min_pm, max_pm, avg_pm, std_pm) = stats_from_samples(&samples_pointmul);
        let total_pm: Duration = samples_pointmul.iter().sum();
        println!("BLS G1 scalar*G (high-level key_gen + sk_to_pk) (n={}):", n);
        println!(
            "  total: {:?}, avg: {:.2} ns/op, min: {:?}, max: {:?}, stddev: {:.2} ns",
            total_pm, avg_pm, min_pm, max_pm, std_pm
        );

        // optionally pairing (signature verify) measurements
        if pairing {
            use blst::min_pk::{SecretKey as SK2, Signature};
            let mut ikm = [0u8; 32];
            rng.fill_bytes(&mut ikm);
            let sk = SK2::key_gen(&ikm, &[]).map_err(|e| anyhow::anyhow!("blst key_gen error: {:?}", e))?;
            let pk = sk.sk_to_pk();
            let message = b"benchmark-message-for-pairing";
            let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"; // typical DST for min_pk

            let sig: Signature = sk.sign(message, dst, &[]);
            // warmup verifies
            for _ in 0..20 {
                let _ok = sig.verify(true, message, dst, &[], &pk, true);
                std::hint::black_box(&_ok);
            }

            let mut samples_verify = Vec::with_capacity(n);
            for _ in 0..n {
                let start = Instant::now();
                let ok = sig.verify(true, message, dst, &[], &pk, true);
                let dur = start.elapsed();
                samples_verify.push(dur);
                std::hint::black_box(&ok);
            }
            let (min_v, max_v, avg_v, std_v) = stats_from_samples(&samples_verify);
            let total_v: Duration = samples_verify.iter().sum();
            println!("BLS signature verify (includes hash_to_curve + pairing) (n={}):", n);
            println!(
                "  total: {:?}, avg: {:.2} ns/op, min: {:?}, max: {:?}, stddev: {:.2} ns",
                total_v, avg_v, min_v, max_v, std_v
            );
        }
    } else {
        // low-level blst_p1_mult for direct G1 scalar mult (C-FFI call)
        use blst::{blst_p1, blst_p1_generator, blst_p1_mult};
        use rand::thread_rng;

        let mut rng = thread_rng();
        // warmup
        unsafe {
            for _ in 0..50 {
                let mut scalar = [0u8; 32];
                rng.fill_bytes(&mut scalar);
                let mut out: blst_p1 = std::mem::zeroed();
                let g = blst_p1_generator(); // g is *const blst_p1
                blst_p1_mult(&mut out as *mut _, g, scalar.as_ptr(), 256);
                std::hint::black_box(&out);
            }
        }

        let mut samples = Vec::with_capacity(n);
        unsafe {
            for _ in 0..n {
                let mut scalar = [0u8; 32];
                rng.fill_bytes(&mut scalar);
                let start = Instant::now();
                let mut out: blst_p1 = std::mem::zeroed();
                let g = blst_p1_generator();
                blst_p1_mult(&mut out as *mut _, g, scalar.as_ptr(), 256);
                std::hint::black_box(&out);
                let dur = start.elapsed();
                samples.push(dur);
            }
        }
        let (min, max, avg_ns, stddev_ns) = stats_from_samples(&samples);
        let total: Duration = samples.iter().sum();
        println!(
            "BLS G1 scalar*G (low-level blst_p1_mult) (n={}):",
            n
        );
        println!(
            "  total: {:?}, avg: {:.2} ns/op, min: {:?}, max: {:?}, stddev: {:.2} ns",
            total, avg_ns, min, max, stddev_ns
        );
    }

    Ok(())
}

// -------------------------------------------------
// Hash benchmarks
fn bench_hashes(n: usize, size: usize) -> Result<()> {
    use digest::Digest;
    use rand::thread_rng;
    use sha2::{Sha256, Sha512};
    use sha3::Sha3_256;
    use blake2::Blake2b512;

    println!("Hash benchmark: {} iterations, message size {} bytes", n, size);

    let mut rng = thread_rng();
    // prepare message buffer
    let mut msg = vec![0u8; size];

    // helper to run a generic Digest impl
    fn bench<D: Digest + Default>(n: usize, msg: &mut [u8]) -> (Duration, Duration, f64, f64)
    where
        D: Digest,
    {
        let mut samples: Vec<Duration> = Vec::with_capacity(n);
        for _ in 0..n {
            // randomize input to avoid caching effects
            rand::thread_rng().fill_bytes(msg);
            let start = Instant::now();
            let mut hasher = D::default();
            hasher.update(&mut *msg);
            let out = hasher.finalize();
            let dur = start.elapsed();
            samples.push(dur);
            std::hint::black_box(&out);
        }
        stats_from_samples(&samples)
    }

    println!("Testing SHA-512 (Ed25519 classic):");
    let (min, max, avg, stddev) = bench::<Sha512>(n, &mut msg);
    println!(
        "  SHA-512: avg {:.2} ns/op, min {:?}, max {:?}, stddev {:.2} ns",
        avg, min, max, stddev
    );

    println!("Testing SHA-256 (common for Schnorr/BLS hash-to-curve):");
    let (min, max, avg, stddev) = bench::<Sha256>(n, &mut msg);
    println!(
        "  SHA-256: avg {:.2} ns/op, min {:?}, max {:?}, stddev {:.2} ns",
        avg, min, max, stddev
    );

    println!("Testing SHA3-256 (Keccak-family alternative):");
    let (min, max, avg, stddev) = bench::<Sha3_256>(n, &mut msg);
    println!(
        "  SHA3-256: avg {:.2} ns/op, min {:?}, max {:?}, stddev {:.2} ns",
        avg, min, max, stddev
    );

    println!("Testing Blake2b-512 (fast alternative):");
    let (min, max, avg, stddev) = bench::<Blake2b512>(n, &mut msg);
    println!(
        "  Blake2b-512: avg {:.2} ns/op, min {:?}, max {:?}, stddev {:.2} ns",
        avg, min, max, stddev
    );

    Ok(())
}
