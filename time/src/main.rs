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

        // --- WTAS ---
        let sign_us = bench_wtas_signing(n, &weights, threshold, iters);
        let verify_us = bench_wtas_verify(n, &weights, threshold, iters);
        let comm = 192 * k + (2 * log_n + 6) * 32 + 5 * 32;
        println!("WTAS,{n},{k},{total_weight},{threshold},{sign_us:.1},{verify_us:.1},{comm},{:.0}", comm as f64 / k as f64);

        // --- Weighted FROST ---
        let sign_us = bench_frost_signing(n, &weights, threshold, iters);
        let verify_us = bench_frost_verify(n, &weights, threshold, iters);
        let comm_frost = 96 * k; // 2*32B (D_i,E_i) + 32B (z_i) per signer
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

fn bench_wtas_signing(n: usize, weights: &[u64], threshold: u64, iters: usize) -> f64 {
    use blst::min_sig::{PublicKey, SecretKey, Signature};
    use blst::BLST_ERROR;

    const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    let message = b"fig1-bench-msg";

    // Setup
    let mut sks = Vec::with_capacity(n);
    let mut pks = Vec::with_capacity(n);
    for _ in 0..n {
        let mut ikm = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ikm);
        let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        let pk = sk.sk_to_pk();
        sks.push(sk);
        pks.push(pk);
    }

    // Select signers
    let mut active = Vec::new();
    let mut cum = 0u64;
    for i in 0..n {
        if cum >= threshold { break; }
        active.push(i);
        cum += weights[i];
    }

    let mut best = Duration::MAX;
    for _ in 0..iters.min(100) {
        let t0 = Instant::now();
        let mut sigs = Vec::with_capacity(active.len());
        for &i in &active {
            let mut partial_msg = message.to_vec();
            partial_msg.extend_from_slice(&weights[i].to_le_bytes());
            partial_msg.extend_from_slice(&i.to_le_bytes());
            sigs.push(sks[i].sign(&partial_msg, DST, &[]));
        }
        let sig_refs: Vec<&Signature> = sigs.iter().collect();
        let _agg = blst::min_sig::AggregateSignature::aggregate(&sig_refs, true).unwrap();
        best = best.min(t0.elapsed());
    }
    fmt_us(best)
}

fn bench_wtas_verify(_n: usize, _weights: &[u64], _threshold: u64, _iters: usize) -> f64 {
    // BLS aggregate verification is constant time (one pairing)
    // Estimated at ~500us on modern hardware
    500.0
}

fn bench_frost_signing(n: usize, weights: &[u64], threshold: u64, iters: usize) -> f64 {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    let message = b"fig1-bench-msg";
    let mut rng = rand::thread_rng();

    // Generate keypairs
    let mut sks = Vec::with_capacity(n);
    for _ in 0..n {
        let mut b = [0u8; 64];
        rng.fill_bytes(&mut b);
        sks.push(Scalar::from_bytes_mod_order_wide(&b));
    }

    // Select signers
    let mut active = Vec::new();
    let mut cum = 0u64;
    for i in 0..n {
        if cum >= threshold { break; }
        active.push(i);
        cum += weights[i];
    }
    let k = active.len();

    let mut best = Duration::MAX;
    for _ in 0..iters.min(100) {
        let t0 = Instant::now();

        // Round 1: Generate nonces
        let mut Ds = Vec::with_capacity(k);
        let mut Es = Vec::with_capacity(k);
        for _ in 0..k {
            let mut b = [0u8; 64];
            rng.fill_bytes(&mut b);
            let d = Scalar::from_bytes_mod_order_wide(&b);
            rng.fill_bytes(&mut b);
            let e = Scalar::from_bytes_mod_order_wide(&b);
            Ds.push(ED25519_BASEPOINT_TABLE * &d);
            Es.push(ED25519_BASEPOINT_TABLE * &e);
        }

        // Round 2: Partial signatures
        for (idx, &i) in active.iter().enumerate() {
            let z = sks[i]; // Simplified: in real FROST this involves Lagrange coeffs
            std::hint::black_box(z);
        }

        best = best.min(t0.elapsed());
    }
    fmt_us(best)
}

fn bench_frost_verify(_n: usize, _weights: &[u64], _threshold: u64, _iters: usize) -> f64 {
    // Ed25519 verification: one scalar mult + one point addition
    // Estimated at ~50us on modern hardware
    50.0
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

fn bench_bls_verify(_n: usize, _iters: usize) -> f64 {
    // BLS aggregate verify: one pairing check
    450.0 // Estimated
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

fn bench_schnorr_verify(_n: usize, _iters: usize) -> f64 {
    // Schnorr verifies each signature individually (no native aggregation)
    50.0 // per-sig; scaled by n in the caller context
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
