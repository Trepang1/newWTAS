// src/main.rs
use anyhow::Result;
use clap::Parser;
use rand::RngCore;
use std::time::{Duration, Instant};

#[derive(Parser)]
struct Cli {
    /// iterations per test
    #[arg(short, long, default_value_t = 10000)]
    n: usize,
}

fn stats(samples: &mut [Duration]) -> (Duration, Duration, f64) {
    samples.sort_unstable();
    let min = samples[0];
    let median = if samples.len() % 2 == 1 {
        samples[samples.len() / 2]
    } else {
        let hi = samples.len() / 2;
        let lo = hi - 1;
        let avg_ns = (samples[lo].as_nanos() + samples[hi].as_nanos()) as f64 / 2.0;
        Duration::from_nanos(avg_ns as u64)
    };
    let total_ns: f64 = samples.iter().map(|d| d.as_nanos() as f64).sum();
    let avg_ns = total_ns / (samples.len() as f64);
    (min, median, avg_ns)
}

fn fmt_ns(ns: f64) -> String {
    if ns >= 1e6 {
        format!("{:.3} ms", ns / 1e6)
    } else if ns >= 1e3 {
        format!("{:.3} µs", ns / 1e3)
    } else {
        format!("{:.0} ns", ns)
    }
}

fn bench_ed25519_only_mul(n: usize) -> Result<()> {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    println!("== Ed25519 pure fixed-base scalar mul ({} iters) ==", n);

    // 1) 预生成随机标量数组（不在计时段内）
    let mut rng = rand::thread_rng();
    let mut scalars_bytes: Vec<[u8; 32]> = Vec::with_capacity(n);
    for _ in 0..n {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        scalars_bytes.push(b);
    }
    let scalars: Vec<Scalar> =
        scalars_bytes.into_iter().map(|b| Scalar::from_bytes_mod_order(b)).collect();

    // 2) warmup
    for i in 0..200.min(n) {
        let _p = ED25519_BASEPOINT_TABLE * &scalars[i];
        std::hint::black_box(&_p);
    }

    // 3) timed loop (仅乘法)
    let mut samples = Vec::with_capacity(n);
    for i in 0..n {
        let s = &scalars[i];
        let start = Instant::now();
        let p = ED25519_BASEPOINT_TABLE * s;
        std::hint::black_box(&p);
        samples.push(start.elapsed());
    }

    let (min, median, avg_ns) = stats(&mut samples);
    println!("runs: {}", n);
    println!("  min    = {:?}", min);
    println!("  median = {:?}", median);
    println!("  avg    = {}", fmt_ns(avg_ns));
    println!();
    Ok(())
}

fn bench_bls_g1_lowlevel_only_mul(n: usize) -> Result<()> {
    println!("== BLS12-381 G1 blst_p1_mult pure mul ({} iters) ==", n);
    use blst::{blst_p1, blst_p1_generator, blst_p1_mult};

    let mut rng = rand::thread_rng();
    // pre-generate scalars
    let mut scalars: Vec<[u8; 32]> = Vec::with_capacity(n);
    for _ in 0..n {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        scalars.push(b);
    }

    // warmup
    unsafe {
        for i in 0..50.min(n) {
            let mut out: blst_p1 = std::mem::zeroed();
            let g = blst_p1_generator();
            blst_p1_mult(&mut out as *mut _, g, scalars[i].as_ptr(), 256);
            std::hint::black_box(&out);
        }
    }

    // timed loop
    let mut samples = Vec::with_capacity(n);
    unsafe {
        let g = blst_p1_generator();
        for i in 0..n {
            let start = Instant::now();
            let mut out: blst_p1 = std::mem::zeroed();
            blst_p1_mult(&mut out as *mut _, g, scalars[i].as_ptr(), 256);
            std::hint::black_box(&out);
            samples.push(start.elapsed());
        }
    }

    let (min, median, avg_ns) = stats(&mut samples);
    println!("runs: {}", n);
    println!("  min    = {:?}", min);
    println!("  median = {:?}", median);
    println!("  avg    = {}", fmt_ns(avg_ns));
    println!();
    Ok(())
}

/// Pure pairing benchmark: Miller loop + final exponentiation only (no hash-to-curve)
fn bench_bls_pairing_only(n: usize) -> Result<()> {
    println!("== BLS12-381 pure pairing (Miller loop + final exp) ({} iters) ==", n);

    use blst::min_pk::SecretKey;
    use blst::{blst_fp12, blst_miller_loop, blst_final_exp};

    let mut rng = rand::thread_rng();
    // generate one keypair and signature; we'll extract affine points and reuse them
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).map_err(|e| anyhow::anyhow!("blst key_gen err: {:?}", e))?;
    let pk = sk.sk_to_pk();
    let message = b"benchmark-message-for-pairing-only";
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let sig = sk.sign(message, dst, &[]);

    // --- CORRECTED: convert owned types into affine (use From impl on owned types) ---
    let p_affine: blst::blst_p1_affine = blst::blst_p1_affine::from(pk);
    let q_affine: blst::blst_p2_affine = blst::blst_p2_affine::from(sig);

    // warmup
    unsafe {
        let mut tmp_fp12: blst_fp12 = std::mem::zeroed();
        let mut out_fp12: blst_fp12 = std::mem::zeroed();
        for _ in 0..20 {
            blst_miller_loop(&mut tmp_fp12 as *mut _, &q_affine as *const _, &p_affine as *const _);
            blst_final_exp(&mut out_fp12 as *mut _, &tmp_fp12 as *const _);
            std::hint::black_box(&out_fp12);
        }
    }

    // timed loop
    let mut samples: Vec<Duration> = Vec::with_capacity(n);
    unsafe {
        let mut tmp_fp12: blst_fp12 = std::mem::zeroed();
        let mut out_fp12: blst_fp12 = std::mem::zeroed();
        for _ in 0..n {
            let start = Instant::now();
            blst_miller_loop(&mut tmp_fp12 as *mut _, &q_affine as *const _, &p_affine as *const _);
            blst_final_exp(&mut out_fp12 as *mut _, &tmp_fp12 as *const _);
            std::hint::black_box(&out_fp12);
            samples.push(start.elapsed());
        }
    }

    let (min, median, avg_ns) = stats(&mut samples);
    println!("runs: {}", n);
    println!("  min    = {:?}", min);
    println!("  median = {:?}", median);
    println!("  avg    = {}", fmt_ns(avg_ns));
    println!();
    Ok(())
}

/// Optional: full verify benchmark (hash-to-curve + pairing) — kept for cross-checking
fn bench_bls_verify(n: usize) -> Result<()> {
    println!("== BLS12-381 full signature verify (hash-to-curve + pairing) ({} iters) ==", n);
    use blst::min_pk::SecretKey;

    let mut rng = rand::thread_rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).map_err(|e| anyhow::anyhow!("blst key_gen err: {:?}", e))?;
    let pk = sk.sk_to_pk();
    let message = b"benchmark-message-for-verify";
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let sig = sk.sign(message, dst, &[]);

    // warmup
    for _ in 0..20 {
        let _ok = sig.verify(true, message, dst, &[], &pk, true);
        std::hint::black_box(&_ok);
    }

    let mut samples: Vec<Duration> = Vec::with_capacity(n);
    for _ in 0..n {
        let start = Instant::now();
        let ok = sig.verify(true, message, dst, &[], &pk, true);
        std::hint::black_box(&ok);
        samples.push(start.elapsed());
    }

    let (min, median, avg_ns) = stats(&mut samples);
    println!("runs: {}", n);
    println!("  min    = {:?}", min);
    println!("  median = {:?}", median);
    println!("  avg    = {}", fmt_ns(avg_ns));
    println!();
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    println!("Benchmark iterations = {}\n", cli.n);

    // Run benchmarks
    bench_ed25519_only_mul(cli.n)?;
    bench_bls_g1_lowlevel_only_mul(cli.n)?;
    bench_bls_pairing_only(cli.n)?;
    // Optional cross-check: full verify including hash-to-curve
    // bench_bls_verify(cli.n)?;

    Ok(())
}
