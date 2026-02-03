// 仅在启用 pr_taps feature 时编译本文件
#![cfg(feature = "pr_taps")]

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::{Duration, Instant};

#[inline]
fn keygen() -> Keypair {
    // 手动生成 32 字节种子，避免 rand_core 版本不一致带来的 CryptoRng 约束
    let mut rng = OsRng;
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);

    let secret = SecretKey::from_bytes(&sk_bytes).expect("secret key");
    let public = PublicKey::from(&secret);
    Keypair { secret, public }
}

#[inline]
fn sign(kp: &Keypair, msg: &[u8]) -> Signature {
    kp.sign(msg)
}

#[inline]
fn verify(pk: &PublicKey, sig: &Signature, msg: &[u8]) -> bool {
    pk.verify(msg, sig).is_ok()
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

pub fn bench_ed25519(num_keys: usize, iters: usize) {
    println!("== pr_taps::Ed25519 bench  num_keys={num_keys}, iters={iters}");
    let message = b"bench-ed25519-msg-0123456789abcdef";

    // 1) Keygen
    let mut kps: Vec<Keypair> = Vec::with_capacity(num_keys);
    let mut best = Duration::MAX;
    for _ in 0..iters {
        kps.clear();
        let t0 = Instant::now();
        for _ in 0..num_keys {
            kps.push(keygen());
        }
        best = best.min(t0.elapsed());
    }
    fmt_rate("keygen", best, num_keys);

    // 2) Sign
    let mut sigs: Vec<Signature> = Vec::with_capacity(num_keys);
    let mut best = Duration::MAX;
    for _ in 0..iters {
        sigs.clear();
        let t0 = Instant::now();
        for kp in &kps {
            sigs.push(sign(kp, message));
        }
        best = best.min(t0.elapsed());
    }
    fmt_rate("sign", best, num_keys);

    // 3) Verify（逐个验证，不做批量）
    let mut best = Duration::MAX;
    for _ in 0..iters {
        let t0 = Instant::now();
        let mut ok = true;
        for (kp, sig) in kps.iter().zip(sigs.iter()) {
            if !verify(&kp.public, sig, message) {
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
}

/// 从 main.rs 调用的入口：`schemes pr_taps [num_keys] [iters]`
pub fn run(args: &[String]) {
    let n = args.get(0).and_then(|s| s.parse::<usize>().ok()).unwrap_or(1024);
    let iters = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(5);
    bench_ed25519(n, iters);
}
