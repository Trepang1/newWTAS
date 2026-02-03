use secp256k1::{
    schnorr::Signature, Keypair, Message, Secp256k1, XOnlyPublicKey,
};
use secp256k1::rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};


#[inline]
fn fmt_rate(op: &str, total: Duration, iters_div: usize) {
    let ns_per = (total.as_nanos() as f64) / (iters_div as f64);
    println!(
        "{op:<12} total = {:>9.3} ms   per-op ≈ {:>9.1} ns  ({:>8.3} µs)",
        total.as_secs_f64() * 1e3,
        ns_per,
        ns_per / 1e3
    );
}

#[inline]
fn digest32(msg: &[u8]) -> Message {
    let d = Sha256::digest(msg);
    // BIP-340 要求 32 字节消息，这里使用 SHA-256 预哈希
    Message::from_digest_slice(&d).expect("32-byte digest")
}

#[inline]
fn keygen(secp: &Secp256k1<secp256k1::All>) -> (Keypair, XOnlyPublicKey) {
    let kp = Keypair::new(secp, &mut OsRng);
    let (xonly, _parity) = XOnlyPublicKey::from_keypair(&kp);
    (kp, xonly)
}

#[inline]
fn sign(secp: &Secp256k1<secp256k1::All>, kp: &Keypair, msg: &[u8]) -> Signature {
    let m = digest32(msg);
    secp.sign_schnorr(&m, kp)
}

#[inline]
fn verify(secp: &Secp256k1<secp256k1::All>, pk: &XOnlyPublicKey, sig: &Signature, msg: &[u8]) -> bool {
    let m = digest32(msg);
    secp.verify_schnorr(sig, &m, pk).is_ok()
}

/// 在 WTS 模块旁跑 Schnorr（BIP-340）基准
pub fn bench_schnorr(num_keys: usize, iters: usize) {
    println!("== Schnorr bench (secp256k1, BIP-340)  num_keys={num_keys}, iters={iters}");
    let secp = Secp256k1::new();
    let message = b"bench-msg-0123456789abcdef-0123456789abcdef";

    // 1) Keygen
    let mut kps = Vec::with_capacity(num_keys);
    let mut pks = Vec::with_capacity(num_keys);
    let mut best = Duration::MAX;
    for _ in 0..iters {
        kps.clear();
        pks.clear();
        let t0 = Instant::now();
        for _ in 0..num_keys {
            let (kp, pk) = keygen(&secp);
            kps.push(kp);
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
        for kp in &kps {
            sigs.push(sign(&secp, kp, message));
        }
        best = best.min(t0.elapsed());
    }
    fmt_rate("sign", best, num_keys);

    // 3) Verify
    let mut best = Duration::MAX;
    for _ in 0..iters {
        let t0 = Instant::now();
        let mut ok = true;
        for ((pk, sig), _i) in pks.iter().zip(sigs.iter()).zip(0..) {
            if !verify(&secp, pk, sig, message) {
                ok = false;
                break;
            }
        }
        let dt = t0.elapsed();
        if ok { best = best.min(dt); }
    }
    fmt_rate("verify", best, num_keys);

    // 注：Schnorr 原生没有像 BLS 一样“同消息聚合验签 = 一次双线性配对”的快捷路径；
    // 若需要，可另行实现“批量验证（随机线性组合）”作为一项对比，这里先保持与单签验证一致的三项指标。
}

/// 从 main.rs 调用的入口：`schemes schnorr [num_keys] [iters]`
pub fn run(args: &[String]) {
    let n     = args.get(0).and_then(|s| s.parse::<usize>().ok()).unwrap_or(1024);
    let iters = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(5);
    bench_schnorr(n, iters);
}
