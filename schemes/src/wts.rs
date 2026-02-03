use blst::min_sig::{AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use rand::RngCore;
use std::time::{Duration, Instant};

/// IETF BLS (min-sig, G1) 的标准 DST
const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

#[inline]
fn keygen() -> (SecretKey, PublicKey) {
    // IKM: 32 字节系统熵
    let mut ikm = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).expect("key_gen");
    let pk = sk.sk_to_pk();
    (sk, pk)
}

#[inline]
fn sign(sk: &SecretKey, msg: &[u8]) -> Signature {
    // blst 内部完成 hash_to_curve + 标准签名流程
    sk.sign(msg, DST, &[])
}

#[inline]
fn verify(pk: &PublicKey, sig: &Signature, msg: &[u8]) -> bool {
    // verify(hash_or_encode, msg, dst, augmentation, pk, pk_validate)
    sig.verify(true, msg, DST, &[], pk, true) == BLST_ERROR::BLST_SUCCESS
}

#[inline]
fn fast_aggregate_verify(pks: &[PublicKey], agg_sig: &Signature, msg: &[u8]) -> bool {
    // 需要 &[&PublicKey]
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    agg_sig.fast_aggregate_verify(true, msg, DST, &pk_refs) == BLST_ERROR::BLST_SUCCESS
}

#[inline]
fn aggregate_sigs(sigs: &[Signature]) -> Signature {
    // 关联函数：aggregate(&[&Signature], validate) -> Result<AggregateSignature, _>
    let sig_refs: Vec<&Signature> = sigs.iter().collect();
    let agg = AggregateSignature::aggregate(&sig_refs, true).expect("aggregate");
    agg.to_signature()
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

/// 在 WTS 模块中跑 BLS（min-sig）基准
pub fn bench_bls(num_keys: usize, iters: usize) {
    println!(
        "== WTS::BLS bench (blst, min-sig)  num_keys={num_keys}, iters={iters}"
    );
    let message = b"bench-msg-0123456789abcdef-0123456789abcdef";

    // 1) Keygen
    let mut sks = Vec::with_capacity(num_keys);
    let mut pks = Vec::with_capacity(num_keys);
    let mut best = Duration::MAX;
    for _ in 0..iters {
        sks.clear();
        pks.clear();
        let t0 = Instant::now();
        for _ in 0..num_keys {
            let (sk, pk) = keygen();
            sks.push(sk);
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
        for sk in &sks {
            sigs.push(sign(sk, message));
        }
        best = best.min(t0.elapsed());
    }
    fmt_rate("sign", best, num_keys);

    // 3) Verify
    let mut best = Duration::MAX;
    for _ in 0..iters {
        let t0 = Instant::now();
        let mut ok = true;
        for (pk, sig) in pks.iter().zip(sigs.iter()) {
            if !verify(pk, sig, message) {
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

    // 4) 同消息聚合验签
    let agg_sig = aggregate_sigs(&sigs);
    let mut best = Duration::MAX;
    for _ in 0..iters {
        let t0 = Instant::now();
        let ok = fast_aggregate_verify(&pks, &agg_sig, message);
        assert!(ok, "fast aggregate verify failed");
        best = best.min(t0.elapsed());
    }
    fmt_rate("agg_verify", best, 1);
}

/// 从 main.rs 调用的入口：`schemes wts [num_keys] [iters]`
pub fn run(args: &[String]) {
    let n = args
        .get(0)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1024);
    let iters = args
        .get(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(5);
    bench_bls(n, iters);
}
