// BLS Baseline — pairing-based threshold signatures
// ==================================================
// This is a COMPARISON BASELINE only, not our scheme.
// Our WTAS scheme is Ed25519-based (pairing-free) in wtas.rs.
//
// BLS provides: native signature aggregation + fast aggregate verification (1 pairing)
// BLS lacks:    pairing-free compatibility (needs BLS12-381 or similar curves)
//
// This baseline is used to show the performance trade-off:
//   BLS:  faster aggregate verify (1 pairing) but requires pairing-friendly curves
//   WTAS: slower per-signer verify but works on any Ed25519-compatible chain

use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::{Duration, Instant};

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

fn fmt_rate(op: &str, total: Duration, iters: usize) {
    let ns = (total.as_nanos() as f64) / (iters as f64);
    println!(
        "{op:<18} total = {:>9.3} ms   avg {:>9.1} ns  ({:>8.3} µs)",
        total.as_secs_f64() * 1e3, ns, ns / 1e3
    );
}

#[inline]
fn keygen() -> (SecretKey, PublicKey) {
    let mut ikm = [0u8; 32];
    OsRng.fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).expect("key_gen");
    let pk = sk.sk_to_pk();
    (sk, pk)
}

/// Run BLS baseline benchmarks: keygen, sign, aggregate, verify.
pub fn bench_bls(num_keys: usize, iters: usize) {
    println!("\n== BLS Baseline (pairing-based, min_pk) n={num_keys}, iters={iters} ==");
    let message = b"bench-msg-bls-0123456789abcdef";

    // Keygen
    let mut sks = Vec::with_capacity(num_keys);
    let mut pks = Vec::with_capacity(num_keys);
    let mut best = Duration::MAX;
    for _ in 0..iters {
        sks.clear(); pks.clear();
        let t0 = Instant::now();
        for _ in 0..num_keys {
            let (sk, pk) = keygen();
            sks.push(sk); pks.push(pk);
        }
        best = best.min(t0.elapsed());
    }
    fmt_rate("keygen", best, num_keys);

    // Sign
    let mut sigs = Vec::with_capacity(num_keys);
    let mut best = Duration::MAX;
    for _ in 0..iters {
        sigs.clear();
        let t0 = Instant::now();
        for sk in &sks { sigs.push(sk.sign(message, DST, &[])); }
        best = best.min(t0.elapsed());
    }
    fmt_rate("sign", best, num_keys);

    // Aggregate
    let mut best = Duration::MAX;
    for _ in 0..iters {
        let sig_refs: Vec<&Signature> = sigs.iter().collect();
        let t0 = Instant::now();
        let agg = AggregateSignature::aggregate(&sig_refs, true).expect("agg");
        best = best.min(t0.elapsed());
        std::hint::black_box(&agg);
    }
    fmt_rate("aggregate", best, num_keys);

    // Fast aggregate verify (1 pairing)
    let sig_refs: Vec<&Signature> = sigs.iter().collect();
    let agg_sig = AggregateSignature::aggregate(&sig_refs, true).expect("agg").to_signature();
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    let mut best = Duration::MAX;
    for _ in 0..iters {
        let t0 = Instant::now();
        let ok = agg_sig.fast_aggregate_verify(true, message, DST, &pk_refs) == BLST_ERROR::BLST_SUCCESS;
        best = best.min(t0.elapsed());
        std::hint::black_box(&ok);
    }
    fmt_rate("agg_verify (1 pair)", best, 1);

    // Communication: 1 aggregated signature = 96 bytes (G2 point)
    println!("{:<18} {:>9} bytes  (1 BLS sig on G2)", "comm_cost", 96);
}

pub fn run(args: &[String]) {
    let n = args.get(0).and_then(|s| s.parse::<usize>().ok()).unwrap_or(1024);
    let iters = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(5);
    bench_bls(n, iters);
}
