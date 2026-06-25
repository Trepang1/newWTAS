// Schemes: WTAS + comparison baselines
//
// Our scheme:
//   wtas          — WTAS: Ed25519-based weighted threshold accountable signatures (pairing-free)
//
// Comparison baselines:
//   virtual_frost — Weighted FROST (Ed25519, 2-round, no accountability)
//   bls_baseline  — BLS pairing-based aggregate signatures (fast verify, needs pairing curve)
//   schnorr       — Schnorr/BIP-340 (secp256k1, single-signer baseline)
//   pr_taps       — Ed25519 (single-signer baseline)

mod wtas;

#[cfg(feature = "virtual_frost")]
mod virtual_frost;

#[cfg(feature = "bls_baseline")]
mod bls_baseline;

#[cfg(feature = "schnorr")]
mod schnorr;

#[cfg(feature = "pr_taps")]
mod pr_taps;

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let _ = args.remove(0);
    if args.is_empty() {
        eprintln!("usage: schemes <wtas|virtual_frost|bls|schnorr|pr_taps> [N] [iters]");
        eprintln!();
        eprintln!("  Our scheme:");
        eprintln!("    wtas [N] [iters]       — WTAS full protocol benchmark (Ed25519, pairing-free)");
        eprintln!();
        eprintln!("  Comparison baselines:");
        eprintln!("    virtual_frost [N] [iters] — Weighted FROST (Ed25519, 2-round)");
        eprintln!("    bls [N] [iters]           — BLS pairing-based (fast agg verify)");
        eprintln!("    schnorr [N] [iters]       — Schnorr/BIP-340 (secp256k1)");
        eprintln!("    pr_taps [N] [iters]       — Ed25519 (single-signer)");
        return;
    }

    let cmd = args.remove(0);
    match cmd.as_str() {
        "wtas" => wtas::run(&args),

        #[cfg(feature = "virtual_frost")]
        "virtual_frost" => virtual_frost::run(&args),
        #[cfg(not(feature = "virtual_frost"))]
        "virtual_frost" => eprintln!("feature not enabled: virtual_frost"),

        #[cfg(feature = "bls_baseline")]
        "bls" => bls_baseline::run(&args),
        #[cfg(not(feature = "bls_baseline"))]
        "bls" => eprintln!("feature not enabled: bls_baseline"),

        #[cfg(feature = "schnorr")]
        "schnorr" => schnorr::run(&args),
        #[cfg(not(feature = "schnorr"))]
        "schnorr" => eprintln!("feature not enabled: schnorr"),

        #[cfg(feature = "pr_taps")]
        "pr_taps" => pr_taps::run(&args),
        #[cfg(not(feature = "pr_taps"))]
        "pr_taps" => eprintln!("feature not enabled: pr_taps"),

        other => eprintln!("unknown: {other}"),
    }
}
