// Schemes: WTAS + comparison baselines
//
// Our scheme:
//   wtas          — WTAS: Ed25519 weighted threshold accountable signatures + Bulletproofs NIZK
//
// Comparison baselines:
//   virtual_frost — V-FROST: Ed25519 weighted threshold via virtualization (O(Σw))
//   wts_das       — WTS (Das et al. 2023): BLS12-381 weighted threshold + pairing verify
//   taps          — TAPS (Boneh-Komlo 2022): Ed25519 equal-weight threshold + Sigma NIZK
//
// Legacy baselines:
//   bls_baseline  — BLS aggregate signatures (pairing baseline)
//   schnorr       — Schnorr/BIP-340 single-signer (legacy)
//   pr_taps       — Ed25519 single-signer (legacy)

mod wtas;

#[cfg(feature = "virtual_frost")]
mod virtual_frost;

#[cfg(feature = "wts_das")]
mod wts_das;

#[cfg(feature = "taps")]
mod taps;

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
        eprintln!("usage: schemes <wtas|virtual_frost|wts_das|taps|bls|schnorr|pr_taps> [N] [iters]");
        eprintln!();
        eprintln!("  Our scheme:");
        eprintln!("    wtas [N] [iters]          — WTAS full protocol (Ed25519 + NIZK + ElGamal)");
        eprintln!();
        eprintln!("  Comparison baselines (Fig 1):");
        eprintln!("    virtual_frost [N] [iters]  — V-FROST (Ed25519, virtualization O(Σw))");
        eprintln!("    wts_das [N] [iters]        — WTS Das et al. (BLS12-381, pairing verify)");
        eprintln!("    taps [N] [iters]           — TAPS Boneh-Komlo (Ed25519, Sigma NIZK)");
        eprintln!();
        eprintln!("  Legacy baselines:");
        eprintln!("    bls [N] [iters]            — BLS aggregate sigs (pairing baseline)");
        eprintln!("    schnorr [N] [iters]        — Schnorr/BIP-340 single-signer (legacy)");
        eprintln!("    pr_taps [N] [iters]        — Ed25519 single-signer (legacy)");
        return;
    }

    let cmd = args.remove(0);
    match cmd.as_str() {
        "wtas" => wtas::run(&args),

        #[cfg(feature = "virtual_frost")]
        "virtual_frost" => virtual_frost::run(&args),
        #[cfg(not(feature = "virtual_frost"))]
        "virtual_frost" => eprintln!("feature not enabled: virtual_frost"),

        #[cfg(feature = "wts_das")]
        "wts_das" => wts_das::run(&args),
        #[cfg(not(feature = "wts_das"))]
        "wts_das" => eprintln!("feature not enabled: wts_das"),

        #[cfg(feature = "taps")]
        "taps" => taps::run(&args),
        #[cfg(not(feature = "taps"))]
        "taps" => eprintln!("feature not enabled: taps"),

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
