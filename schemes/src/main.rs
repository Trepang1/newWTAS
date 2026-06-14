mod wts;

#[cfg(feature = "schnorr")]
mod schnorr;

#[cfg(feature = "pr_taps")]
mod pr_taps;

#[cfg(feature = "virtual_frost")]
mod virtual_frost;

fn main() {
    let mut args = std::env::args().collect::<Vec<_>>();
    let _ = args.remove(0); // binary name
    if args.is_empty() {
        eprintln!("usage: schemes <wts|schnorr|pr_taps|virtual_frost> [num] [iters]");
        eprintln!("  wts              - BLS baseline benchmarks");
        eprintln!("  wts full [N] [iters] - Full WTAS protocol benchmark (Fig 1)");
        eprintln!("  schnorr          - Schnorr/BIP-340 benchmarks");
        eprintln!("  pr_taps          - Ed25519 benchmarks");
        eprintln!("  virtual_frost    - Weighted FROST benchmarks (Fig 1 comparison)");
        return;
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "wts" => wts::run(&args),
        #[cfg(feature = "schnorr")]
        "schnorr" => schnorr::run(&args),
        #[cfg(not(feature = "schnorr"))]
        "schnorr" => eprintln!("unknown cmd or feature not enabled: schnorr"),

        #[cfg(feature = "pr_taps")]
        "pr_taps" => pr_taps::run(&args),
        #[cfg(not(feature = "pr_taps"))]
        "pr_taps" => eprintln!("unknown cmd or feature not enabled: pr_taps"),

        #[cfg(feature = "virtual_frost")]
        "virtual_frost" => virtual_frost::run(&args),
        #[cfg(not(feature = "virtual_frost"))]
        "virtual_frost" => eprintln!("unknown cmd or feature not enabled: virtual_frost"),

        other => eprintln!("unknown cmd or feature not enabled: {other}"),
    }
}
