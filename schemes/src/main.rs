mod wts;

#[cfg(feature = "schnorr")]
mod schnorr;

#[cfg(feature = "pr_taps")]
mod pr_taps;

fn main() {
    let mut args = std::env::args().collect::<Vec<_>>();
    let _ = args.remove(0); // binary name
    if args.is_empty() {
        eprintln!("usage: schemes <wts|schnorr|pr_taps> [num] [iters]");
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

        other => eprintln!("unknown cmd or feature not enabled: {other}"),
    }
}
