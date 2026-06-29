// WTAS + comparison schemes — library crate
// ============================================
// Re-exports all protocol implementations for use by CLI, benchmarks, etc.

pub mod wtas;

#[cfg(feature = "virtual_frost")]
pub mod virtual_frost;

#[cfg(feature = "wts_das")]
pub mod wts_das;

#[cfg(feature = "taps")]
pub mod taps;

#[cfg(feature = "bls_baseline")]
pub mod bls_baseline;

#[cfg(feature = "schnorr")]
pub mod schnorr;

#[cfg(feature = "pr_taps")]
pub mod pr_taps;
