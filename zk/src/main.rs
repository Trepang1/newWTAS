// Demo binary for the WTAPS NIZK proof system.
// For library usage, see lib.rs.

use rand::rngs::OsRng;
use std::iter;
use zk::*;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};

fn main() {
    let mut rng = OsRng;
    let n = 8;
    let params = PublicParams::new(n, &mut rng);

    let b = vec![Scalar::ONE, Scalar::ZERO, Scalar::ONE, Scalar::ONE,
                 Scalar::ZERO, Scalar::ONE, Scalar::ZERO, Scalar::ONE];
    let w = vec![
        Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64), Scalar::from(4u64),
        Scalar::from(5u64), Scalar::from(6u64), Scalar::from(7u64), Scalar::from(8u64),
    ];

    let mut t = Scalar::ZERO;
    for i in 0..n { t += b[i] * w[i]; }

    let participant_keys: Vec<RistrettoPoint> = (0..n)
        .map(|_| RistrettoPoint::random(&mut rng)).collect();
    let mut k_agg = RistrettoPoint::identity();
    for i in 0..n {
        if b[i] == Scalar::ONE { k_agg += participant_keys[i]; }
    }

    let sk_enc = Scalar::random(&mut rng);
    let pk_enc = &params.G * sk_enc;
    let r_enc: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    let mut ciphertexts_v = Vec::new();
    for i in 0..n {
        ciphertexts_v.push(&pk_enc * r_enc[i] + &params.B * b[i]);
    }

    let rho_w = Scalar::random(&mut rng);
    let c_w = RistrettoPoint::multiscalar_mul(
        iter::once(&rho_w).chain(w.iter()),
        iter::once(&params.H).chain(params.h_vec.iter()),
    );

    let public = PublicInput {
        ciphertexts_v, k_agg, t, pk_enc, participant_keys,
        c_w, w_total: w.iter().sum(),
    };
    let secret = SecretWitness { b, w, r_enc, rho_w };

    println!("=== WTAPS NIZK Proof Demo (n={n}) ===");
    let proof = WTAPSProof::prove(&params, &public, &secret, &mut rng)
        .expect("Proof generation failed");
    println!("Proof generated: {} bytes", proof.proof_size_bytes());

    proof.verify_normal(&params, &public).expect("Normal verification failed");
    println!("[OK] Normal verification passed");

    proof.verify_fast(&params, &public).expect("Fast verification failed");
    println!("[OK] Fast verification passed");

    proof.verify_consistency(&params, &public).expect("Consistency check failed");
    println!("[OK] Consistency check passed");
}
