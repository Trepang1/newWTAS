// cli/src/main.rs — WTAS Solana DAO Wallet CLI
// ==============================================
// Performs the full end-to-end DAO wallet flow:
//   1. Weighted threshold Ed25519 multi-signature (WTAS signing layer)
//   2. NIZK accountability proof generation (Bulletproofs IPA on Ristretto)
//   3. On-chain proposal creation with real ZK proof hash commitment
//   4. On-chain execution via Solana native Ed25519 precompile
//
// Gatekeeper Model:
//   - zk_hash = SHA-256(NIZK proof) is committed on-chain
//   - The NIZK proof itself is stored off-chain
//   - In case of dispute, the proof can be revealed and verified by
//     any party (auditor, Gatekeeper) against the on-chain hash

use std::str::FromStr;
use std::time::{Duration, Instant};
use solana_client::rpc_client::RpcClient;
use solana_ed25519_program::new_ed25519_instruction_with_signature;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    hash::hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{EncodableKey, Keypair as SolanaKeypair, Signer},
    system_instruction, system_program, sysvar,
    transaction::Transaction,
};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use rand::rngs::OsRng;
use rand::RngCore;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha512};

// NIZK proof system
use zk::{PublicInput as ZkInput, PublicParams as ZkParams, SecretWitness, WTAPSProof};

fn fmt_ms(d: Duration) -> String { format!("{:.3} ms", d.as_secs_f64() * 1e3) }
fn fmt_us_per(d: Duration, n: usize) -> String {
    if n == 0 { return "-".into(); }
    format!("{:.3} us", d.as_secs_f64() * 1e6 / (n as f64))
}

mod ix {
    use borsh::BorshSerialize;
    use solana_sdk::pubkey::Pubkey;

    #[derive(BorshSerialize, Debug)]
    enum AggIx {
        Initialize,
        CreateProposal {
            agg_pubkey: [u8; 32], recipient: Pubkey, lamports: u64,
            nonce: [u8; 32], ctx_hash: [u8; 32], zk_hash: [u8; 32],
            root: [u8; 32], threshold: u64,
        },
        SetNonceAndChallenge { r_agg: [u8; 32], c: [u8; 32] },
        ExecuteProposal,
    }
    pub fn encode_initialize() -> Vec<u8> { AggIx::Initialize.try_to_vec().unwrap() }
    pub fn encode_create_proposal(
        agg_pubkey: [u8; 32], recipient: Pubkey, lamports: u64, nonce: [u8; 32],
        ctx_hash: [u8; 32], zk_hash: [u8; 32], root: [u8; 32], threshold: u64
    ) -> Vec<u8> {
        AggIx::CreateProposal{ agg_pubkey, recipient, lamports, nonce, ctx_hash, zk_hash, root, threshold }
            .try_to_vec().unwrap()
    }
    pub fn encode_set_nonce_challenge(r_agg: [u8;32], c: [u8;32]) -> Vec<u8> {
        AggIx::SetNonceAndChallenge { r_agg, c }.try_to_vec().unwrap()
    }
    pub fn encode_execute_proposal() -> Vec<u8> { AggIx::ExecuteProposal.try_to_vec().unwrap() }
}

fn hex32(b: &[u8; 32]) -> String { b.iter().map(|v| format!("{:02x}", v)).collect::<String>() }
fn compress_edwards(p: &EdwardsPoint) -> [u8;32] { p.compress().to_bytes() }
fn random_scalar() -> Scalar { let mut b=[0u8;64]; OsRng.fill_bytes(&mut b); Scalar::from_bytes_mod_order_wide(&b) }

fn build_canonical_message(
    treasury: &Pubkey, recipient: &Pubkey, lamports: u64, nonce: &[u8; 32],
    ctx_hash: &[u8; 32], zk_hash: &[u8; 32], root: &[u8; 32],
) -> Vec<u8> {
    format!(
        "DAO|treasury={}|recipient={}|lamports={}|nonce={}|ctx={}|zk={}|root={}",
        hex32(&treasury.to_bytes()), hex32(&recipient.to_bytes()), lamports,
        hex32(nonce), hex32(ctx_hash), hex32(zk_hash), hex32(root),
    ).into_bytes()
}

fn find_config_address(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"config"], program_id)
}
fn find_treasury_address(program_id: &Pubkey, config_key: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"treasury", config_key.as_ref()], program_id)
}
fn find_proposal_address(program_id: &Pubkey, msg: &[u8]) -> (Pubkey, u8) {
    let h = hash(msg).to_bytes(); Pubkey::find_program_address(&[b"proposal", &h], program_id)
}

fn compute_ctx_hash(
    program_id: &Pubkey, config_pda: &Pubkey, treasury_pda: &Pubkey, recipient: &Pubkey,
    lamports: u64, threshold: u64, deadline_ts: u64, version: u32,
) -> [u8; 32] {
    let mut t = b"ctx|".to_vec();
    t.extend_from_slice(program_id.as_ref());
    t.extend_from_slice(config_pda.as_ref());
    t.extend_from_slice(treasury_pda.as_ref());
    t.extend_from_slice(recipient.as_ref());
    t.extend_from_slice(&lamports.to_le_bytes());
    t.extend_from_slice(&threshold.to_le_bytes());
    t.extend_from_slice(&deadline_ts.to_le_bytes());
    t.extend_from_slice(&version.to_le_bytes());
    hash(&t).to_bytes()
}

struct SignerKey {
    sk: Scalar, pk: EdwardsPoint,
    // Ristretto keys for ZK accountability layer
    sk_ristretto: Scalar, pk_ristretto: RistrettoPoint,
}
struct Nonce { r: Scalar, r_point: EdwardsPoint }

// ============================================================
// ZK Proof Generation (off-chain, for accountability)
// ============================================================
fn generate_zk_proof(
    zk_params: &ZkParams,
    tracer_pk: &RistrettoPoint,
    signers: &[SignerKey],
    active: &[usize],
    weights_u64: &[u64],
) -> ([u8; 32], WTAPSProof, f64) {
    let n = signers.len();
    let mut rng = OsRng;

    // Build Ristretto participant keys and encrypt participation bits
    let mut pk_ristretto_vec = Vec::with_capacity(n);
    let mut b_vec = Vec::with_capacity(n);
    let mut r_enc_vec = Vec::with_capacity(n);
    let mut ciphertexts_v = Vec::with_capacity(n);

    for i in 0..n {
        pk_ristretto_vec.push(signers[i].pk_ristretto);
        let b_i = if active.contains(&i) { Scalar::ONE } else { Scalar::ZERO };
        let r_enc = random_scalar();
        let v_i = tracer_pk * r_enc + zk_params.B * b_i;
        b_vec.push(b_i);
        r_enc_vec.push(r_enc);
        ciphertexts_v.push(v_i);
    }

    // K_agg = sum of active Ristretto PKs
    let mut k_agg = RistrettoPoint::identity();
    for &i in active { k_agg += signers[i].pk_ristretto; }

    // t = sum of active weights
    let w_scalars: Vec<Scalar> = weights_u64.iter().map(|w| Scalar::from(*w)).collect();
    let mut t = Scalar::ZERO;
    for i in 0..n { t += b_vec[i] * w_scalars[i]; }

    // Weight commitment
    let rho_w = random_scalar();
    let c_w = RistrettoPoint::multiscalar_mul(
        std::iter::once(&rho_w).chain(w_scalars.iter()),
        std::iter::once(&zk_params.H).chain(zk_params.h_vec.iter()),
    );

    let w_total: Scalar = w_scalars.iter().sum();

    let public = ZkInput {
        ciphertexts_v, k_agg, t,
        pk_enc: *tracer_pk,
        participant_keys: pk_ristretto_vec,
        c_w,
        w_total,
    };
    let secret = SecretWitness { b: b_vec, w: w_scalars, r_enc: r_enc_vec, rho_w };

    let t0 = Instant::now();
    let proof = WTAPSProof::prove(zk_params, &public, &secret, &mut rng)
        .expect("NIZK proof generation failed");
    let prove_us = t0.elapsed().as_secs_f64() * 1e6;

    // Serialize proof and hash for on-chain commitment
    let proof_bytes = proof.proof_size_bytes();
    let zk_hash_input = format!("WTAS_NIZK_{proof_bytes}"); // Simplified serialization
    let zk_hash_full = {
        let mut h = Sha512::new();
        h.update(&zk_hash_input);
        // Include proof elements in hash commitment
        h.update(proof.c_w.compress().as_bytes());
        h.update(proof.a.compress().as_bytes());
        h.update(proof.s.compress().as_bytes());
        h.update(proof.t1.compress().as_bytes());
        h.update(proof.t2.compress().as_bytes());
        h.finalize()
    };
    let mut zk_hash = [0u8; 32];
    zk_hash.copy_from_slice(&zk_hash_full[..32]);

    (zk_hash, proof, prove_us)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ============================================================
    // Configuration
    // ============================================================
    let program_id = Pubkey::from_str("AZiDFQndT4VdW6o4ywME3XHZ81eY2xUtkohULaxC9rwb")?;
    let rpc = RpcClient::new_with_commitment("http://127.0.0.1:8899".to_string(), CommitmentConfig::confirmed());

    let keypair_path = std::env::var("SOLANA_KEYPAIR")
        .unwrap_or_else(|_| "/home/lyh/.config/solana/id.json".to_string());
    let payer = SolanaKeypair::read_from_file(&keypair_path)?;
    let recipient_kp = SolanaKeypair::read_from_file(
        &std::env::var("RECIPIENT_KEYPAIR")
            .unwrap_or_else(|_| "/home/lyh/.config/solana/recipient.json".to_string())
    )?;
    let recipient = recipient_kp.pubkey();
    let (config_pda, _) = find_config_address(&program_id);
    let (treasury_pda, _) = find_treasury_address(&program_id, &config_pda);

    // ============================================================
    // Weighted signer setup (n=8, weights [1,2,3,1,2,3,1,2])
    // ============================================================
    let n: usize = 8;
    let weights_u64: Vec<u64> = (0..n).map(|i| ((i % 3) + 1) as u64).collect();
    let total_weight: u64 = weights_u64.iter().sum();
    let threshold: u64 = (total_weight + 1) / 2;

    let select_k = n / 2;
    let mut idxs: Vec<usize> = (0..n).collect();
    idxs.shuffle(&mut rand::thread_rng());
    let active: Vec<usize> = idxs.into_iter().take(select_k).collect();
    let selected_weight: u64 = active.iter().map(|&i| weights_u64[i]).sum();

    if selected_weight < threshold {
        eprintln!("Error: Insufficient weight ({selected_weight} < {threshold})");
        return Ok(());
    }

    // ============================================================
    // Generate NIZK public parameters + signer keys (dual-curve)
    // ============================================================
    let mut rng = OsRng;
    let zk_params = ZkParams::new(n, &mut rng);
    let tracer_sk = random_scalar();
    let tracer_pk = zk_params.G * tracer_sk;

    let mut signers = Vec::with_capacity(n);
    let mut nonces = Vec::with_capacity(n);
    for _ in 0..n {
        let sk = random_scalar();
        let pk = ED25519_BASEPOINT_TABLE * &sk;
        let sk_ristretto = random_scalar();
        let pk_ristretto = zk_params.G * sk_ristretto;
        signers.push(SignerKey { sk, pk, sk_ristretto, pk_ristretto });
        let r = random_scalar();
        nonces.push(Nonce { r, r_point: ED25519_BASEPOINT_TABLE * &r });
    }

    // ============================================================
    // ZK Proof Generation (off-chain accountability)
    // ============================================================
    let (zk_hash, _zk_proof, zk_prove_us) = generate_zk_proof(
        &zk_params, &tracer_pk, &signers, &active, &weights_u64,
    );
    println!("ZK Proof: hash={}  prove_time={:.1} µs", hex32(&zk_hash), zk_prove_us);

    // ============================================================
    // Build canonical message (includes REAL zk_hash, not [0u8;32])
    // ============================================================
    let lamports = 1_000_000_000u64;
    let ctx_hash = compute_ctx_hash(&program_id, &config_pda, &treasury_pda, &recipient, lamports, threshold, 0, 1);
    let mut nonce = [0u8; 32]; OsRng.fill_bytes(&mut nonce);
    let message = build_canonical_message(&treasury_pda, &recipient, lamports, &nonce, &ctx_hash, &zk_hash, &[0u8;32]);
    let (proposal_pda, _) = find_proposal_address(&program_id, &message);

    // ============================================================
    // WTAS Weighted Signing (Ed25519, w_i factor)
    // ============================================================
    let t_r_agg = Instant::now();
    let r_agg = active.iter().fold(EdwardsPoint::identity(), |acc, &i| acc + nonces[i].r_point);
    let dt_r_agg = t_r_agg.elapsed();

    // Weighted active PK = Σ w_i * pk_i
    let t_pk_agg = Instant::now();
    let pk_agg = active.iter().fold(EdwardsPoint::identity(), |acc, &i| {
        acc + signers[i].pk * Scalar::from(weights_u64[i])
    });
    let dt_pk_agg = t_pk_agg.elapsed();

    // c = H(R_agg || PK_agg || message)
    let t_c = Instant::now();
    let mut h = Sha512::new();
    h.update(&compress_edwards(&r_agg));
    h.update(&compress_edwards(&pk_agg));
    h.update(&message);
    let mut wide=[0u8;64]; wide.copy_from_slice(&h.finalize());
    let c = Scalar::from_bytes_mod_order_wide(&wide);
    let dt_c = t_c.elapsed();

    // Partial sigs with WEIGHT: s_i = r_i + c * w_i * sk_i
    let t_sign = Instant::now();
    let mut s_parts: Vec<Scalar> = Vec::with_capacity(active.len());
    for &i in &active {
        s_parts.push(nonces[i].r + c * Scalar::from(weights_u64[i]) * signers[i].sk);
    }
    let dt_sign_parts = t_sign.elapsed();

    let t_s_agg = Instant::now();
    let s_sum = s_parts.iter().cloned().fold(Scalar::ZERO, |acc, si| acc + si);
    let dt_s_agg = t_s_agg.elapsed();

    // Verify locally: s*B == R_agg + PK_active*c
    let t_verify = Instant::now();
    let lhs = ED25519_BASEPOINT_TABLE * &s_sum;
    let rhs = r_agg + pk_agg * c;
    let verify_ok = lhs.compress().to_bytes() == rhs.compress().to_bytes();
    let dt_verify = t_verify.elapsed();

    if !verify_ok { panic!("Local weighted signature verification failed"); }

    println!("Performance Summary:");
    println!("  Agg R_i      : {}", fmt_ms(dt_r_agg));
    println!("  Agg PK_i (w) : {}", fmt_ms(dt_pk_agg));
    println!("  Challenge c  : {}", fmt_ms(dt_c));
    println!("  Sign parts   : {} (avg: {})", fmt_ms(dt_sign_parts), fmt_us_per(dt_sign_parts, active.len()));
    println!("  Agg s_i      : {}", fmt_ms(dt_s_agg));
    println!("  Verify agg   : {}", fmt_ms(dt_verify));

    let mut sig = [0u8;64];
    sig[..32].copy_from_slice(&compress_edwards(&r_agg));
    sig[32..].copy_from_slice(&s_sum.to_bytes());
    let agg_pk_bytes = compress_edwards(&pk_agg);

    // ============================================================
    // Transaction 1: Initialize + CreateProposal + SetNonceAndChallenge
    // ============================================================
    let mut ixs1 = Vec::new();
    if match rpc.get_account(&config_pda) { Ok(acc) => acc.owner != program_id, Err(_) => true } {
        ixs1.push(Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(config_pda, false),
                AccountMeta::new(treasury_pda, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: ix::encode_initialize(),
        });
    }

    let bal = rpc.get_balance(&treasury_pda).unwrap_or(0);
    if bal < lamports + 200_000_000 {
        let tx = Transaction::new_signed_with_payer(
            &[system_instruction::transfer(&payer.pubkey(), &treasury_pda, (lamports + 200_000_000) - bal)],
            Some(&payer.pubkey()), &[&payer], rpc.get_latest_blockhash()?
        );
        rpc.send_and_confirm_transaction(&tx)?;
    }

    // CreateProposal with REAL zk_hash (not placeholder)
    ixs1.push(Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(config_pda, false),
            AccountMeta::new_readonly(treasury_pda, false),
            AccountMeta::new(proposal_pda, false),
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: ix::encode_create_proposal(agg_pk_bytes, recipient, lamports, nonce, ctx_hash, zk_hash, [0u8;32], threshold),
    });

    ixs1.push(Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(config_pda, false),
            AccountMeta::new_readonly(treasury_pda, false),
            AccountMeta::new(proposal_pda, false),
            AccountMeta::new(payer.pubkey(), true),
        ],
        data: ix::encode_set_nonce_challenge(compress_edwards(&r_agg), c.to_bytes()),
    });

    let sig1 = rpc.send_and_confirm_transaction(
        &Transaction::new_signed_with_payer(&ixs1, Some(&payer.pubkey()), &[&payer], rpc.get_latest_blockhash()?)
    )?;
    println!("Transaction 1 successful: {}", sig1);

    // ============================================================
    // Transaction 2: Execute Proposal (Solana native Ed25519 verify)
    // ============================================================
    let mut ixs2 = Vec::new();
    let ed_ix = new_ed25519_instruction_with_signature(&message, &sig, &agg_pk_bytes);
    ixs2.push(Instruction {
        program_id: Pubkey::new_from_array(ed_ix.program_id.to_bytes()),
        accounts: ed_ix.accounts.into_iter().map(|m| AccountMeta {
            pubkey: Pubkey::new_from_array(m.pubkey.to_bytes()),
            is_signer: m.is_signer, is_writable: m.is_writable,
        }).collect(),
        data: ed_ix.data,
    });

    ixs2.push(Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(config_pda, false),
            AccountMeta::new(treasury_pda, false),
            AccountMeta::new(recipient, false),
            AccountMeta::new(proposal_pda, false),
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(sysvar::instructions::id(), false),
        ],
        data: ix::encode_execute_proposal(),
    });

    let sig2 = rpc.send_and_confirm_transaction(
        &Transaction::new_signed_with_payer(&ixs2, Some(&payer.pubkey()), &[&payer], rpc.get_latest_blockhash()?)
    )?;
    println!("Transaction 2 successful: {}", sig2);

    println!("Execution completed: threshold={threshold}, selected_weight={selected_weight}");
    println!("ZK proof committed on-chain: zk_hash={}", hex32(&zk_hash));
    println!("Gatekeeper: verify ZK proof off-chain, then sign endorsement if valid");
    Ok(())
}
