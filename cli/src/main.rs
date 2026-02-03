// cli/src/main.rs

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
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::rngs::OsRng;
use rand::RngCore;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha512};

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
            agg_pubkey: [u8; 32],
            recipient: Pubkey,
            lamports: u64,
            nonce: [u8; 32],
            ctx_hash: [u8; 32],
            zk_hash: [u8; 32],
            root: [u8; 32],
            threshold: u64,
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
fn compress_point(p: &EdwardsPoint) -> [u8;32] { p.compress().to_bytes() }
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

fn find_config_address(program_id: &Pubkey) -> (Pubkey, u8) { Pubkey::find_program_address(&[b"config"], program_id) }
fn find_treasury_address(program_id: &Pubkey, config_key: &Pubkey) -> (Pubkey, u8) { Pubkey::find_program_address(&[b"treasury", config_key.as_ref()], program_id) }
fn find_proposal_address(program_id: &Pubkey, msg: &[u8]) -> (Pubkey, u8) {
    let h = hash(msg).to_bytes(); Pubkey::find_program_address(&[b"proposal", &h], program_id)
}
const CONFIG_SIZE: usize = 1;

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

struct Keypair { sk: Scalar, pk: EdwardsPoint }
struct Nonce   { r: Scalar, r_point: EdwardsPoint }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let program_id = Pubkey::from_str("AZiDFQndT4VdW6o4ywME3XHZ81eY2xUtkohULaxC9rwb")?;
    let rpc = RpcClient::new_with_commitment("http://127.0.0.1:8899".to_string(), CommitmentConfig::confirmed());

    let payer = SolanaKeypair::read_from_file("/home/lyh/.config/solana/id.json")?;
    let recipient_kp = SolanaKeypair::read_from_file("/home/lyh/.config/solana/recipient.json")?;
    let recipient = recipient_kp.pubkey();

    let (config_pda, _) = find_config_address(&program_id);
    let (treasury_pda, _) = find_treasury_address(&program_id, &config_pda);

    let n: usize = 8;
    let mut weights_u64 = vec![0u64; n];
    for i in 0..n { weights_u64[i] = ((i%3)+1) as u64; }
    let total_weight: u64 = weights_u64.iter().sum();
    let t_threshold: u64 = (total_weight + 1) / 2;

    let select_k = n/2;
    let mut idxs: Vec<usize> = (0..n).collect();
    idxs.shuffle(&mut rand::thread_rng());
    let active: Vec<usize> = idxs.into_iter().take(select_k).collect();
    let selected_weight: u64 = active.iter().map(|&i| weights_u64[i]).sum();

    if selected_weight < t_threshold {
        eprintln!("Error: Insufficient weight ({selected_weight} < {t_threshold})");
        return Ok(());
    }

    let lamports = 1_000_000_000u64;
    let ctx_hash = compute_ctx_hash(&program_id, &config_pda, &treasury_pda, &recipient, lamports, t_threshold, 0, 1);

    let mut keypairs = Vec::with_capacity(n);
    let mut nonces = Vec::with_capacity(n);
    for _ in 0..n {
        let sk = random_scalar();
        keypairs.push(Keypair { sk, pk: G * sk });
        let r = random_scalar();
        nonces.push(Nonce { r, r_point: G * r });
    }

    let zk_hash = [0u8; 32];
    let mut nonce = [0u8; 32]; OsRng.fill_bytes(&mut nonce);
    let message = build_canonical_message(&treasury_pda, &recipient, lamports, &nonce, &ctx_hash, &zk_hash, &[0u8;32]);

    let (proposal_pda, _) = find_proposal_address(&program_id, &message);

    // Aggregation Logic
    let t_r_agg = Instant::now();
    let r_agg = active.iter().fold(EdwardsPoint::identity(), |acc, &i| acc + nonces[i].r_point);
    let dt_r_agg = t_r_agg.elapsed();

    let t_pk_agg = Instant::now();
    let pk_agg = active.iter().fold(EdwardsPoint::identity(), |acc, &i| acc + keypairs[i].pk);
    let dt_pk_agg = t_pk_agg.elapsed();

    // c = H(R_agg || PK_agg || message)
    let t_c = Instant::now();
    let mut h = Sha512::new();
    h.update(&compress_point(&r_agg));
    h.update(&compress_point(&pk_agg));
    h.update(&message);
    let mut wide=[0u8;64]; wide.copy_from_slice(&h.finalize());
    let c = Scalar::from_bytes_mod_order_wide(&wide);
    let dt_c = t_c.elapsed();

    let t_sign = Instant::now();
    let mut s_parts: Vec<Scalar> = Vec::with_capacity(active.len());
    for &i in &active {
        s_parts.push(nonces[i].r + c * keypairs[i].sk);
    }
    let dt_sign_parts = t_sign.elapsed();

    let t_s_agg = Instant::now();
    let s_sum = s_parts.iter().cloned().fold(Scalar::ZERO, |acc, si| acc + si);
    let dt_s_agg = t_s_agg.elapsed();

    // Verification Logic: G*s = R_agg + PK_agg*c
    let t_verify = Instant::now();
    let lhs = G * s_sum;
    let rhs = r_agg + pk_agg * c;
    let verify_ok = lhs.compress().to_bytes() == rhs.compress().to_bytes();
    let dt_verify = t_verify.elapsed();

    if !verify_ok { panic!("Local signature verification failed"); }

    println!("Performance Summary:");
    println!("  Agg R_i      : {}", fmt_ms(dt_r_agg));
    println!("  Agg PK_i     : {}", fmt_ms(dt_pk_agg));
    println!("  Challenge c  : {}", fmt_ms(dt_c));
    println!("  Sign parts   : {} (avg: {})", fmt_ms(dt_sign_parts), fmt_us_per(dt_sign_parts, active.len()));
    println!("  Agg s_i      : {}", fmt_ms(dt_s_agg));
    println!("  Verify agg   : {}", fmt_ms(dt_verify));

    let mut sig = [0u8;64];
    sig[..32].copy_from_slice(&compress_point(&r_agg));
    sig[32..].copy_from_slice(&s_sum.to_bytes());
    let agg_pk_bytes = compress_point(&pk_agg);

    // Tx1: Create Proposal
    let mut ixs1 = Vec::new();
    if match rpc.get_account(&config_pda) { Ok(acc) => acc.owner != program_id, Err(_) => true } {
        ixs1.push(Instruction {
            program_id,
            accounts: vec![AccountMeta::new(config_pda, false), AccountMeta::new(treasury_pda, false), AccountMeta::new(payer.pubkey(), true), AccountMeta::new_readonly(system_program::id(), false)],
            data: ix::encode_initialize(),
        });
    }

    let bal = rpc.get_balance(&treasury_pda).unwrap_or(0);
    if bal < lamports + 200_000_000 {
        let tx = Transaction::new_signed_with_payer(&[system_instruction::transfer(&payer.pubkey(), &treasury_pda, (lamports + 200_000_000) - bal)], Some(&payer.pubkey()), &[&payer], rpc.get_latest_blockhash()?);
        rpc.send_and_confirm_transaction(&tx)?;
    }

    ixs1.push(Instruction {
        program_id,
        accounts: vec![AccountMeta::new_readonly(config_pda, false), AccountMeta::new_readonly(treasury_pda, false), AccountMeta::new(proposal_pda, false), AccountMeta::new(payer.pubkey(), true), AccountMeta::new_readonly(system_program::id(), false)],
        data: ix::encode_create_proposal(agg_pk_bytes, recipient, lamports, nonce, ctx_hash, zk_hash, [0u8;32], t_threshold),
    });

    ixs1.push(Instruction {
        program_id,
        accounts: vec![AccountMeta::new_readonly(config_pda, false), AccountMeta::new_readonly(treasury_pda, false), AccountMeta::new(proposal_pda, false), AccountMeta::new(payer.pubkey(), true)],
        data: ix::encode_set_nonce_challenge(compress_point(&r_agg), c.to_bytes()),
    });

    let sig1 = rpc.send_and_confirm_transaction(&Transaction::new_signed_with_payer(&ixs1, Some(&payer.pubkey()), &[&payer], rpc.get_latest_blockhash()?))?;
    println!("Transaction 1 successful: {}", sig1);

    // Tx2: Execute Proposal
    let mut ixs2 = Vec::new();
    let ed_ix = new_ed25519_instruction_with_signature(&message, &sig, &agg_pk_bytes);
    ixs2.push(Instruction {
        program_id: Pubkey::new_from_array(ed_ix.program_id.to_bytes()),
        accounts: ed_ix.accounts.into_iter().map(|m| AccountMeta { pubkey: Pubkey::new_from_array(m.pubkey.to_bytes()), is_signer: m.is_signer, is_writable: m.is_writable }).collect(),
        data: ed_ix.data,
    });

    ixs2.push(Instruction {
        program_id,
        accounts: vec![AccountMeta::new_readonly(config_pda, false), AccountMeta::new(treasury_pda, false), AccountMeta::new(recipient, false), AccountMeta::new(proposal_pda, false), AccountMeta::new(payer.pubkey(), true), AccountMeta::new_readonly(system_program::id(), false), AccountMeta::new_readonly(sysvar::instructions::id(), false)],
        data: ix::encode_execute_proposal(),
    });

    let sig2 = rpc.send_and_confirm_transaction(&Transaction::new_signed_with_payer(&ixs2, Some(&payer.pubkey()), &[&payer], rpc.get_latest_blockhash()?))?;
    println!("Transaction 2 successful: {}", sig2);

    println!("Execution completed: threshold={t_threshold}, selected_weight={selected_weight}");
    Ok(())
}
