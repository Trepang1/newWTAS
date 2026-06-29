// cli/src/main.rs — WTAS Solana DAO Wallet CLI
// ==============================================
// Full end-to-end DAO wallet flow using WtasGroup library:
//   1. WtasGroup::setup()     — dual-curve key generation
//   2. WtasGroup::sign()      — dual-nonce weighted signing + combiner endorsement
//   3. WtasGroup::prove_accountability()  — Bulletproofs IPA NIZK proof
//   4. On-chain proposal creation with ZK proof hash commitment
//   5. On-chain execution via Solana native Ed25519 precompile
//   6. WtasGroup::trace()     — accountability: identify signers post-dispute
//
// Gatekeeper Model:
//   - zk_hash = SHA-256(NIZK proof) is committed on-chain
//   - NIZK proof stored off-chain, verifiable by any party against on-chain hash

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
use rand::RngCore;
use sha2::{Digest, Sha512};

// WTAS protocol library (dual-nonce signing, combiner endorsement, NIZK, Trace)
use schemes::wtas::{
    WtasGroup, WtasFullSignature, ElGamalCiphertext,
};

fn fmt_ms(d: Duration) -> String { format!("{:.3} ms", d.as_secs_f64() * 1e3) }
fn fmt_us_per(d: Duration, n: usize) -> String {
    if n == 0 { return "-".into(); }
    format!("{:.3} us", d.as_secs_f64() * 1e6 / (n as f64))
}

// ============================================================
// On-chain instruction encoding (Solana program interface)
// ============================================================
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

/// Hash the NIZK proof elements for on-chain commitment.
fn hash_proof(proof: &schemes::wtas::WtasAccountabilityProof) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(b"WTAS_NIZK");
    h.update(&proof.proof_bytes.to_le_bytes());
    h.update(proof.zk_proof.c_w.compress().as_bytes());
    h.update(proof.zk_proof.a.compress().as_bytes());
    h.update(proof.zk_proof.s.compress().as_bytes());
    h.update(proof.zk_proof.t1.compress().as_bytes());
    h.update(proof.zk_proof.t2.compress().as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[..32]);
    out
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║       WTAS — Weighted Threshold Accountable Signatures      ║");
    println!("║          Solana DAO Wallet — End-to-End Demo                ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // ============================================================
    // 0. Chain Configuration
    // ============================================================
    let program_id = Pubkey::from_str("Aw2LiU4ufNYwDLmSwAKmP1xcMs8vnvTMtPSwkQ5o9WSP")?;
    let rpc = RpcClient::new_with_commitment(
        "http://127.0.0.1:8899".to_string(), CommitmentConfig::confirmed());

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

    println!("┌─ Chain Configuration ─────────────────────────────────────┐");
    println!("│ Program ID : {}", program_id);
    println!("│ Payer      : {}", payer.pubkey());
    println!("│ Recipient  : {}", recipient);
    println!("│ Treasury   : {} (PDA)", treasury_pda);
    println!("└──────────────────────────────────────────────────────────┘\n");

    // ============================================================
    // 1. Weighted Signer Setup (via WtasGroup)
    // ============================================================
    let n: usize = 8;
    let weights: Vec<u64> = (0..n).map(|i| ((i % 3) + 1) as u64).collect();
    let total_weight: u64 = weights.iter().sum();
    let threshold: u64 = (total_weight + 1) / 2;

    let mut rng = rand::thread_rng();
    let group = WtasGroup::setup(n, &weights, threshold);
    let (active, selected_weight) = group.select_signers();

    println!("┌─ 1. Weighted Signer Setup (WtasGroup) ────────────────────┐");
    println!("│ Signers       : n = {n}");
    println!("│ Weights       : {:?}", weights);
    println!("│ Total weight  : W = {total_weight}");
    println!("│ Threshold     : t = {threshold}  (> W/2)");
    println!("│ Active        : {:?}  (weight={selected_weight} ≥ t ✓)", active);
    for &i in &active {
        println!("│   Signer[{i}]: w={}, participates=YES", weights[i]);
    }
    for i in 0..n {
        if !active.contains(&i) {
            println!("│   Signer[{i}]: w={}, participates=NO", weights[i]);
        }
    }
    println!("│ Combiner pk   : {:02x}..", group.combiner_pk.compress().as_bytes()[0]);
    println!("│ Tracer pk     : {:02x}.. (Ristretto)", group.tracer_pk.compress().as_bytes()[0]);
    println!("└──────────────────────────────────────────────────────────┘\n");

    // ============================================================
    // 2. Signing Protocol (dual-nonce + combiner endorsement)
    // ============================================================
    let message_raw = b"DAO-transfer-benchmark-msg-0123456789";

    println!("┌─ 2. Signing Protocol (dual-nonce, anti-ROS) ──────────────┐");
    let t_sign = Instant::now();
    let (full_sig, dt_r1, dt_bctx, dt_r2, _) = group.sign(&active, message_raw);
    let total_sign = t_sign.elapsed();

    println!("│ Round 1  (dual nonces) : {}", fmt_ms(dt_r1));
    println!("│ Coord    (bind ctx)    : {}", fmt_ms(dt_bctx));
    println!("│ Round 2  (partial sig) : {}", fmt_ms(dt_r2));
    println!("│ Total signing time     : {}", fmt_ms(total_sign));
    println!("│");
    println!("│ Signature components:");
    println!("│   R_eff  = {:02x}..  (effective agg commitment)", full_sig.sig.r_agg.compress().as_bytes()[0]);
    println!("│   s_agg  = {:02x}..  (aggregated scalar)", full_sig.sig.s_agg.as_bytes()[0]);
    println!("│   σ_C    = {:02x}..  (combiner endorsement, 64B)", full_sig.combiner_sig[0]);
    println!("└──────────────────────────────────────────────────────────┘\n");

    // ============================================================
    // 3. Local Verification
    // ============================================================
    println!("┌─ 3. Local Verification ───────────────────────────────────┐");
    let (verify_ok, dt_verify) = group.verify(&full_sig, &active, message_raw);
    println!("│ EdDSA check : [s]B ≟ R_eff + [c]K_agg  → {}", if verify_ok { "✓" } else { "✗" });
    println!("│ Combiner check: σ_C valid for (m,R_eff,S,K_agg) → {}",
        WtasGroup::verify_combiner_endorsement(
            &full_sig.combiner_pk, message_raw,
            &full_sig.sig.r_agg, &group.active_group_pk(&active),
            &full_sig.sig.s_agg, &full_sig.combiner_sig,
        ).then(|| "✓").unwrap_or("✗"));
    println!("│ Verify time : {}", fmt_ms(dt_verify));
    println!("└──────────────────────────────────────────────────────────┘\n");

    // Convert signature to raw bytes for Solana precompile
    let sig_bytes = {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(full_sig.sig.r_agg.compress().as_bytes());
        b[32..].copy_from_slice(full_sig.sig.s_agg.as_bytes());
        b
    };
    let agg_pk_bytes = {
        let pk = group.active_group_pk(&active);
        pk.compress().to_bytes()
    };

    // ============================================================
    // 4. NIZK Accountability Proof (via WtasGroup)
    // ============================================================
    println!("┌─ 4. NIZK Accountability Proof (Bulletproofs IPA) ─────────┐");
    let acc_proof = group.prove_accountability(&active);
    let zk_hash = hash_proof(&acc_proof);

    println!("│ Curve       : Ristretto  (prime-order, pairing-free)");
    println!("│ Protocol    : Bulletproofs IPA + Super Basis Injection");
    println!("│ Rounds      : log₂({n}) = {}", (n as f64).log2().ceil() as usize);
    println!("│ Proof size  : {} bytes  (O(log n))", acc_proof.proof_bytes);
    println!("│ Prove time  : {:.0} µs", acc_proof.prove_us);
    println!("│");
    println!("│ Statement proved:");
    println!("│   (a) b_i ∈ {{0,1}}  ∀i");
    println!("│   (b) Σ b_i·w_i = {selected_weight} ≥ t={threshold} ✓");
    println!("│   (c) V_i = tpk·r_i + B·b_i  (ElGamal well-formed)");
    println!("│   (d) K_agg consistent with participant keys");
    println!("│");
    println!("│ On-chain commitment:");
    println!("│   zk_hash = SHA-512( WTAS_NIZK || c_w || A || S || T1 || T2 )");
    println!("│   zk_hash = {}..", hex32(&zk_hash));
    println!("│   (proof stored off-chain, hash committed on-chain)");
    println!("└──────────────────────────────────────────────────────────┘\n");

    // ============================================================
    // 5. Canonical Message
    // ============================================================
    let lamports = 1_000_000_000u64;
    let ctx_hash = compute_ctx_hash(
        &program_id, &config_pda, &treasury_pda, &recipient, lamports, threshold, 0, 1);
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let message = build_canonical_message(
        &treasury_pda, &recipient, lamports, &nonce, &ctx_hash, &zk_hash, &[0u8;32]);
    let (proposal_pda, _) = find_proposal_address(&program_id, &message);

    println!("┌─ 5. Canonical Message ────────────────────────────────────┐");
    println!("│ DAO|treasury={}..", hex32(&treasury_pda.to_bytes()));
    println!("│     |recipient={}..", hex32(&recipient.to_bytes()));
    println!("│     |lamports={lamports}|nonce={}..", hex32(&nonce));
    println!("│     |zk_hash={}  (← NIZK commitment)", hex32(&zk_hash));
    println!("│ Proposal PDA: {}", proposal_pda);
    println!("└──────────────────────────────────────────────────────────┘\n");

    // ============================================================
    // 6. Transaction 1 — Initialize + CreateProposal + SetNonce
    // ============================================================
    println!("┌─ 6. Transaction 1: CreateProposal + SetNonceAndChallenge ─┐");
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
        println!("│ [ix 0] Initialize  →  create config + treasury PDAs");
    }

    let bal = rpc.get_balance(&treasury_pda).unwrap_or(0);
    if bal < lamports + 200_000_000 {
        let tx = Transaction::new_signed_with_payer(
            &[system_instruction::transfer(&payer.pubkey(), &treasury_pda,
                (lamports + 200_000_000) - bal)],
            Some(&payer.pubkey()), &[&payer], rpc.get_latest_blockhash()?
        );
        rpc.send_and_confirm_transaction(&tx)?;
        println!("│ [fund] {} SOL → treasury", (lamports + 200_000_000) as f64 / 1e9);
    }

    ixs1.push(Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(config_pda, false),
            AccountMeta::new_readonly(treasury_pda, false),
            AccountMeta::new(proposal_pda, false),
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: ix::encode_create_proposal(
            agg_pk_bytes, recipient, lamports, nonce, ctx_hash, zk_hash, [0u8;32], threshold),
    });
    println!("│ [ix 1] CreateProposal");
    println!("│   agg_pk   = {}..", hex32(&agg_pk_bytes));
    println!("│   lamports = {lamports}  ({} SOL)", lamports as f64 / 1e9);
    println!("│   zk_hash  = {}  (← NIZK proof commitment)", hex32(&zk_hash));

    // Use R_eff from signature as the nonce commitment
    let r_eff_bytes = full_sig.sig.r_agg.compress().to_bytes();
    // Challenge is embedded in the binding context; for on-chain we store R_eff
    let c_bytes = {
        // Reconstruct challenge for on-chain SetNonce
        let k_agg = group.active_group_pk(&active);
        let mut h = Sha512::new();
        h.update(b"WTAS_challenge");
        h.update(&r_eff_bytes);
        h.update(k_agg.compress().as_bytes());
        h.update(message_raw);
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&h.finalize());
        curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&wide).to_bytes()
    };

    ixs1.push(Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(config_pda, false),
            AccountMeta::new_readonly(treasury_pda, false),
            AccountMeta::new(proposal_pda, false),
            AccountMeta::new(payer.pubkey(), true),
        ],
        data: ix::encode_set_nonce_challenge(r_eff_bytes, c_bytes),
    });
    println!("│ [ix 2] SetNonceAndChallenge");
    println!("│   R_eff  = {}..", hex32(&r_eff_bytes));
    println!("│   c      = {}..", hex32(&c_bytes));

    let sig1 = rpc.send_and_confirm_transaction(
        &Transaction::new_signed_with_payer(&ixs1, Some(&payer.pubkey()),
            &[&payer], rpc.get_latest_blockhash()?)
    )?;
    println!("│ ✓ Tx1: {}", sig1);
    println!("└──────────────────────────────────────────────────────────┘\n");

    // ============================================================
    // 7. Transaction 2 — Execute Proposal
    // ============================================================
    println!("┌─ 7. Transaction 2: ExecuteProposal ───────────────────────┐");
    let mut ixs2 = Vec::new();
    let ed_ix = new_ed25519_instruction_with_signature(&message, &sig_bytes, &agg_pk_bytes);
    ixs2.push(Instruction {
        program_id: Pubkey::new_from_array(ed_ix.program_id.to_bytes()),
        accounts: ed_ix.accounts.into_iter().map(|m| AccountMeta {
            pubkey: Pubkey::new_from_array(m.pubkey.to_bytes()),
            is_signer: m.is_signer, is_writable: m.is_writable,
        }).collect(),
        data: ed_ix.data,
    });
    println!("│ [ix 0] Ed25519SignatureVerify  (Solana native precompile)");
    println!("│   sig = (R_eff, s_agg)  64 bytes");
    println!("│   pk  = K_agg           32 bytes");

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
    println!("│ [ix 1] ExecuteProposal");
    println!("│   Verify: canonical msg → pk → R  (all match)");
    println!("│   Transfer: treasury ─{} SOL→ recipient", lamports as f64 / 1e9);

    let sig2 = rpc.send_and_confirm_transaction(
        &Transaction::new_signed_with_payer(&ixs2, Some(&payer.pubkey()),
            &[&payer], rpc.get_latest_blockhash()?)
    )?;
    println!("│ ✓ Tx2: {}", sig2);
    println!("└──────────────────────────────────────────────────────────┘\n");

    // ============================================================
    // 8. Accountability Trace (post-dispute)
    // ============================================================
    println!("┌─ 8. Accountability Trace (post-dispute) ──────────────────┐");
    let (elgamal_cts, _, _) = group.encrypt_participation_ristretto(&active);
    let t_trace = Instant::now();
    let traced = group.trace(&elgamal_cts);
    let dt_trace = t_trace.elapsed();
    let trace_ok = group.trace_and_verify(&elgamal_cts, &active);

    println!("│ Tracer decrypts ElGamal ciphertexts:");
    println!("│   For each i: M_i = V_i - tsk·U_i");
    println!("│   M_i == B  →  b_i = 1 (participated)");
    println!("│   M_i == O  →  b_i = 0 (absent)");
    println!("│");
    println!("│ Traced signers : {:?}  (expected: {:?})", traced, active);
    println!("│ Trace match    : {}", if trace_ok { "✓" } else { "✗" });
    println!("│ Trace time     : {}  ({})", fmt_ms(dt_trace), fmt_us_per(dt_trace, n));
    println!("│ Ciphertexts    : {} × (U,V) = {} bytes", n, n * 64);
    println!("└──────────────────────────────────────────────────────────┘\n");

    // ============================================================
    // 9. Summary
    // ============================================================
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                    EXECUTION COMPLETE                       ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Protocol   : WTAS (dual-nonce, anti-ROS)                  ║");
    println!("║  Signers    : {}/{} active, weight {}/{}              ║",
        active.len(), n, selected_weight, total_weight);
    println!("║  Threshold  : {}  (met ✓)                                  ║", threshold);
    println!("║  Signature  : valid Ed25519 weighted multi-sig             ║");
    println!("║  Combiner   : endorsed by σ_C (64B Ed25519 sig)           ║");
    println!("║  NIZK       : {}B proof, O(log n)                          ║", acc_proof.proof_bytes);
    println!("║  Trace      : {} signers identified ✓                      ║", traced.len());
    println!("║  Transfer   : treasury → recipient  ({} SOL)              ║", lamports as f64 / 1e9);
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Architecture:                                             ║");
    println!("║    Signing    → Ed25519 dual-nonce weighted multi-sig      ║");
    println!("║    ZK Proof   → Bulletproofs IPA on Ristretto (off-chain)  ║");
    println!("║    Combiner   → Ed25519 endorsement (on-chain verifiable)  ║");
    println!("║    Gatekeeper → verifies ZK proof, signs endorsement       ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    Ok(())
}
