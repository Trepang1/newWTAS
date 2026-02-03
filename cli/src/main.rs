// cli/src/main.rs

use std::str::FromStr;
use std::time::{Duration, Instant};
use std::ops::Neg;

use bs58;
use hex;
use rand::rngs::OsRng;
use rand::RngCore;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha512};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

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

fn fmt_ms(d: Duration) -> String { format!("{:.3} ms", d.as_secs_f64() * 1e3) }
fn fmt_us_per(d: Duration, n: usize) -> String {
    if n == 0 { return "-".into(); }
    format!("{:.3} µs", d.as_secs_f64() * 1e6 / (n as f64))
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
fn hex_bytes(v: &[u8]) -> String { v.iter().map(|x| format!("{:02x}", x)).collect::<String>() }
fn hex_point(p: &EdwardsPoint) -> String { hex::encode(p.compress().to_bytes()) }
fn hex_scalar(s: &Scalar) -> String { hex::encode(s.to_bytes()) }

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
    program_id: &Pubkey,
    config_pda: &Pubkey,
    treasury_pda: &Pubkey,
    recipient: &Pubkey,
    lamports: u64,
    threshold: u64,
    deadline_ts: u64,
    version: u32,
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
fn compress_point(p: &EdwardsPoint) -> [u8;32] { p.compress().to_bytes() }
fn random_scalar() -> Scalar { let mut b=[0u8;64]; OsRng.fill_bytes(&mut b); Scalar::from_bytes_mod_order_wide(&b) }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let program_id = Pubkey::from_str("AZiDFQndT4VdW6o4ywME3XHZ81eY2xUtkohULaxC9rwb")?;
    let rpc = RpcClient::new_with_commitment("http://127.0.0.1:8899".to_string(), CommitmentConfig::confirmed());

    let payer = SolanaKeypair::read_from_file("/home/lyh/.config/solana/id.json")?;
    let recipient_kp = SolanaKeypair::read_from_file("/home/lyh/.config/solana/recipient.json")?;
    let recipient = recipient_kp.pubkey();

    println!("payer: {}", payer.pubkey());
    println!("recipient: {}", recipient);

    let (config_pda, _cb) = find_config_address(&program_id);
    let (treasury_pda, _tb) = find_treasury_address(&program_id, &config_pda);
    println!("treasury PDA: {}", treasury_pda);

    //================= 参与者与权重（演示） =================
    let n: usize = 8;
    assert!(n.is_power_of_two());
    let mut weights_u64 = vec![0u64; n];
    for i in 0..n { weights_u64[i] = ((i%3)+1) as u64; } // 1/2/3 循环
    let total_weight: u64 = weights_u64.iter().sum();
    let t_threshold: u64 = (total_weight + 1) / 2; // ceil(total/2)

    // 随机选一半人
    let select_k = n/2;
    let mut idxs: Vec<usize> = (0..n).collect();
    idxs.shuffle(&mut rand::thread_rng());
    let active: Vec<usize> = idxs.into_iter().take(select_k).collect();
    let selected_weight: u64 = active.iter().map(|&i| weights_u64[i]).sum();

    println!("--- 阈值与抽样 ---");
    println!("权重向量 w_i = {:?}", weights_u64);
    println!("Σ w_i = {}, t = ceil(Σw_i / 2) = {}", total_weight, t_threshold);
    println!("随机选择的签名者索引 = {:?}, 其权重和 Σ_selected w_i = {}", active, selected_weight);
    if selected_weight < t_threshold {
        eprintln!("🛑 选中权重不足：selected_weight({selected_weight}) < t({t_threshold})，终止，不提交交易。");
        return Ok(());
    }

    //================= 业务参数 & 上下文哈希 =================
    let lamports = 1_000_000_000u64;
    let deadline_ts: u64 = 0;
    let version: u32 = 1;
    let threshold = t_threshold;

    let ctx_hash = compute_ctx_hash(&program_id, &config_pda, &treasury_pda, &recipient, lamports, threshold, deadline_ts, version);
    println!("--- 上下文哈希 ctx_hash 计算 ---");
    println!("ctx = H( \"ctx|\" || program_id || config_pda || treasury_pda || recipient || lamports || threshold || deadline_ts || version )");
    println!("ctx_hash(hex): {}", hex::encode(ctx_hash));

    //================= 本地生成 signer 密钥与临时随机数（演示） =================
    let mut keypairs = Vec::with_capacity(n);
    let mut nonces = Vec::with_capacity(n);
    for _ in 0..n {
        let sk = random_scalar(); let pk = G * sk;
        keypairs.push(Keypair { sk, pk });
        let r = random_scalar(); let r_point = G * r;
        nonces.push(Nonce { r, r_point });
    }

    //================= ZK 部分已移除 =================
    println!("--- ZK 证明已跳过 ---");
    // 使用全0替代真实的 ZK hash，仅用于占位以保证指令结构正确
    let zk_hash = [0u8; 32];
    println!("zk_hash(placeholder): {}", hex::encode(zk_hash));

    let merkle_root = [0u8; 32];

    //================= 生成提案消息（含 zk_hash 占位符） =================
    let mut nonce = [0u8; 32]; OsRng.fill_bytes(&mut nonce);
    let message = build_canonical_message(&treasury_pda, &recipient, lamports, &nonce, &ctx_hash, &zk_hash, &merkle_root);

    println!("--- 提案消息 ---");
    println!("message(hex): {}", hex::encode(&message));

    let (proposal_pda, _pb) = find_proposal_address(&program_id, &message);
    println!("proposal PDA: {}", proposal_pda);

    //================= 聚合签名（仅 active 子集） + 计时 =================
    println!("--- 聚合签名 ---");

    // R_agg 聚合计时
    let t0 = Instant::now();
    let r_agg = active.iter().fold(EdwardsPoint::identity(), |acc, &i| acc + nonces[i].r_point);
    let dt_r_agg = t0.elapsed();

    // PK_agg 聚合计时
    let t0 = Instant::now();
    let pk_agg = active.iter().fold(EdwardsPoint::identity(), |acc, &i| acc + keypairs[i].pk);
    let dt_pk_agg = t0.elapsed();

    println!("R_agg = Σ_i R_i  -> {}", hex_point(&r_agg));
    println!("PK_agg = Σ_i PK_i -> {}", hex_point(&pk_agg));

    // 挑战 c = H(R_agg || PK_agg || message) 计时（可选）
    let t0 = Instant::now();
    let mut h = Sha512::new();
    h.update(&compress_point(&r_agg));
    h.update(&compress_point(&pk_agg));
    h.update(&message);
    let digest = h.finalize();
    let mut wide=[0u8;64]; wide.copy_from_slice(&digest);
    let c = Scalar::from_bytes_mod_order_wide(&wide);
    let dt_c = t0.elapsed();

    println!("c = H(R_agg || PK_agg || message) = {}", hex_scalar(&c));

    // 每个签名者产生自己的份额 s_i（计时）
    let t0 = Instant::now();
    let mut s_parts: Vec<Scalar> = Vec::with_capacity(active.len());
    for &i in &active {
        s_parts.push(nonces[i].r + c * keypairs[i].sk);
    }
    let dt_sign_parts = t0.elapsed();

    // 聚合 s_i -> s_sum（计时）
    let t0 = Instant::now();
    let s_sum = s_parts.iter().cloned().fold(Scalar::ZERO, |acc, si| acc + si);
    let dt_s_agg = t0.elapsed();

    println!("s = Σ_i (r_i + c*sk_i) = {}", hex_scalar(&s_sum));

    let mut sig = [0u8;64];
    sig[..32].copy_from_slice(&compress_point(&r_agg));
    sig[32..].copy_from_slice(&s_sum.to_bytes());
    let agg_pk_bytes: [u8;32] = compress_point(&pk_agg);

    println!("agg pk(hex)  : {}", hex::encode(agg_pk_bytes));
    println!("agg pk(bs58) : {}", bs58::encode(agg_pk_bytes).into_string());
    println!("agg sig(hex) : {}", hex::encode(sig));
    println!("sig.R(hex)   : {}", hex_bytes(&sig[0..32]));
    println!("sig.S(hex)   : {}", hex_bytes(&sig[32..64]));

    // ===== 在链上操作前：本地验证聚合签名（替代链上验签时间测试） =====
    let t0 = Instant::now();
    // 验证公式： G*s ?= R_agg + PK_agg*c
    let lhs = G * s_sum;
    let rhs = r_agg + pk_agg * c;
    let verify_ok = lhs.compress().to_bytes() == rhs.compress().to_bytes();
    let dt_verify = t0.elapsed();

    println!("--- 本地聚合签名验证（链上验签替身） ---");
    println!("lhs = G*s       = {}", hex_point(&lhs));
    println!("rhs = R + c*PK  = {}", hex_point(&rhs));
    println!("verify result   = {}", verify_ok);

    // ===== 汇总计时 =====
    println!("--- 性能计时（本地） ---");
    println!("Agg R      (Σ R_i)      : {}", fmt_ms(dt_r_agg));
    println!("Agg PK     (Σ PK_i)     : {}", fmt_ms(dt_pk_agg));
    println!("Challenge c (H(...))    : {}", fmt_ms(dt_c));
    println!("Sign parts  (all s_i)   : {}   (per-signer ≈ {})", fmt_ms(dt_sign_parts), fmt_us_per(dt_sign_parts, active.len()));
    println!("Agg S      (Σ s_i)      : {}", fmt_ms(dt_s_agg));
    println!("Verify agg (G*s ?= R+cPK): {}", fmt_ms(dt_verify));

    //================= 指令序列（拆成两笔交易） =================

    // ---------- Tx1: Initialize(可选) + CreateProposal + SetNonceAndChallenge ----------
    let mut ixs1: Vec<Instruction> = Vec::new();

    // Initialize（如需）
    let need_init = match rpc.get_account(&config_pda) {
        Ok(acc) => acc.owner != program_id || acc.data.len() != CONFIG_SIZE || acc.lamports == 0,
        Err(_)  => true,
    };
    if need_init {
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
        println!("Tx1 将包含 Initialize 指令");
    }

    // 充钱（本地，单独发起，以免撑大 Tx2）
    let lamports = 1_000_000_000u64;
    let need = lamports + 200_000_000;
    let bal = rpc.get_balance(&treasury_pda).unwrap_or(0);
    if bal < need {
        let top = system_instruction::transfer(&payer.pubkey(), &treasury_pda, need - bal);
        let bh = rpc.get_latest_blockhash()?; 
        let tx = Transaction::new_signed_with_payer(&[top], Some(&payer.pubkey()), &[&payer], bh);
        rpc.send_and_confirm_transaction(&tx)?; 
        println!("treasury topped up.");
    }

    // CreateProposal（使用新的 placeholder zk_hash）
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
    println!("CreateProposal: 写入 agg_pk, recipient, lamports, nonce, ctx_hash, zk_hash, root, threshold");

    // SetNonceAndChallenge（把 R 和 c 写到提案里）
    ixs1.push(Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(config_pda, false),
            AccountMeta::new_readonly(treasury_pda, false),
            AccountMeta::new(proposal_pda, false),
            AccountMeta::new(payer.pubkey(), true),
        ],
        data: ix::encode_set_nonce_challenge(compress_point(&r_agg), c.to_bytes()),
    });
    println!("SetNonceAndChallenge: r_agg={}, c={}", hex_point(&r_agg), hex_scalar(&c));

    // 发送 Tx1
    {
        use solana_client::rpc_config::RpcSimulateTransactionConfig;
        let mut sim = RpcSimulateTransactionConfig::default();
        sim.sig_verify = false; 
        sim.replace_recent_blockhash = true;
        sim.commitment = Some(CommitmentConfig::processed());
        let bh = rpc.get_latest_blockhash()?; 
        let tx1 = Transaction::new_signed_with_payer(&ixs1, Some(&payer.pubkey()), &[&payer], bh);
        println!("Tx1 指令数 = {}", ixs1.len());

        let res1 = rpc.simulate_transaction_with_config(&tx1, sim.clone())?;
        if let Some(err)=res1.value.err {
            eprintln!("simulate(Tx1) err: {:?}", err);
            if let Some(logs)=res1.value.logs { for l in logs { eprintln!("  {l}"); } }
            return Ok(());
        } else { println!("simulate(Tx1) ok, CU={:?}", res1.value.units_consumed); }

        let sig1 = rpc.send_and_confirm_transaction(&tx1)?;
        println!("sent Tx1: {sig1}");
    }

    // ---------- Tx2: ed25519 + ExecuteProposal ----------
    let mut ixs2: Vec<Instruction> = Vec::new();

    // ed25519（验证 (R,S,PK_agg) 对 message 的签名）
    let ed_ix_prog = new_ed25519_instruction_with_signature(&message, &sig, &agg_pk_bytes);
    println!("ed25519 ix data len = {} bytes", ed_ix_prog.data.len());
    ixs2.push(Instruction {
        program_id: Pubkey::new_from_array(ed_ix_prog.program_id.to_bytes()),
        accounts: ed_ix_prog.accounts.into_iter().map(|m| AccountMeta{
            pubkey: Pubkey::new_from_array(m.pubkey.to_bytes()),
            is_signer: m.is_signer, is_writable: m.is_writable
        }).collect(),
        data: ed_ix_prog.data,
    });

    // ExecuteProposal（程序在此强校验 pubkey/R/message 三元一致）
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
    println!("Tx2 指令数 = {}", ixs2.len());

    // 发送 Tx2
    {
        use solana_client::rpc_config::RpcSimulateTransactionConfig;
        let mut sim = RpcSimulateTransactionConfig::default();
        sim.sig_verify = false; 
        sim.replace_recent_blockhash = true;
        sim.commitment = Some(CommitmentConfig::processed());
        let bh = rpc.get_latest_blockhash()?; 
        let tx2 = Transaction::new_signed_with_payer(&ixs2, Some(&payer.pubkey()), &[&payer], bh);

        let res2 = rpc.simulate_transaction_with_config(&tx2, sim)?;
        if let Some(err)=res2.value.err {
            eprintln!("simulate(Tx2) err: {:?}", err);
            if let Some(logs)=res2.value.logs { for l in logs { eprintln!("  {l}"); } }
            return Ok(());
        } else { println!("simulate(Tx2) ok, CU={:?}", res2.value.units_consumed); }
        let sig2 = rpc.send_and_confirm_transaction(&tx2)?;
        println!("sent Tx2: {sig2}");
    }

    let bal_t = rpc.get_balance(&treasury_pda).unwrap_or(0);
    let bal_r = rpc.get_balance(&recipient).unwrap_or(0);
    println!("✅ 转账完成：selected_weight={selected_weight}, threshold t={t_threshold}");
    println!("treasury balance: {bal_t}");
    println!("recipient balance: {bal_r}");
    Ok(())
}