use borsh::{BorshDeserialize, BorshSerialize};
use borsh_derive::{BorshDeserialize as DeriveBorshDeserialize, BorshSerialize as DeriveBorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    ed25519_program,
    entrypoint, entrypoint::ProgramResult,
    hash::hash,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction, system_program,
    sysvar::{self, Sysvar},
};

solana_program::declare_id!("AZiDFQndT4VdW6o4ywME3XHZ81eY2xUtkohULaxC9rwb");

#[derive(DeriveBorshSerialize, DeriveBorshDeserialize, Debug)]
pub enum AggIx {
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
    
    SetNonceAndChallenge {
        r_agg: [u8; 32],
        c: [u8; 32],
    },
    ExecuteProposal,
}

pub mod ix {
    use super::AggIx;
    use borsh::BorshSerialize;
    use solana_program::pubkey::Pubkey;

    pub fn encode_initialize() -> Vec<u8> { AggIx::Initialize.try_to_vec().unwrap() }
    pub fn encode_create_proposal(
        agg_pubkey: [u8; 32],
        recipient: Pubkey,
        lamports: u64,
        nonce: [u8; 32],
        ctx_hash: [u8; 32],
        zk_hash: [u8; 32],
        root: [u8; 32],
        threshold: u64,
    ) -> Vec<u8> {
        AggIx::CreateProposal {
            agg_pubkey, recipient, lamports, nonce, ctx_hash, zk_hash, root, threshold
        }.try_to_vec().unwrap()
    }
    pub fn encode_set_nonce_and_challenge(r_agg: [u8;32], c: [u8;32]) -> Vec<u8> {
        AggIx::SetNonceAndChallenge { r_agg, c }.try_to_vec().unwrap()
    }
    pub fn encode_execute_proposal() -> Vec<u8> {
        AggIx::ExecuteProposal.try_to_vec().unwrap()
    }
}

#[derive(DeriveBorshSerialize, DeriveBorshDeserialize, Debug, Clone, Default)]
pub struct Config { pub treasury_bump: u8 }
impl Config { pub const SIZE: usize = 1; }

#[derive(DeriveBorshSerialize, DeriveBorshDeserialize, Debug, Clone)]
pub struct Proposal {
    pub agg_pubkey: [u8; 32],
    pub recipient: Pubkey,
    pub lamports: u64,
    pub nonce: [u8; 32],
    pub consumed: u8,
    pub ctx_hash: [u8; 32],
    pub zk_hash: [u8; 32],
    pub root: [u8; 32],
    pub threshold: u64,
    
    pub r_agg: [u8; 32],
    pub c: [u8; 32],
}
// 32+32+8+32+1+32+32+32+8+32+32 = 273
impl Proposal { pub const SIZE: usize = 273; }

fn hex32(b: &[u8; 32]) -> String { b.iter().map(|v| format!("{:02x}", v)).collect::<String>() }
fn build_canonical_message(
    treasury: &Pubkey,
    recipient: &Pubkey,
    lamports: u64,
    nonce: &[u8; 32],
    ctx_hash: &[u8; 32],
    zk_hash: &[u8; 32],
    root: &[u8; 32],
) -> Vec<u8> {
    format!(
        "DAO|treasury={}|recipient={}|lamports={}|nonce={}|ctx={}|zk={}|root={}",
        hex32(&treasury.to_bytes()),
        hex32(&recipient.to_bytes()),
        lamports,
        hex32(nonce),
        hex32(ctx_hash),
        hex32(zk_hash),
        hex32(root),
    ).into_bytes()
}

entrypoint!(process_instruction);
pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], ix_data: &[u8]) -> ProgramResult {
    let ix = AggIx::try_from_slice(ix_data).map_err(|_| ProgramError::InvalidInstructionData)?;
    match ix {
        AggIx::Initialize => initialize(program_id, accounts),
        AggIx::CreateProposal { agg_pubkey, recipient, lamports, nonce, ctx_hash, zk_hash, root, threshold } =>
            create_proposal(program_id, accounts, agg_pubkey, recipient, lamports, nonce, ctx_hash, zk_hash, root, threshold),
        AggIx::SetNonceAndChallenge { r_agg, c } =>
            set_nonce_and_challenge(program_id, accounts, r_agg, c),
        AggIx::ExecuteProposal => execute_proposal(program_id, accounts),
    }
}

fn initialize(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let acc_iter = &mut accounts.iter();
    let config_ai   = next_account_info(acc_iter)?; // 0
    let treasury_ai = next_account_info(acc_iter)?; // 1
    let payer_ai    = next_account_info(acc_iter)?; // 2
    let system_ai   = next_account_info(acc_iter)?; // 3

    let (config_key, config_bump) = Pubkey::find_program_address(&[b"config"], program_id);
    let (treasury_key, treasury_bump) = Pubkey::find_program_address(&[b"treasury", config_key.as_ref()], program_id);
    if &config_key != config_ai.key || &treasury_key != treasury_ai.key {
        msg!("PDA mismatch"); return Err(ProgramError::InvalidSeeds);
    }

    if config_ai.data_is_empty() {
        let rent = Rent::get()?; let lamports = rent.minimum_balance(Config::SIZE);
        let create = system_instruction::create_account(payer_ai.key, config_ai.key, lamports, Config::SIZE as u64, program_id);
        invoke_signed(&create, &[payer_ai.clone(), config_ai.clone(), system_ai.clone()], &[&[b"config", &[config_bump]]])?;
    }
    Config{treasury_bump}.serialize(&mut &mut config_ai.data.borrow_mut()[..])?;

    if treasury_ai.lamports() == 0 {
        let rent = Rent::get()?; let lamports = rent.minimum_balance(0);
        let create = system_instruction::create_account(payer_ai.key, treasury_ai.key, lamports, 0, &system_program::id());
        invoke_signed(&create, &[payer_ai.clone(), treasury_ai.clone(), system_ai.clone()], &[&[b"treasury", config_key.as_ref(), &[treasury_bump]]])?;
    }
    msg!("initialize ok. cfg={}, treasury={}", config_key, treasury_key);
    Ok(())
}

fn create_proposal(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    agg_pubkey: [u8; 32],
    recipient: Pubkey,
    lamports: u64,
    nonce: [u8; 32],
    ctx_hash: [u8; 32],
    zk_hash: [u8; 32],
    root: [u8; 32],
    threshold: u64,
) -> ProgramResult {
    let acc_iter = &mut accounts.iter();
    let config_ai   = next_account_info(acc_iter)?; // 0
    let treasury_ai = next_account_info(acc_iter)?; // 1
    let proposal_ai = next_account_info(acc_iter)?; // 2
    let payer_ai    = next_account_info(acc_iter)?; // 3
    let system_ai   = next_account_info(acc_iter)?; // 4

    let (config_key, _cb) = Pubkey::find_program_address(&[b"config"], program_id);
    if &config_key != config_ai.key { return Err(ProgramError::InvalidSeeds); }
    let (treasury_key, _tb) = Pubkey::find_program_address(&[b"treasury", config_key.as_ref()], program_id);
    if &treasury_key != treasury_ai.key { return Err(ProgramError::InvalidSeeds); }

    let msg_bytes = build_canonical_message(&treasury_key, &recipient, lamports, &nonce, &ctx_hash, &zk_hash, &root);
    let h = hash(&msg_bytes).to_bytes();
    let (expected_proposal, bump) = Pubkey::find_program_address(&[b"proposal", &h], program_id);
    if &expected_proposal != proposal_ai.key { msg!("proposal PDA mismatch"); return Err(ProgramError::InvalidSeeds); }

    if proposal_ai.data_is_empty() {
        let rent = Rent::get()?; let lamports_min = rent.minimum_balance(Proposal::SIZE);
        let create = system_instruction::create_account(payer_ai.key, proposal_ai.key, lamports_min, Proposal::SIZE as u64, program_id);
        invoke_signed(&create, &[payer_ai.clone(), proposal_ai.clone(), system_ai.clone()], &[&[b"proposal", &h, &[bump]]])?;
    }

    Proposal{
        agg_pubkey, recipient, lamports, nonce, consumed:0, ctx_hash, zk_hash, root, threshold,
        r_agg:[0u8;32], c:[0u8;32],
    }.serialize(&mut &mut proposal_ai.data.borrow_mut()[..])?;

    msg!("create_proposal ok {}", expected_proposal);
    Ok(())
}

fn set_nonce_and_challenge(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    r_agg: [u8; 32],
    c: [u8; 32],
) -> ProgramResult {
    let acc_iter = &mut accounts.iter();
    let config_ai   = next_account_info(acc_iter)?; // 0
    let treasury_ai = next_account_info(acc_iter)?; // 1
    let proposal_ai = next_account_info(acc_iter)?; // 2
    let payer_ai    = next_account_info(acc_iter)?; // 3

    if !payer_ai.is_signer { return Err(ProgramError::MissingRequiredSignature); }

    let (config_key, _cb) = Pubkey::find_program_address(&[b"config"], program_id);
    if &config_key != config_ai.key { return Err(ProgramError::InvalidSeeds); }
    let (treasury_key, _tb) = Pubkey::find_program_address(&[b"treasury", config_key.as_ref()], program_id);
    if &treasury_key != treasury_ai.key { return Err(ProgramError::InvalidSeeds); }
    if proposal_ai.owner != program_id { return Err(ProgramError::IncorrectProgramId); }

    let mut p: Proposal = Proposal::try_from_slice(&proposal_ai.data.borrow()[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if p.consumed != 0 { return Err(ProgramError::InvalidInstructionData); }

    p.r_agg = r_agg;
    p.c = c;
    p.serialize(&mut &mut proposal_ai.data.borrow_mut()[..])?;
    msg!("set_nonce_and_challenge ok");
    Ok(())
}

fn extract_pk_R_msg_with_expected<'a>(d: &'a [u8], expected_pk: &[u8; 32]) -> Result<([u8; 32], [u8;32], &'a [u8]), ProgramError> {
    
    if d.len() >= 1 + 3 + 14 && d[0] == 1 {
        let sig_off = u16::from_le_bytes([d[4], d[5]]) as usize;
        let sig_ix  = u16::from_le_bytes([d[6], d[7]]);
        let pk_off  = u16::from_le_bytes([d[8], d[9]]) as usize;
        let pk_ix   = u16::from_le_bytes([d[10], d[11]]);
        let msg_off = u16::from_le_bytes([d[12], d[13]]) as usize;
        let msg_len = u16::from_le_bytes([d[14], d[15]]) as usize;
        let msg_ix  = u16::from_le_bytes([d[16], d[17]]);
        let bounds_ok = sig_off + 64 <= d.len() && pk_off + 32 <= d.len() && msg_off + msg_len <= d.len();
        if sig_ix == 0xFFFF && pk_ix == 0xFFFF && msg_ix == 0xFFFF && bounds_ok {
            let mut pk = [0u8; 32]; pk.copy_from_slice(&d[pk_off..pk_off+32]);
            let mut R  = [0u8; 32]; R.copy_from_slice(&d[sig_off..sig_off+32]); // 签名前 32B 即 R
            let msg_bytes = &d[msg_off..msg_off+msg_len];
            return Ok((pk, R, msg_bytes));
        }
    }
   
    let mut msg_off_opt=None;
    for i in 0..d.len().saturating_sub(4) { if &d[i..i+4]==b"DAO|" { msg_off_opt=Some(i); break; } }
    let msg_off = msg_off_opt.ok_or(ProgramError::InvalidInstructionData)?;
    let msg_bytes=&d[msg_off..];

    
    if msg_off>=96 {
        let mut pk=[0u8;32]; pk.copy_from_slice(&d[msg_off-32..msg_off]);
        if &pk==expected_pk {
            let mut R=[0u8;32]; R.copy_from_slice(&d[msg_off-64..msg_off-32]);
            msg!("ed25519 parse = fallback-A");
            return Ok((pk,R,msg_bytes));
        }
    }
    if msg_off>=96 {
        let mut pk=[0u8;32]; pk.copy_from_slice(&d[msg_off-96..msg_off-64]);
        if &pk==expected_pk {
            let mut R=[0u8;32]; R.copy_from_slice(&d[msg_off-64..msg_off-32]);
            msg!("ed25519 parse = fallback-B");
            return Ok((pk,R,msg_bytes));
        }
    }
    msg!("ed25519 fallback failed: neither pattern matches expected agg_pubkey");
    Err(ProgramError::InvalidInstructionData)
}

fn execute_proposal(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let acc_iter = &mut accounts.iter();
    let config_ai    = next_account_info(acc_iter)?; // 0
    let treasury_ai  = next_account_info(acc_iter)?; // 1
    let recipient_ai = next_account_info(acc_iter)?; // 2
    let proposal_ai  = next_account_info(acc_iter)?; // 3
    let _payer_ai    = next_account_info(acc_iter)?; // 4
    let system_ai    = next_account_info(acc_iter)?; // 5
    let ix_sysvar_ai = next_account_info(acc_iter)?; // 6

    if config_ai.owner != program_id { msg!("bad config owner"); return Err(ProgramError::IncorrectProgramId); }
    let cfg_bytes = config_ai.data.borrow().to_vec();
    let cfg = Config::try_from_slice(&cfg_bytes).map_err(|_|{ msg!("config deserialize failed: len={}", cfg_bytes.len()); ProgramError::InvalidAccountData })?;

    if proposal_ai.owner != program_id { return Err(ProgramError::IncorrectProgramId); }
    let proposal_bytes = proposal_ai.data.borrow().to_vec();
    let mut p = Proposal::try_from_slice(&proposal_bytes).map_err(|_| ProgramError::InvalidAccountData)?;
    if p.consumed != 0 { msg!("proposal already consumed"); return Err(ProgramError::InvalidInstructionData); }
    if &p.recipient != recipient_ai.key { msg!("recipient mismatch"); return Err(ProgramError::InvalidInstructionData); }

    if ix_sysvar_ai.key != &sysvar::instructions::id() { msg!("bad ix sysvar"); return Err(ProgramError::InvalidAccountData); }
    let cur_index = sysvar::instructions::load_current_index_checked(ix_sysvar_ai).map_err(|_| ProgramError::InvalidInstructionData)?;
    if cur_index == 0 { msg!("no previous instruction"); return Err(ProgramError::InvalidInstructionData); }
    let prev_ix = sysvar::instructions::load_instruction_at_checked((cur_index-1) as usize, ix_sysvar_ai).map_err(|_| ProgramError::InvalidInstructionData)?;
    if prev_ix.program_id != ed25519_program::id() { msg!("prev is not ed25519"); return Err(ProgramError::InvalidInstructionData); }

    let (pk_from_ix, R_from_ix, msg_bytes) = extract_pk_R_msg_with_expected(prev_ix.data.as_slice(), &p.agg_pubkey)?;

    let (config_key, _cb) = Pubkey::find_program_address(&[b"config"], program_id);
    let (treasury_key, _tb) = Pubkey::find_program_address(&[b"treasury", config_key.as_ref()], program_id);
    if &treasury_key != treasury_ai.key { msg!("treasury PDA mismatch"); return Err(ProgramError::InvalidSeeds); }

    let expected_msg = build_canonical_message(&treasury_key, &p.recipient, p.lamports, &p.nonce, &p.ctx_hash, &p.zk_hash, &p.root);
    if msg_bytes != expected_msg.as_slice() { msg!("message mismatch"); return Err(ProgramError::InvalidInstructionData); }
    if pk_from_ix != p.agg_pubkey { msg!("agg pubkey mismatch"); return Err(ProgramError::InvalidInstructionData); }
    if R_from_ix != p.r_agg      { msg!("R mismatch");          return Err(ProgramError::InvalidInstructionData); }

    p.consumed = 1;
    p.serialize(&mut &mut proposal_ai.data.borrow_mut()[..])?;

    if treasury_ai.lamports() < p.lamports { msg!("insufficient treasury funds"); return Err(ProgramError::InsufficientFunds); }
    let seeds: &[&[u8]] = &[b"treasury", config_key.as_ref(), &[cfg.treasury_bump]];
    let ix = system_instruction::transfer(treasury_ai.key, recipient_ai.key, p.lamports);
    invoke_signed(&ix, &[treasury_ai.clone(), recipient_ai.clone(), system_ai.clone()], &[seeds])?;

    msg!("execute_proposal ok");
    Ok(())
}
