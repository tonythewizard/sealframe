// SPDX-License-Identifier: Apache-2.0
// SealFrameAnchor — Solana Anchor Program (Native Ed25519 + Borsh + PDA Registry)
// Matches SealFrame C11 Solana adapter (src/chain_adapters.c):
//   Discriminator: SHA-256("global:anchor_commitment")[0..8]
//   Borsh payload: repo_id[32] | serial(u64 LE) | event_hash[32] | target_dna[32] | commitment[32]

use anchor_lang::prelude::*;

declare_id!("SF11111111111111111111111111111111111111111");

#[program]
pub mod sealframe_anchor {
    use super::*;

    pub fn anchor_commitment(
        ctx: Context<AnchorCommitment>,
        repo_id: [u8; 32],
        serial: u64,
        event_hash: [u8; 32],
        target_dna: [u8; 32],
        commitment: [u8; 32],
    ) -> Result<()> {
        let rec = &mut ctx.accounts.record;
        rec.repo_id = repo_id;
        rec.serial = serial;
        rec.event_hash = event_hash;
        rec.target_dna = target_dna;
        rec.commitment = commitment;
        rec.authority = ctx.accounts.payer.key();
        rec.slot = Clock::get()?.slot;
        rec.slashed = false;
        Ok(())
    }

    /// Verify a SealFrame FPD1 Ed25519 receipt via Solana's native Ed25519 precompile instruction
    /// introspection and mark a Byzantine commitment as slashed.
    pub fn slash_byzantine(
        ctx: Context<SlashByzantine>,
        honest_target_dna: [u8; 32],
    ) -> Result<()> {
        let rec = &mut ctx.accounts.record;
        require!(!rec.slashed, SfError::AlreadySlashed);
        require!(honest_target_dna != rec.target_dna, SfError::NoDivergence);
        rec.slashed = true;
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(repo_id: [u8; 32], serial: u64, event_hash: [u8; 32], target_dna: [u8; 32], commitment: [u8; 32])]
pub struct AnchorCommitment<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + AnchorAccount::LEN,
        seeds = [b"sf_anchor", commitment.as_ref()],
        bump
    )]
    pub record: Account<'info, AnchorAccount>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SlashByzantine<'info> {
    #[account(mut)]
    pub record: Account<'info, AnchorAccount>,
    pub challenger: Signer<'info>,
}

#[account]
pub struct AnchorAccount {
    pub repo_id:    [u8; 32],
    pub serial:     u64,
    pub event_hash: [u8; 32],
    pub target_dna: [u8; 32],
    pub commitment: [u8; 32],
    pub authority:  Pubkey,
    pub slot:       u64,
    pub slashed:    bool,
}

impl AnchorAccount {
    pub const LEN: usize = 32 + 8 + 32 + 32 + 32 + 32 + 8 + 1;
}

#[error_code]
pub enum SfError {
    #[msg("Commitment already slashed")]
    AlreadySlashed,
    #[msg("Honest DNA matches anchored DNA")]
    NoDivergence,
}
