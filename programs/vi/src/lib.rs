use anchor_lang::prelude::*;
use bytemuck::bytes_of;
use solana_feature_set::FeatureSet;
use solana_precompile_error::PrecompileError;
use solana_secp256r1_program::{
    verify, Secp256r1SignatureOffsets, DATA_START, SIGNATURE_OFFSETS_START,
};

declare_id!("PhaARiQBd8a2AcH239Hzf84EM3KLNP1JGEP9CUeZfvE");

#[program]
pub mod vi {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }

    pub fn create_instruction(ctx: Context<CreateInstruction>) -> Result<()> {
        let mut instruction_data = vec![0u8; DATA_START];
        let offsets = Secp256r1SignatureOffsets {
            signature_instruction_index: 1,
            ..Secp256r1SignatureOffsets::default()
        };
        let num_signatures = 1u16;
        instruction_data[0..SIGNATURE_OFFSETS_START].copy_from_slice(bytes_of(&num_signatures));
        instruction_data[SIGNATURE_OFFSETS_START..DATA_START].copy_from_slice(bytes_of(&offsets));

        assert_eq!(
            verify(
                &instruction_data,
                &[&[0u8; 100]],
                &FeatureSet::all_enabled()
            ),
            Err(PrecompileError::InvalidInstructionDataSize)
        );

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}

#[derive(Accounts)]
pub struct CreateInstruction {}

#[account]
pub struct ViAccount {
    pub value: u64,
}

#[error_code]
pub enum CustomError {
    #[msg("Signature verification failed")]
    SignatureVerificationFailed,
}
