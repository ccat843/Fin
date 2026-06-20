use anchor_lang::prelude::*;

#[program]
pub mod vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require_keys_eq!(ctx.accounts.owner.key(), ctx.accounts.vault.owner);
        ctx.accounts.vault.balance = ctx.accounts.vault.balance.checked_sub(amount).unwrap();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    pub owner: Signer<'info>,
}

#[account]
pub struct VaultState {
    pub owner: Pubkey,
    pub balance: u64,
}
