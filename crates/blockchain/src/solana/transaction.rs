//! Solana transaction support

use super::SolanaPublicKey;
use crate::error::{BlockchainError, Result};
use sha2::{Digest, Sha256};
use std::fmt;

/// Solana transaction instruction
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Program ID
    pub program_id: SolanaPublicKey,
    /// Account keys
    pub accounts: Vec<AccountMeta>,
    /// Instruction data
    pub data: Vec<u8>,
}

impl Instruction {
    /// Create a new instruction
    pub fn new(program_id: SolanaPublicKey, accounts: Vec<AccountMeta>, data: Vec<u8>) -> Self {
        Self {
            program_id,
            accounts,
            data,
        }
    }
}

/// Account metadata for instructions
#[derive(Debug, Clone)]
pub struct AccountMeta {
    /// Account public key
    pub pubkey: SolanaPublicKey,
    /// Is signer
    pub is_signer: bool,
    /// Is writable
    pub is_writable: bool,
}

impl AccountMeta {
    /// Create a new account meta
    pub fn new(pubkey: SolanaPublicKey, is_signer: bool, is_writable: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable,
        }
    }

    /// Create a readonly account
    pub fn readonly(pubkey: SolanaPublicKey, is_signer: bool) -> Self {
        Self::new(pubkey, is_signer, false)
    }

    /// Create a writable account
    pub fn writable(pubkey: SolanaPublicKey, is_signer: bool) -> Self {
        Self::new(pubkey, is_signer, true)
    }
}

/// Solana message header
#[derive(Debug, Clone)]
pub struct MessageHeader {
    /// Number of required signatures
    pub num_required_signatures: u8,
    /// Number of readonly signed accounts
    pub num_readonly_signed_accounts: u8,
    /// Number of readonly unsigned accounts
    pub num_readonly_unsigned_accounts: u8,
}

/// Solana transaction message
#[derive(Debug, Clone)]
pub struct Message {
    /// Message header
    pub header: MessageHeader,
    /// Account keys
    pub account_keys: Vec<SolanaPublicKey>,
    /// Recent blockhash
    pub recent_blockhash: [u8; 32],
    /// Instructions
    pub instructions: Vec<CompiledInstruction>,
}

/// Compiled instruction (with account indices)
#[derive(Debug, Clone)]
pub struct CompiledInstruction {
    /// Program ID index in account_keys
    pub program_id_index: u8,
    /// Account indices
    pub accounts: Vec<u8>,
    /// Instruction data
    pub data: Vec<u8>,
}

impl Message {
    /// Create a new message
    pub fn new(
        instructions: &[Instruction],
        payer: &SolanaPublicKey,
        recent_blockhash: [u8; 32],
    ) -> Self {
        // Collect all unique accounts
        let mut account_keys = Vec::new();
        let mut writable_signers = Vec::new();
        let mut readonly_signers = Vec::new();
        let mut writable_non_signers = Vec::new();
        let mut readonly_non_signers = Vec::new();

        // Add payer first (always writable signer)
        writable_signers.push(*payer);

        for instruction in instructions {
            // Add program ID
            if !readonly_non_signers.contains(&instruction.program_id)
                && !writable_non_signers.contains(&instruction.program_id)
            {
                readonly_non_signers.push(instruction.program_id);
            }

            // Add accounts
            for account in &instruction.accounts {
                if account.is_signer {
                    if account.is_writable {
                        if !writable_signers.contains(&account.pubkey) {
                            writable_signers.push(account.pubkey);
                        }
                    } else if !readonly_signers.contains(&account.pubkey) {
                        readonly_signers.push(account.pubkey);
                    }
                } else if account.is_writable {
                    if !writable_non_signers.contains(&account.pubkey) {
                        writable_non_signers.push(account.pubkey);
                    }
                } else if !readonly_non_signers.contains(&account.pubkey) {
                    readonly_non_signers.push(account.pubkey);
                }
            }
        }

        // Build account keys in order
        account_keys.extend(writable_signers.clone());
        account_keys.extend(readonly_signers.clone());
        account_keys.extend(writable_non_signers);
        account_keys.extend(readonly_non_signers.clone());

        let header = MessageHeader {
            num_required_signatures: (writable_signers.len() + readonly_signers.len()) as u8,
            num_readonly_signed_accounts: readonly_signers.len() as u8,
            num_readonly_unsigned_accounts: readonly_non_signers.len() as u8,
        };

        // Compile instructions
        let compiled_instructions: Vec<CompiledInstruction> = instructions
            .iter()
            .map(|ix| {
                let program_id_index = account_keys
                    .iter()
                    .position(|k| k == &ix.program_id)
                    .unwrap() as u8;

                let accounts: Vec<u8> = ix
                    .accounts
                    .iter()
                    .map(|acc| account_keys.iter().position(|k| k == &acc.pubkey).unwrap() as u8)
                    .collect();

                CompiledInstruction {
                    program_id_index,
                    accounts,
                    data: ix.data.clone(),
                }
            })
            .collect();

        Self {
            header,
            account_keys,
            recent_blockhash,
            instructions: compiled_instructions,
        }
    }

    /// Serialize the message
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Header
        data.push(self.header.num_required_signatures);
        data.push(self.header.num_readonly_signed_accounts);
        data.push(self.header.num_readonly_unsigned_accounts);

        // Account keys (compact-u16 length prefix)
        data.extend_from_slice(&encode_compact_u16(self.account_keys.len() as u16));
        for key in &self.account_keys {
            data.extend_from_slice(key.as_bytes());
        }

        // Recent blockhash
        data.extend_from_slice(&self.recent_blockhash);

        // Instructions (compact-u16 length prefix)
        data.extend_from_slice(&encode_compact_u16(self.instructions.len() as u16));
        for ix in &self.instructions {
            data.push(ix.program_id_index);
            data.extend_from_slice(&encode_compact_u16(ix.accounts.len() as u16));
            data.extend_from_slice(&ix.accounts);
            data.extend_from_slice(&encode_compact_u16(ix.data.len() as u16));
            data.extend_from_slice(&ix.data);
        }

        data
    }

    /// Get the message hash for signing
    pub fn hash(&self) -> [u8; 32] {
        let serialized = self.serialize();
        Sha256::digest(&serialized).into()
    }
}

/// Encode a u16 in compact format
fn encode_compact_u16(value: u16) -> Vec<u8> {
    if value < 128 {
        vec![value as u8]
    } else if value < 16384 {
        vec![(value & 0x7f) as u8 | 0x80, (value >> 7) as u8]
    } else {
        vec![
            (value & 0x7f) as u8 | 0x80,
            ((value >> 7) & 0x7f) as u8 | 0x80,
            (value >> 14) as u8,
        ]
    }
}

/// Solana transaction
#[derive(Clone)]
pub struct SolanaTransaction {
    /// Signatures
    pub signatures: Vec<[u8; 64]>,
    /// Message
    pub message: Message,
}

impl SolanaTransaction {
    /// Create a new unsigned transaction
    pub fn new(message: Message) -> Self {
        let num_signers = message.header.num_required_signatures as usize;
        Self {
            signatures: vec![[0; 64]; num_signers],
            message,
        }
    }

    /// Add a signature at the specified index
    pub fn add_signature(&mut self, index: usize, signature: [u8; 64]) -> Result<()> {
        if index >= self.signatures.len() {
            return Err(BlockchainError::InvalidTransaction(
                "Signature index out of bounds".to_string(),
            ));
        }
        self.signatures[index] = signature;
        Ok(())
    }

    /// Check if transaction is fully signed
    pub fn is_signed(&self) -> bool {
        self.signatures.iter().all(|sig| sig != &[0; 64])
    }

    /// Serialize the transaction
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Signatures (compact-u16 length prefix)
        data.extend_from_slice(&encode_compact_u16(self.signatures.len() as u16));
        for sig in &self.signatures {
            data.extend_from_slice(sig);
        }

        // Message
        data.extend_from_slice(&self.message.serialize());

        data
    }

    /// Get transaction hash (first signature if signed)
    pub fn hash(&self) -> Option<[u8; 64]> {
        if self.is_signed() {
            Some(self.signatures[0])
        } else {
            None
        }
    }
}

impl fmt::Debug for SolanaTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SolanaTransaction")
            .field(
                "signatures",
                &format!("[{} signatures]", self.signatures.len()),
            )
            .field("message", &self.message)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solana::SolanaKeypair;

    #[test]
    fn test_create_instruction() {
        let program_id = SolanaPublicKey::from_bytes([1; 32]);
        let account = AccountMeta::writable(SolanaPublicKey::from_bytes([2; 32]), true);

        let ix = Instruction::new(program_id, vec![account], vec![1, 2, 3, 4]);

        assert_eq!(ix.program_id, program_id);
        assert_eq!(ix.accounts.len(), 1);
        assert_eq!(ix.data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_create_message() {
        let payer = SolanaPublicKey::from_bytes([1; 32]);
        let program_id = SolanaPublicKey::from_bytes([2; 32]);
        let account = AccountMeta::writable(SolanaPublicKey::from_bytes([3; 32]), false);
        let recent_blockhash = [0; 32];

        let ix = Instruction::new(program_id, vec![account], vec![]);
        let message = Message::new(&[ix], &payer, recent_blockhash);

        assert_eq!(message.header.num_required_signatures, 1);
        assert!(message.account_keys.len() >= 2); // At least payer and program
    }

    #[test]
    fn test_message_serialization() {
        let payer = SolanaPublicKey::from_bytes([1; 32]);
        let program_id = SolanaPublicKey::from_bytes([2; 32]);
        let recent_blockhash = [0; 32];

        let ix = Instruction::new(program_id, vec![], vec![]);
        let message = Message::new(&[ix], &payer, recent_blockhash);

        let serialized = message.serialize();
        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_transaction_signing() {
        let keypair = SolanaKeypair::generate();
        let payer = *keypair.public_key();
        let program_id = SolanaPublicKey::from_bytes([2; 32]);
        let recent_blockhash = [0; 32];

        let ix = Instruction::new(program_id, vec![], vec![]);
        let message = Message::new(&[ix], &payer, recent_blockhash);

        let mut tx = SolanaTransaction::new(message.clone());
        assert!(!tx.is_signed());

        // Sign the transaction
        let message_bytes = message.serialize();
        let signature = keypair.sign(&message_bytes);
        tx.add_signature(0, signature).unwrap();

        assert!(tx.is_signed());
    }

    #[test]
    fn test_compact_u16_encoding() {
        assert_eq!(encode_compact_u16(0), vec![0]);
        assert_eq!(encode_compact_u16(127), vec![127]);
        assert_eq!(encode_compact_u16(128), vec![0x80, 0x01]);
        assert_eq!(encode_compact_u16(16383), vec![0xff, 0x7f]);
    }
}
