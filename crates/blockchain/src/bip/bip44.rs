//! BIP-44: Multi-Account Hierarchy for Deterministic Wallets
//!
//! Provides standardized derivation paths for different cryptocurrencies.
//!
//! # Path Structure
//!
//! ```text
//! m / purpose' / coin_type' / account' / change / address_index
//! ```
//!
//! - purpose: Always 44' for BIP-44
//! - coin_type: Registered coin type (see SLIP-44)
//! - account: Account index (0-based)
//! - change: 0 for external, 1 for internal (change) addresses
//! - address_index: Address index (0-based)

use super::bip32::{ChildNumber, DerivationPath};
use serde::{Deserialize, Serialize};

/// Standard coin types from SLIP-44
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoinType {
    /// Bitcoin (BTC)
    Bitcoin,
    /// Bitcoin Testnet
    BitcoinTestnet,
    /// Litecoin (LTC)
    Litecoin,
    /// Dogecoin (DOGE)
    Dogecoin,
    /// Ethereum (ETH)
    Ethereum,
    /// Ethereum Classic (ETC)
    EthereumClassic,
    /// Ripple (XRP)
    Ripple,
    /// Bitcoin Cash (BCH)
    BitcoinCash,
    /// Stellar (XLM)
    Stellar,
    /// Tron (TRX)
    Tron,
    /// Binance Chain (BNB)
    BinanceChain,
    /// Solana (SOL)
    Solana,
    /// Polygon (MATIC)
    Polygon,
    /// Avalanche (AVAX)
    Avalanche,
    /// Arbitrum
    Arbitrum,
    /// Optimism
    Optimism,
    /// Cosmos (ATOM)
    Cosmos,
    /// Polkadot (DOT)
    Polkadot,
    /// Custom coin type
    Custom(u32),
}

impl CoinType {
    /// Get the coin type number
    pub fn value(&self) -> u32 {
        match self {
            CoinType::Bitcoin => 0,
            CoinType::BitcoinTestnet => 1,
            CoinType::Litecoin => 2,
            CoinType::Dogecoin => 3,
            CoinType::Ethereum => 60,
            CoinType::EthereumClassic => 61,
            CoinType::Ripple => 144,
            CoinType::BitcoinCash => 145,
            CoinType::Stellar => 148,
            CoinType::Tron => 195,
            CoinType::BinanceChain => 714,
            CoinType::Solana => 501,
            CoinType::Polygon => 966,
            CoinType::Avalanche => 9000,
            CoinType::Arbitrum => 9001,
            CoinType::Optimism => 614,
            CoinType::Cosmos => 118,
            CoinType::Polkadot => 354,
            CoinType::Custom(v) => *v,
        }
    }

    /// Create from raw value
    pub fn from_value(value: u32) -> Self {
        match value {
            0 => CoinType::Bitcoin,
            1 => CoinType::BitcoinTestnet,
            2 => CoinType::Litecoin,
            3 => CoinType::Dogecoin,
            60 => CoinType::Ethereum,
            61 => CoinType::EthereumClassic,
            144 => CoinType::Ripple,
            145 => CoinType::BitcoinCash,
            148 => CoinType::Stellar,
            195 => CoinType::Tron,
            714 => CoinType::BinanceChain,
            501 => CoinType::Solana,
            966 => CoinType::Polygon,
            9000 => CoinType::Avalanche,
            9001 => CoinType::Arbitrum,
            614 => CoinType::Optimism,
            118 => CoinType::Cosmos,
            354 => CoinType::Polkadot,
            v => CoinType::Custom(v),
        }
    }
}

/// Account path builder for BIP-44 compliance
#[derive(Debug, Clone)]
pub struct AccountPath {
    /// Purpose (always 44 for BIP-44)
    purpose: u32,
    /// Coin type
    coin_type: CoinType,
    /// Account index
    account: u32,
    /// Change (0 for external, 1 for internal)
    change: u32,
}

impl AccountPath {
    /// Create a new account path
    pub fn new(coin_type: CoinType, account: u32) -> Self {
        Self {
            purpose: 44,
            coin_type,
            account,
            change: 0, // External by default
        }
    }

    /// Set to internal (change) chain
    pub fn internal(mut self) -> Self {
        self.change = 1;
        self
    }

    /// Set to external chain
    pub fn external(mut self) -> Self {
        self.change = 0;
        self
    }

    /// Get derivation path for a specific address index
    pub fn address(&self, index: u32) -> DerivationPath {
        DerivationPath::from_components(vec![
            ChildNumber::hardened(self.purpose),
            ChildNumber::hardened(self.coin_type.value()),
            ChildNumber::hardened(self.account),
            ChildNumber::normal(self.change),
            ChildNumber::normal(index),
        ])
    }

    /// Get the account-level path (without change and address index)
    pub fn account_path(&self) -> DerivationPath {
        DerivationPath::from_components(vec![
            ChildNumber::hardened(self.purpose),
            ChildNumber::hardened(self.coin_type.value()),
            ChildNumber::hardened(self.account),
        ])
    }

    /// Get the change-level path (without address index)
    pub fn change_path(&self) -> DerivationPath {
        DerivationPath::from_components(vec![
            ChildNumber::hardened(self.purpose),
            ChildNumber::hardened(self.coin_type.value()),
            ChildNumber::hardened(self.account),
            ChildNumber::normal(self.change),
        ])
    }

    /// Get coin type
    pub fn coin_type(&self) -> CoinType {
        self.coin_type
    }

    /// Get account index
    pub fn account(&self) -> u32 {
        self.account
    }

    /// Get change index
    pub fn change(&self) -> u32 {
        self.change
    }
}

/// Commonly used derivation paths
pub mod paths {
    use super::*;

    /// Standard Ethereum path: m/44'/60'/0'/0/0
    pub fn ethereum_default() -> DerivationPath {
        AccountPath::new(CoinType::Ethereum, 0).address(0)
    }

    /// Standard Bitcoin path: m/44'/0'/0'/0/0
    pub fn bitcoin_default() -> DerivationPath {
        AccountPath::new(CoinType::Bitcoin, 0).address(0)
    }

    /// Standard Solana path: m/44'/501'/0'/0'
    pub fn solana_default() -> DerivationPath {
        // Solana uses all hardened derivation
        DerivationPath::from_components(vec![
            ChildNumber::hardened(44),
            ChildNumber::hardened(501),
            ChildNumber::hardened(0),
            ChildNumber::hardened(0),
        ])
    }

    /// Ledger Live Ethereum path: m/44'/60'/index'/0/0
    pub fn ledger_live_ethereum(index: u32) -> DerivationPath {
        AccountPath::new(CoinType::Ethereum, index).address(0)
    }

    /// MetaMask/MEW path: m/44'/60'/0'/0/index
    pub fn metamask_ethereum(index: u32) -> DerivationPath {
        AccountPath::new(CoinType::Ethereum, 0).address(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coin_type_values() {
        assert_eq!(CoinType::Bitcoin.value(), 0);
        assert_eq!(CoinType::Ethereum.value(), 60);
        assert_eq!(CoinType::Solana.value(), 501);
        assert_eq!(CoinType::Custom(12345).value(), 12345);
    }

    #[test]
    fn test_coin_type_from_value() {
        assert_eq!(CoinType::from_value(0), CoinType::Bitcoin);
        assert_eq!(CoinType::from_value(60), CoinType::Ethereum);
        assert_eq!(CoinType::from_value(501), CoinType::Solana);
        assert_eq!(CoinType::from_value(99999), CoinType::Custom(99999));
    }

    #[test]
    fn test_account_path_ethereum() {
        let path = AccountPath::new(CoinType::Ethereum, 0).address(0);
        assert_eq!(path.to_string(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn test_account_path_bitcoin() {
        let path = AccountPath::new(CoinType::Bitcoin, 0).address(0);
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn test_account_path_internal() {
        let path = AccountPath::new(CoinType::Ethereum, 0)
            .internal()
            .address(5);
        assert_eq!(path.to_string(), "m/44'/60'/0'/1/5");
    }

    #[test]
    fn test_account_path_multiple_accounts() {
        let path0 = AccountPath::new(CoinType::Ethereum, 0).address(0);
        let path1 = AccountPath::new(CoinType::Ethereum, 1).address(0);
        let path2 = AccountPath::new(CoinType::Ethereum, 2).address(0);

        assert_eq!(path0.to_string(), "m/44'/60'/0'/0/0");
        assert_eq!(path1.to_string(), "m/44'/60'/1'/0/0");
        assert_eq!(path2.to_string(), "m/44'/60'/2'/0/0");
    }

    #[test]
    fn test_standard_paths() {
        assert_eq!(paths::ethereum_default().to_string(), "m/44'/60'/0'/0/0");
        assert_eq!(paths::bitcoin_default().to_string(), "m/44'/0'/0'/0/0");
        assert_eq!(paths::solana_default().to_string(), "m/44'/501'/0'/0'");
    }

    #[test]
    fn test_ledger_live_path() {
        assert_eq!(
            paths::ledger_live_ethereum(0).to_string(),
            "m/44'/60'/0'/0/0"
        );
        assert_eq!(
            paths::ledger_live_ethereum(1).to_string(),
            "m/44'/60'/1'/0/0"
        );
    }

    #[test]
    fn test_metamask_path() {
        assert_eq!(paths::metamask_ethereum(0).to_string(), "m/44'/60'/0'/0/0");
        assert_eq!(paths::metamask_ethereum(5).to_string(), "m/44'/60'/0'/0/5");
    }
}
