//! Cosmos chain registry and configuration

use std::collections::HashMap;

/// Known Cosmos SDK chains
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KnownChain {
    /// Cosmos Hub (ATOM)
    CosmosHub,
    /// Osmosis (OSMO)
    Osmosis,
    /// Injective (INJ)
    Injective,
    /// Celestia (TIA)
    Celestia,
    /// dYdX (DYDX)
    DyDx,
    /// Sei (SEI)
    Sei,
    /// Noble (USDC)
    Noble,
    /// Akash (AKT)
    Akash,
    /// Kava (KAVA)
    Kava,
    /// Stride (STRD)
    Stride,
}

impl KnownChain {
    /// Get the chain configuration
    pub fn config(&self) -> ChainConfig {
        match self {
            Self::CosmosHub => ChainConfig {
                chain_id: "cosmoshub-4".to_string(),
                bech32_prefix: "cosmos".to_string(),
                coin_type: 118,
                denom: "uatom".to_string(),
                gas_price: "0.025".to_string(),
            },
            Self::Osmosis => ChainConfig {
                chain_id: "osmosis-1".to_string(),
                bech32_prefix: "osmo".to_string(),
                coin_type: 118,
                denom: "uosmo".to_string(),
                gas_price: "0.025".to_string(),
            },
            Self::Injective => ChainConfig {
                chain_id: "injective-1".to_string(),
                bech32_prefix: "inj".to_string(),
                coin_type: 60, // Uses Ethereum derivation
                denom: "inj".to_string(),
                gas_price: "500000000".to_string(),
            },
            Self::Celestia => ChainConfig {
                chain_id: "celestia".to_string(),
                bech32_prefix: "celestia".to_string(),
                coin_type: 118,
                denom: "utia".to_string(),
                gas_price: "0.002".to_string(),
            },
            Self::DyDx => ChainConfig {
                chain_id: "dydx-mainnet-1".to_string(),
                bech32_prefix: "dydx".to_string(),
                coin_type: 118,
                denom: "adydx".to_string(),
                gas_price: "0".to_string(), // dYdX has no gas fees
            },
            Self::Sei => ChainConfig {
                chain_id: "pacific-1".to_string(),
                bech32_prefix: "sei".to_string(),
                coin_type: 118,
                denom: "usei".to_string(),
                gas_price: "0.1".to_string(),
            },
            Self::Noble => ChainConfig {
                chain_id: "noble-1".to_string(),
                bech32_prefix: "noble".to_string(),
                coin_type: 118,
                denom: "uusdc".to_string(),
                gas_price: "0".to_string(),
            },
            Self::Akash => ChainConfig {
                chain_id: "akashnet-2".to_string(),
                bech32_prefix: "akash".to_string(),
                coin_type: 118,
                denom: "uakt".to_string(),
                gas_price: "0.025".to_string(),
            },
            Self::Kava => ChainConfig {
                chain_id: "kava_2222-10".to_string(),
                bech32_prefix: "kava".to_string(),
                coin_type: 459,
                denom: "ukava".to_string(),
                gas_price: "0.05".to_string(),
            },
            Self::Stride => ChainConfig {
                chain_id: "stride-1".to_string(),
                bech32_prefix: "stride".to_string(),
                coin_type: 118,
                denom: "ustrd".to_string(),
                gas_price: "0.0025".to_string(),
            },
        }
    }

    /// Get BIP-44 coin type for this chain
    pub fn coin_type(&self) -> u32 {
        self.config().coin_type
    }

    /// Get bech32 address prefix
    pub fn bech32_prefix(&self) -> &str {
        match self {
            Self::CosmosHub => "cosmos",
            Self::Osmosis => "osmo",
            Self::Injective => "inj",
            Self::Celestia => "celestia",
            Self::DyDx => "dydx",
            Self::Sei => "sei",
            Self::Noble => "noble",
            Self::Akash => "akash",
            Self::Kava => "kava",
            Self::Stride => "stride",
        }
    }
}

/// Chain configuration
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// Chain ID (e.g., "cosmoshub-4")
    pub chain_id: String,
    /// Bech32 address prefix (e.g., "cosmos")
    pub bech32_prefix: String,
    /// BIP-44 coin type
    pub coin_type: u32,
    /// Native denomination (e.g., "uatom")
    pub denom: String,
    /// Default gas price
    pub gas_price: String,
}

/// Chain registry for looking up chain configurations
#[derive(Debug, Clone, Default)]
pub struct ChainRegistry {
    /// Custom chain configurations
    chains: HashMap<String, ChainConfig>,
}

impl ChainRegistry {
    /// Create a new chain registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry with all known chains pre-registered
    pub fn with_known_chains() -> Self {
        let mut registry = Self::new();
        for chain in [
            KnownChain::CosmosHub,
            KnownChain::Osmosis,
            KnownChain::Injective,
            KnownChain::Celestia,
            KnownChain::DyDx,
            KnownChain::Sei,
            KnownChain::Noble,
            KnownChain::Akash,
            KnownChain::Kava,
            KnownChain::Stride,
        ] {
            let config = chain.config();
            let chain_id = config.chain_id.clone();
            registry.register(&chain_id, config);
        }
        registry
    }

    /// Register a chain configuration
    pub fn register(&mut self, chain_id: &str, config: ChainConfig) {
        self.chains.insert(chain_id.to_string(), config);
    }

    /// Get a chain configuration by chain ID
    pub fn get(&self, chain_id: &str) -> Option<&ChainConfig> {
        self.chains.get(chain_id)
    }

    /// Get a chain configuration, falling back to a known chain
    pub fn get_or_known(&self, chain_id: &str) -> Option<ChainConfig> {
        if let Some(config) = self.chains.get(chain_id) {
            return Some(config.clone());
        }

        // Try to find a matching known chain
        for chain in [
            KnownChain::CosmosHub,
            KnownChain::Osmosis,
            KnownChain::Injective,
            KnownChain::Celestia,
            KnownChain::DyDx,
            KnownChain::Sei,
            KnownChain::Noble,
            KnownChain::Akash,
            KnownChain::Kava,
            KnownChain::Stride,
        ] {
            let config = chain.config();
            if config.chain_id == chain_id {
                return Some(config);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_chain_config() {
        let config = KnownChain::CosmosHub.config();
        assert_eq!(config.chain_id, "cosmoshub-4");
        assert_eq!(config.bech32_prefix, "cosmos");
        assert_eq!(config.coin_type, 118);
    }

    #[test]
    fn test_chain_registry() {
        let registry = ChainRegistry::with_known_chains();
        let config = registry.get("cosmoshub-4").unwrap();
        assert_eq!(config.bech32_prefix, "cosmos");
    }
}
