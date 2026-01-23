//! Address-based policies (allowlist/blocklist)

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

/// Address restriction mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressRestrictionMode {
    /// Only allow addresses in the list
    Allowlist,
    /// Block addresses in the list (allow all others)
    Blocklist,
}

/// Address entry with optional metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressEntry {
    /// The address (normalized to lowercase)
    pub address: String,
    /// Optional label/description
    pub label: Option<String>,
    /// Whether this entry is enabled
    pub enabled: bool,
    /// Expiration timestamp (optional)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl AddressEntry {
    /// Create a new address entry
    pub fn new(address: &str) -> Self {
        Self {
            address: address.to_lowercase(),
            label: None,
            enabled: true,
            expires_at: None,
        }
    }

    /// Set label
    pub fn with_label(mut self, label: &str) -> Self {
        self.label = Some(label.to_string());
        self
    }

    /// Set expiration
    pub fn expires_at(mut self, expires: chrono::DateTime<chrono::Utc>) -> Self {
        self.expires_at = Some(expires);
        self
    }

    /// Check if the entry is currently valid
    pub fn is_valid(&self) -> bool {
        if !self.enabled {
            return false;
        }
        if let Some(expires) = self.expires_at {
            if chrono::Utc::now() > expires {
                return false;
            }
        }
        true
    }
}

/// Address policy for allowlist/blocklist management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressPolicy {
    /// Restriction mode
    pub mode: AddressRestrictionMode,
    /// Address entries
    pub addresses: Vec<AddressEntry>,
    /// Wildcard patterns (e.g., "0x000*" for burn addresses)
    pub patterns: Vec<String>,
    /// Chain ID this policy applies to (None = all chains)
    pub chain_id: Option<u64>,
    /// Whether to check contract addresses
    pub check_contracts: bool,
}

impl AddressPolicy {
    /// Create a new allowlist policy
    pub fn allowlist() -> Self {
        Self {
            mode: AddressRestrictionMode::Allowlist,
            addresses: Vec::new(),
            patterns: Vec::new(),
            chain_id: None,
            check_contracts: true,
        }
    }

    /// Create a new blocklist policy
    pub fn blocklist() -> Self {
        Self {
            mode: AddressRestrictionMode::Blocklist,
            addresses: Vec::new(),
            patterns: Vec::new(),
            chain_id: None,
            check_contracts: true,
        }
    }

    /// Add an address
    pub fn add_address(mut self, entry: AddressEntry) -> Self {
        self.addresses.push(entry);
        self
    }

    /// Add multiple addresses
    pub fn add_addresses(mut self, addresses: &[&str]) -> Self {
        for addr in addresses {
            self.addresses.push(AddressEntry::new(addr));
        }
        self
    }

    /// Add a pattern
    pub fn add_pattern(mut self, pattern: &str) -> Self {
        self.patterns.push(pattern.to_lowercase());
        self
    }

    /// Set chain ID
    pub fn for_chain(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Check if an address is in the list
    fn contains_address(&self, address: &str) -> bool {
        let normalized = address.to_lowercase();

        // Check exact matches
        for entry in &self.addresses {
            if entry.is_valid() && entry.address == normalized {
                return true;
            }
        }

        // Check patterns
        for pattern in &self.patterns {
            if Self::matches_pattern(&normalized, pattern) {
                return true;
            }
        }

        false
    }

    /// Check if address matches a pattern
    fn matches_pattern(address: &str, pattern: &str) -> bool {
        if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            address.starts_with(prefix)
        } else if pattern.starts_with('*') {
            let suffix = &pattern[1..];
            address.ends_with(suffix)
        } else {
            address == pattern
        }
    }

    /// Check if an address is allowed
    pub fn is_allowed(&self, address: &str) -> bool {
        let in_list = self.contains_address(address);

        match self.mode {
            AddressRestrictionMode::Allowlist => in_list,
            AddressRestrictionMode::Blocklist => !in_list,
        }
    }

    /// Get the reason for rejection (if any)
    pub fn rejection_reason(&self, address: &str) -> Option<String> {
        if self.is_allowed(address) {
            None
        } else {
            match self.mode {
                AddressRestrictionMode::Allowlist => {
                    Some(format!("Address {} not in allowlist", address))
                }
                AddressRestrictionMode::Blocklist => {
                    Some(format!("Address {} is blocklisted", address))
                }
            }
        }
    }

    /// Get all valid addresses
    pub fn get_addresses(&self) -> Vec<&str> {
        self.addresses
            .iter()
            .filter(|e| e.is_valid())
            .map(|e| e.address.as_str())
            .collect()
    }

    /// Remove an address
    pub fn remove_address(&mut self, address: &str) {
        let normalized = address.to_lowercase();
        self.addresses.retain(|e| e.address != normalized);
    }

    /// Enable/disable an address
    pub fn set_address_enabled(&mut self, address: &str, enabled: bool) {
        let normalized = address.to_lowercase();
        for entry in &mut self.addresses {
            if entry.address == normalized {
                entry.enabled = enabled;
                break;
            }
        }
    }
}

impl fmt::Display for AddressPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = match self.mode {
            AddressRestrictionMode::Allowlist => "Allowlist",
            AddressRestrictionMode::Blocklist => "Blocklist",
        };
        let valid_count = self.addresses.iter().filter(|e| e.is_valid()).count();
        write!(
            f,
            "{} ({} addresses, {} patterns)",
            mode,
            valid_count,
            self.patterns.len()
        )
    }
}

/// Common blocklisted addresses (OFAC, known scams, etc.)
pub mod common_blocklists {
    use super::*;

    /// Create a blocklist with common scam/exploit contract patterns
    pub fn scam_patterns() -> AddressPolicy {
        AddressPolicy::blocklist()
            .add_pattern("0x0000000000000000000000000000000000000000") // Zero address
            .add_pattern("0x000000000000000000000000000000000000dead") // Dead address
    }

    /// Create an allowlist for common DeFi protocols (example)
    pub fn known_defi_contracts(chain_id: u64) -> AddressPolicy {
        let mut policy = AddressPolicy::allowlist().for_chain(chain_id);

        // Add well-known Ethereum mainnet contracts (examples)
        if chain_id == 1 {
            policy = policy
                .add_address(
                    AddressEntry::new("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                        .with_label("WETH"),
                )
                .add_address(
                    AddressEntry::new("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")
                        .with_label("Uniswap V2 Router"),
                )
                .add_address(
                    AddressEntry::new("0xE592427A0AEce92De3Edee1F18E0157C05861564")
                        .with_label("Uniswap V3 Router"),
                );
        }

        policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowlist() {
        let policy = AddressPolicy::allowlist().add_addresses(&[
            "0x1234567890123456789012345678901234567890",
            "0xabcdef1234567890123456789012345678901234",
        ]);

        assert!(policy.is_allowed("0x1234567890123456789012345678901234567890"));
        assert!(policy.is_allowed("0xABCDEF1234567890123456789012345678901234")); // Case insensitive
        assert!(!policy.is_allowed("0x0000000000000000000000000000000000000000"));
    }

    #[test]
    fn test_blocklist() {
        let policy = AddressPolicy::blocklist()
            .add_addresses(&["0x0000000000000000000000000000000000000000"]);

        assert!(!policy.is_allowed("0x0000000000000000000000000000000000000000"));
        assert!(policy.is_allowed("0x1234567890123456789012345678901234567890"));
    }

    #[test]
    fn test_patterns() {
        let policy = AddressPolicy::blocklist().add_pattern("0x000000*"); // Block burn addresses

        assert!(!policy.is_allowed("0x0000000000000000000000000000000000000000"));
        assert!(!policy.is_allowed("0x000000000000000000000000000000000000dead"));
        assert!(policy.is_allowed("0x1234567890123456789012345678901234567890"));
    }

    #[test]
    fn test_address_entry_expiration() {
        let expired =
            AddressEntry::new("0x1234").expires_at(chrono::Utc::now() - chrono::Duration::hours(1));
        assert!(!expired.is_valid());

        let valid =
            AddressEntry::new("0x5678").expires_at(chrono::Utc::now() + chrono::Duration::hours(1));
        assert!(valid.is_valid());
    }

    #[test]
    fn test_rejection_reason() {
        let allowlist = AddressPolicy::allowlist().add_addresses(&["0x1234"]);

        assert!(allowlist.rejection_reason("0x1234").is_none());
        assert!(allowlist.rejection_reason("0x5678").is_some());
    }
}
