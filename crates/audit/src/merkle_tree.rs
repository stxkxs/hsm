//! # Merkle Tree Implementation
//!
//! A Merkle tree (hash tree) for efficient verification of audit log integrity.
//! Provides logarithmic-time proofs of event inclusion without requiring the
//! entire event log.
//!
//! ## What is a Merkle Tree?
//!
//! A Merkle tree is a binary tree where:
//! - **Leaves** contain hashes of audit events
//! - **Internal nodes** contain hashes of their children
//! - **Root** is a single hash representing the entire tree
//!
//! ## Tree Construction Algorithm
//!
//! The tree is built bottom-up from the leaf hashes:
//!
//! ```text
//! Given leaf hashes: [H1, H2, H3, H4, H5]
//!
//! Level 0 (leaves):     H1    H2    H3    H4    H5
//!                        |     |     |     |     |
//! Level 1:            H(1,2)  H(3,4)  H(5,5)*
//!                        |       |       |
//! Level 2:           H(H12,H34)  H55*
//!                          |       |
//! Level 3 (root):      H(H1234,H55)
//!
//! * Odd node is paired with itself
//! ```
//!
//! ### Construction Steps:
//!
//! 1. **Initialize**: Create leaf nodes from event hashes
//! 2. **Pair nodes**: Group adjacent nodes in pairs
//! 3. **Combine**: Hash each pair: `SHA256(left_hash || right_hash)`
//! 4. **Handle odd nodes**: Duplicate the last node if odd count
//! 5. **Repeat**: Continue until only one node remains (the root)
//!
//! ### Time Complexity:
//!
//! - **Build**: O(n) - process each node once
//! - **Update**: O(n) - rebuild entire tree
//! - **Generate Proof**: O(log n) - traverse height of tree
//! - **Verify Proof**: O(log n) - rehash path to root
//!
//! ## Merkle Proof
//!
//! A Merkle proof proves an event is in the tree without revealing all events.
//!
//! ```text
//! To prove H3 is in the tree:
//!
//!          Root
//!         /    \
//!      H(1,2)  H(3,4)  ← Need H(1,2)
//!       / \     / \
//!      H1  H2  H3* H4  ← Need H4
//!              ^
//!           Proving this
//!
//! Proof = [H4, H(1,2)]
//! Verification: Hash(Hash(H3, H4), H(1,2)) == Root ✓
//! ```
//!
//! ## Usage Example
//!
//! ```rust
//! use hsm_audit::MerkleTree;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create tree from event hashes
//! let hashes = vec![
//!     "hash1".to_string(),
//!     "hash2".to_string(),
//!     "hash3".to_string(),
//!     "hash4".to_string(),
//! ];
//!
//! let tree = MerkleTree::from_hashes(hashes.clone());
//!
//! // Get the root hash (fingerprint of all events)
//! let root = tree.get_root()?;
//! println!("Merkle root: {}", root);
//!
//! // Verify an event is in the tree
//! assert!(tree.verify_inclusion("hash2"));
//!
//! // Generate a proof that hash2 is in the tree
//! let proof = tree.generate_proof("hash2")?;
//!
//! // Verify the proof (can be done by third party)
//! assert!(tree.verify_proof(&proof)?);
//! # Ok(())
//! # }
//! ```
//!
//! ## Incremental Updates
//!
//! ```rust
//! use hsm_audit::MerkleTree;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut tree = MerkleTree::new();
//!
//! // Add events one at a time (rebuilds tree each time)
//! tree.update("event_hash_1");
//! tree.update("event_hash_2");
//! tree.update("event_hash_3");
//!
//! // Root changes with each update
//! let root = tree.get_root()?;
//! println!("Current root: {}", root);
//! # Ok(())
//! # }
//! ```
//!
//! ## Proof Verification Workflow
//!
//! ```rust
//! # use hsm_audit::{MerkleTree, MerkleProof};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let tree = MerkleTree::from_hashes(vec!["h1".into(), "h2".into(), "h3".into()]);
//! // Auditor generates proof for a specific event
//! let event_hash = "h2";
//! let proof = tree.generate_proof(event_hash)?;
//! let root = tree.get_root()?;
//!
//! // Third party can verify the proof with just:
//! // 1. The event hash
//! // 2. The proof
//! // 3. The trusted root hash
//! assert!(proof.verify(&root));
//! println!("Event verified in log without seeing all events!");
//! # Ok(())
//! # }
//! ```
//!
//! ## Advantages Over Hash Chain
//!
//! | Feature | Hash Chain | Merkle Tree |
//! |---------|-----------|-------------|
//! | Append | O(1) | O(n) |
//! | Verify All | O(n) | O(n) |
//! | Prove Inclusion | O(n) | O(log n) |
//! | Verify Inclusion | O(n) | O(log n) |
//! | Space | O(n) | O(n) |
//!
//! **Use Cases:**
//! - **Hash Chain**: Sequential verification, tamper detection, audit trail
//! - **Merkle Tree**: Efficient proofs, batch verification, certificate transparency
//!
//! ## Security Considerations
//!
//! - Uses SHA-256 for collision resistance
//! - Duplicate nodes for odd counts (standard practice)
//! - Proofs are public - don't reveal sensitive event data
//! - Root hash serves as commitment to entire log
//!
//! ## Performance Notes
//!
//! - Tree rebuild on each update: O(n)
//! - For high-throughput systems, consider batching updates
//! - Proofs are compact: ~log₂(n) hashes
//! - Example: 1 million events → proof has ~20 hashes

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("Tree is empty")]
    EmptyTree,

    #[error("Hash not found in tree")]
    HashNotFound,

    #[error("Invalid proof")]
    InvalidProof,
}

/// Internal node in the Merkle tree.
///
/// Each node contains a hash that is either:
/// - A leaf hash (from an audit event)
/// - A combined hash of two child nodes
#[derive(Debug, Clone)]
struct MerkleNode {
    /// SHA-256 hash as hex string
    hash: String,
}

/// RFC 6962 domain-separation prefix for leaf nodes.
const LEAF_PREFIX: u8 = 0x00;
/// RFC 6962 domain-separation prefix for internal nodes.
const NODE_PREFIX: u8 = 0x01;

/// Hash a raw leaf value using RFC 6962 domain separation.
///
/// `leaf_digest = SHA256(0x00 || leaf_value_bytes)`
///
/// The `0x00` prefix ensures a leaf hash can never collide with an internal
/// node hash (which is prefixed with `0x01`). Without this separation an
/// attacker could present an internal-node hash as if it were a leaf, forging
/// a second pre-image inclusion proof for an event that was never logged.
fn hash_leaf(leaf_value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(leaf_value.as_bytes());
    hex::encode(hasher.finalize())
}

/// Combine two child node hashes using RFC 6962 domain separation.
///
/// `node = SHA256(0x01 || left_digest_bytes || right_digest_bytes)`
///
/// The child digests are interpreted as raw bytes (decoded from hex) so that
/// the construction matches the canonical RFC 6962 binary layout. If a child
/// digest is not valid hex (should never happen for internally produced
/// hashes), its UTF-8 bytes are used as a fallback so verification of
/// externally supplied proofs remains deterministic.
fn hash_node(left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    match (hex::decode(left), hex::decode(right)) {
        (Ok(l), Ok(r)) => {
            hasher.update(&l);
            hasher.update(&r);
        }
        _ => {
            hasher.update(left.as_bytes());
            hasher.update(right.as_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

impl MerkleNode {
    /// Create a leaf node from a raw leaf value (applies the leaf prefix).
    fn leaf(leaf_value: &str) -> Self {
        Self {
            hash: hash_leaf(leaf_value),
        }
    }

    fn with_children(left: MerkleNode, right: MerkleNode) -> Self {
        let hash = hash_node(&left.hash, &right.hash);
        Self { hash }
    }
}

/// Merkle tree for efficient verification of audit log integrity.
///
/// Provides O(log n) proof generation and verification for event inclusion,
/// making it efficient to prove an event is in the audit log without
/// revealing all events.
///
/// # Structure
///
/// - `root`: The top node representing the entire tree
/// - `leaves`: Ordered list of leaf hashes (audit event hashes)
/// - `leaf_indices`: HashMap for O(1) hash lookup
///
/// # Examples
///
/// ```rust
/// use hsm_audit::MerkleTree;
///
/// let hashes = vec!["h1".to_string(), "h2".to_string(), "h3".to_string()];
/// let tree = MerkleTree::from_hashes(hashes);
///
/// assert_eq!(tree.len(), 3);
/// assert!(!tree.is_empty());
/// ```
pub struct MerkleTree {
    /// Root node of the tree (None if empty)
    root: Option<MerkleNode>,
    /// Leaf hashes in insertion order
    leaves: Vec<String>,
    /// Index mapping for O(1) hash lookup
    leaf_indices: HashMap<String, usize>,
}

impl MerkleTree {
    /// Create a new empty Merkle tree
    pub fn new() -> Self {
        Self {
            root: None,
            leaves: Vec::new(),
            leaf_indices: HashMap::new(),
        }
    }

    /// Create a Merkle tree from a list of hashes
    pub fn from_hashes(hashes: Vec<String>) -> Self {
        let mut tree = Self::new();
        // Build leaf indices and leaves without rebuilding tree for each hash
        for (idx, hash) in hashes.iter().enumerate() {
            tree.leaf_indices.insert(hash.clone(), idx);
            tree.leaves.push(hash.clone());
        }
        // Rebuild tree once after all leaves are added
        tree.rebuild();
        tree
    }

    /// Add a new hash to the tree (rebuilds the tree)
    pub fn update(&mut self, hash: &str) {
        self.leaf_indices
            .insert(hash.to_string(), self.leaves.len());
        self.leaves.push(hash.to_string());
        self.rebuild();
    }

    /// Rebuilds the entire tree from leaves using bottom-up construction.
    ///
    /// # Algorithm
    ///
    /// 1. Start with leaf nodes
    /// 2. While more than one node exists:
    ///    - Pair adjacent nodes
    ///    - Combine each pair: SHA256(left || right)
    ///    - If odd count, duplicate the last node
    ///    - Move to next level
    /// 3. Last remaining node becomes the root
    ///
    /// # Time Complexity
    ///
    /// O(n) - processes each node exactly once during tree construction
    ///
    /// # Example Tree Construction
    ///
    /// ```text
    /// Leaves: [A, B, C, D, E]
    ///
    /// Level 1: [H(A,B), H(C,D), H(E,E)]
    /// Level 2: [H(H(A,B),H(C,D)), H(H(E,E),H(E,E))]
    /// Level 3: [H(all)]  ← Root
    /// ```
    fn rebuild(&mut self) {
        if self.leaves.is_empty() {
            self.root = None;
            return;
        }

        let mut nodes: Vec<MerkleNode> = self
            .leaves
            .iter()
            .map(|leaf_value| MerkleNode::leaf(leaf_value))
            .collect();

        // Build tree bottom-up
        while nodes.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in nodes.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(MerkleNode::with_children(
                        chunk[0].clone(),
                        chunk[1].clone(),
                    ));
                } else {
                    // Odd number of nodes - duplicate the last one
                    next_level.push(MerkleNode::with_children(
                        chunk[0].clone(),
                        chunk[0].clone(),
                    ));
                }
            }

            nodes = next_level;
        }

        self.root = Some(nodes.into_iter().next().unwrap());
    }

    /// Get the root hash of the tree
    pub fn get_root(&self) -> Result<String, MerkleError> {
        self.root
            .as_ref()
            .map(|node| node.hash.clone())
            .ok_or(MerkleError::EmptyTree)
    }

    /// Verify that a hash is included in the tree
    pub fn verify_inclusion(&self, hash: &str) -> bool {
        self.leaf_indices.contains_key(hash)
    }

    /// Generates a Merkle proof for a given hash.
    ///
    /// A Merkle proof is a list of sibling hashes along the path from the
    /// leaf to the root. Anyone with this proof and the root hash can verify
    /// that the event is in the tree without seeing all events.
    ///
    /// # Arguments
    ///
    /// * `hash` - The leaf hash to generate a proof for
    ///
    /// # Returns
    ///
    /// A `MerkleProof` containing the sibling hashes needed for verification
    ///
    /// # Errors
    ///
    /// Returns `MerkleError::HashNotFound` if the hash is not in the tree
    ///
    /// # Time Complexity
    ///
    /// O(log n) - traverses from leaf to root
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use hsm_audit::MerkleTree;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let tree = MerkleTree::from_hashes(vec![
    ///     "h1".to_string(),
    ///     "h2".to_string(),
    ///     "h3".to_string(),
    ///     "h4".to_string(),
    /// ]);
    ///
    /// let proof = tree.generate_proof("h2")?;
    /// println!("Proof has {} sibling hashes", proof.elements.len());
    ///
    /// // Verify the proof
    /// let root = tree.get_root()?;
    /// assert!(proof.verify(&root));
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate_proof(&self, hash: &str) -> Result<MerkleProof, MerkleError> {
        let index = self
            .leaf_indices
            .get(hash)
            .ok_or(MerkleError::HashNotFound)?;

        let mut proof = Vec::new();
        let mut current_index = *index;

        // Build proof by traversing from leaf to root. The proof operates on
        // domain-separated leaf digests (SHA256(0x00 || leaf_value)), so the
        // sibling hashes recorded here are leaf/internal-node *digests*, never
        // raw leaf values. This prevents an internal-node hash from being
        // replayed as a leaf during verification.
        let mut level_nodes: Vec<String> = self.leaves.iter().map(|v| hash_leaf(v)).collect();
        let mut level_size = level_nodes.len();

        while level_size > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            // Get sibling hash (duplicate if at end)
            let sibling = if sibling_index < level_nodes.len() {
                level_nodes[sibling_index].clone()
            } else {
                level_nodes[current_index].clone()
            };

            proof.push(ProofElement {
                hash: sibling,
                is_left: current_index % 2 != 0,
            });

            // Move to parent level
            let mut next_level = Vec::new();
            for chunk in level_nodes.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(hash_node(&chunk[0], &chunk[1]));
                } else {
                    next_level.push(hash_node(&chunk[0], &chunk[0]));
                }
            }

            current_index /= 2;
            level_nodes = next_level;
            level_size = level_nodes.len();
        }

        Ok(MerkleProof {
            leaf_hash: hash.to_string(),
            elements: proof,
        })
    }

    /// Verify a Merkle proof against the current root
    pub fn verify_proof(&self, proof: &MerkleProof) -> Result<bool, MerkleError> {
        let root = self.get_root()?;
        Ok(proof.verify(&root))
    }

    /// Get the number of leaves in the tree
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Get all leaf hashes
    pub fn get_leaves(&self) -> Vec<String> {
        self.leaves.clone()
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Element in a Merkle proof path.
///
/// Each element represents a sibling hash needed to compute
/// the parent hash along the path from leaf to root.
#[derive(Debug, Clone)]
pub struct ProofElement {
    /// Sibling hash as hex string
    pub hash: String,
    /// Position: true if sibling is on the left, false if on the right
    pub is_left: bool,
}

/// Merkle proof for inclusion verification.
///
/// Contains the minimal set of hashes needed to verify that a specific
/// event is included in the tree without requiring all events.
///
/// # Structure
///
/// - `leaf_hash`: The event hash being proven
/// - `elements`: Sibling hashes from leaf to root
///
/// # Proof Size
///
/// Proof size is O(log n) where n is the number of leaves:
/// - 10 events → ~4 hashes
/// - 100 events → ~7 hashes
/// - 1,000 events → ~10 hashes
/// - 1,000,000 events → ~20 hashes
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The leaf hash being proven
    pub leaf_hash: String,
    /// Sibling hashes along the path to root
    pub elements: Vec<ProofElement>,
}

impl MerkleProof {
    /// Verifies the proof against a given root hash.
    ///
    /// Recomputes the path from leaf to root using the sibling hashes
    /// and checks if the final computed hash matches the expected root.
    ///
    /// # Arguments
    ///
    /// * `root_hash` - The expected Merkle root to verify against
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid and the leaf is in the tree,
    /// `false` otherwise
    ///
    /// # Algorithm
    ///
    /// ```text
    /// Start with leaf_hash
    /// For each sibling in proof:
    ///     If sibling is left:
    ///         hash = SHA256(sibling || hash)
    ///     Else:
    ///         hash = SHA256(hash || sibling)
    /// Return hash == root_hash
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use hsm_audit::MerkleTree;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let tree = MerkleTree::from_hashes(vec![
    ///     "event1".to_string(),
    ///     "event2".to_string(),
    ///     "event3".to_string(),
    /// ]);
    ///
    /// let root = tree.get_root()?;
    /// let proof = tree.generate_proof("event2")?;
    ///
    /// // Third party can verify with just root and proof
    /// assert!(proof.verify(&root));
    ///
    /// // Wrong root fails verification
    /// assert!(!proof.verify("invalid_root"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify(&self, root_hash: &str) -> bool {
        // Start from the domain-separated leaf digest (0x00 prefix). Sibling
        // elements are combined with the internal-node hash (0x01 prefix).
        // Because the prefixes differ, a proof whose recorded `leaf_hash` is
        // actually an internal-node digest cannot be coerced into matching the
        // root: it will be re-hashed as a leaf (0x00) and diverge.
        let mut current = hash_leaf(&self.leaf_hash);

        for element in &self.elements {
            current = if element.is_left {
                hash_node(&element.hash, &current)
            } else {
                hash_node(&current, &element.hash)
            };
        }

        current == root_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_string(s: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        hex::encode(hasher.finalize())
    }

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new();
        assert!(tree.is_empty());
        assert!(tree.get_root().is_err());
    }

    #[test]
    fn test_single_leaf() {
        let mut tree = MerkleTree::new();
        let hash = hash_string("data1");

        tree.update(&hash);

        assert_eq!(tree.len(), 1);
        // With RFC 6962 domain separation the single-leaf root is the leaf
        // digest SHA256(0x00 || leaf_value), not the raw leaf value itself.
        assert_eq!(tree.get_root().unwrap(), hash_leaf(&hash));
        assert!(tree.verify_inclusion(&hash));
    }

    #[test]
    fn test_multiple_leaves() {
        let mut tree = MerkleTree::new();
        let hashes: Vec<String> = (1..=4)
            .map(|i| hash_string(&format!("data{}", i)))
            .collect();

        for hash in &hashes {
            tree.update(hash);
        }

        assert_eq!(tree.len(), 4);
        let root = tree.get_root().unwrap();
        assert!(!root.is_empty());

        // All hashes should be verifiable
        for hash in &hashes {
            assert!(tree.verify_inclusion(hash));
        }
    }

    #[test]
    fn test_odd_number_of_leaves() {
        let mut tree = MerkleTree::new();
        let hashes: Vec<String> = (1..=5)
            .map(|i| hash_string(&format!("data{}", i)))
            .collect();

        for hash in &hashes {
            tree.update(hash);
        }

        assert_eq!(tree.len(), 5);
        assert!(tree.get_root().is_ok());
    }

    #[test]
    fn test_merkle_proof_generation() {
        let mut tree = MerkleTree::new();
        let hashes: Vec<String> = (1..=4)
            .map(|i| hash_string(&format!("data{}", i)))
            .collect();

        for hash in &hashes {
            tree.update(hash);
        }

        for hash in &hashes {
            let proof = tree.generate_proof(hash).unwrap();
            assert_eq!(proof.leaf_hash, *hash);
            assert!(!proof.elements.is_empty());
        }
    }

    #[test]
    fn test_merkle_proof_verification() {
        let mut tree = MerkleTree::new();
        let hashes: Vec<String> = (1..=8)
            .map(|i| hash_string(&format!("data{}", i)))
            .collect();

        for hash in &hashes {
            tree.update(hash);
        }

        let root = tree.get_root().unwrap();

        for hash in &hashes {
            let proof = tree.generate_proof(hash).unwrap();
            assert!(proof.verify(&root));
            assert!(tree.verify_proof(&proof).unwrap());
        }
    }

    #[test]
    fn test_invalid_proof() {
        let mut tree = MerkleTree::new();
        let hashes: Vec<String> = (1..=4)
            .map(|i| hash_string(&format!("data{}", i)))
            .collect();

        for hash in &hashes {
            tree.update(hash);
        }

        let proof = tree.generate_proof(&hashes[0]).unwrap();

        // Verify against wrong root should fail
        let wrong_root = hash_string("wrong");
        assert!(!proof.verify(&wrong_root));
    }

    #[test]
    fn test_second_preimage_internal_node_as_leaf_rejected() {
        // Build a 4-leaf tree.
        let leaves: Vec<String> = (1..=4)
            .map(|i| hash_string(&format!("data{}", i)))
            .collect();
        let tree = MerkleTree::from_hashes(leaves.clone());
        let root = tree.get_root().unwrap();

        // Compute the internal node digest covering leaves 0 and 1. Pre-domain
        // separation, an attacker could present this internal-node hash as a
        // single "leaf" and use the right subtree's internal node as the only
        // proof element to reconstruct the root, forging inclusion of an event
        // that was never logged. Reproduce that forgery attempt here.
        let l0 = hash_leaf(&leaves[0]);
        let l1 = hash_leaf(&leaves[1]);
        let l2 = hash_leaf(&leaves[2]);
        let l3 = hash_leaf(&leaves[3]);
        let left_internal = hash_node(&l0, &l1); // node over leaves 0,1
        let right_internal = hash_node(&l2, &l3); // node over leaves 2,3

        // Sanity: the honest root is hash_node(left_internal, right_internal).
        assert_eq!(root, hash_node(&left_internal, &right_internal));

        // Forged proof: claim `left_internal` is itself a leaf, with
        // `right_internal` as the sibling. Under domain separation, verify()
        // re-hashes the claimed leaf as SHA256(0x00 || left_internal), which
        // differs from `left_internal`, so the recomputed root will not match.
        let forged = MerkleProof {
            leaf_hash: left_internal.clone(),
            elements: vec![ProofElement {
                hash: right_internal.clone(),
                is_left: false,
            }],
        };
        assert!(
            !forged.verify(&root),
            "internal node hash must not be accepted as a leaf"
        );

        // The same forgery framed as a left sibling must also be rejected.
        let forged_left = MerkleProof {
            leaf_hash: right_internal,
            elements: vec![ProofElement {
                hash: left_internal,
                is_left: true,
            }],
        };
        assert!(!forged_left.verify(&root));

        // Meanwhile, a genuine proof for a real leaf still verifies.
        let honest = tree.generate_proof(&leaves[2]).unwrap();
        assert!(honest.verify(&root));
    }

    #[test]
    fn test_inclusion_after_update() {
        let mut tree = MerkleTree::new();
        let hash1 = hash_string("data1");
        let hash2 = hash_string("data2");

        tree.update(&hash1);
        assert!(tree.verify_inclusion(&hash1));
        assert!(!tree.verify_inclusion(&hash2));

        tree.update(&hash2);
        assert!(tree.verify_inclusion(&hash1));
        assert!(tree.verify_inclusion(&hash2));
    }

    #[test]
    fn test_from_hashes() {
        let hashes: Vec<String> = (1..=5)
            .map(|i| hash_string(&format!("data{}", i)))
            .collect();

        let tree = MerkleTree::from_hashes(hashes.clone());

        assert_eq!(tree.len(), 5);
        for hash in &hashes {
            assert!(tree.verify_inclusion(hash));
        }
    }

    #[test]
    fn test_root_changes_on_update() {
        let mut tree = MerkleTree::new();
        let hash1 = hash_string("data1");
        let hash2 = hash_string("data2");

        tree.update(&hash1);
        let root1 = tree.get_root().unwrap();

        tree.update(&hash2);
        let root2 = tree.get_root().unwrap();

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_large_tree() {
        let mut tree = MerkleTree::new();
        let hashes: Vec<String> = (1..=1000)
            .map(|i| hash_string(&format!("data{}", i)))
            .collect();

        for hash in &hashes {
            tree.update(hash);
        }

        assert_eq!(tree.len(), 1000);

        // Verify some random proofs
        for i in [0, 100, 500, 999] {
            let proof = tree.generate_proof(&hashes[i]).unwrap();
            assert!(tree.verify_proof(&proof).unwrap());
        }
    }
}
