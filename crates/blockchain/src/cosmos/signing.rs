//! Cosmos signing implementation

use crate::error::{BlockchainError, Result};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Cosmos address derived from a public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosmosAddress {
    /// The bech32-encoded address
    pub address: String,
    /// The raw address bytes (20 bytes for secp256k1)
    pub bytes: Vec<u8>,
}

impl CosmosAddress {
    /// Derive a Cosmos address from a secp256k1 public key.
    ///
    /// The address is the canonical Cosmos SDK derivation
    /// (`AddressHash` for secp256k1 keys):
    /// 1. The public key MUST be the 33-byte SEC1 *compressed* form. Cosmos SDK
    ///    only ever hashes the compressed encoding; hashing an uncompressed
    ///    65-byte key would yield a different (wrong) address that no chain would
    ///    recognise, so uncompressed keys are normalised to compressed first.
    /// 2. `HASH160 = RIPEMD160(SHA256(compressed_pubkey))` — 20 bytes.
    /// 3. Bech32 encoding with the chain's prefix.
    pub fn from_public_key(public_key: &[u8], prefix: &str) -> Result<String> {
        let address_bytes = Self::hash160_from_public_key(public_key)?;
        bech32_encode(prefix, &address_bytes)
    }

    /// Compute the 20-byte Cosmos address (HASH160) from a secp256k1 public key.
    ///
    /// Accepts a 33-byte compressed key directly, or a 65-byte uncompressed key
    /// (which is re-compressed before hashing, since Cosmos addresses are always
    /// derived from the compressed encoding).
    fn hash160_from_public_key(public_key: &[u8]) -> Result<[u8; 20]> {
        let compressed = match public_key.len() {
            33 => {
                if public_key[0] != 0x02 && public_key[0] != 0x03 {
                    return Err(BlockchainError::InvalidPublicKey(
                        "Compressed secp256k1 key must start with 0x02 or 0x03".to_string(),
                    ));
                }
                // Validate the point lies on the curve.
                k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|e| BlockchainError::InvalidPublicKey(e.to_string()))?;
                public_key.to_vec()
            }
            65 => {
                // Re-encode to compressed form.
                let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|e| BlockchainError::InvalidPublicKey(e.to_string()))?;
                vk.to_encoded_point(true).as_bytes().to_vec()
            }
            other => {
                return Err(BlockchainError::InvalidPublicKey(format!(
                    "Invalid public key length: expected 33 (compressed) or 65 (uncompressed), got {}",
                    other
                )));
            }
        };

        // HASH160 = RIPEMD160(SHA256(compressed_pubkey))
        let sha = Sha256::digest(&compressed);
        let ripemd = Ripemd160::digest(sha);

        let mut out = [0u8; 20];
        out.copy_from_slice(&ripemd);
        Ok(out)
    }

    /// Create from raw address bytes
    pub fn from_bytes(bytes: &[u8], prefix: &str) -> Result<Self> {
        if bytes.len() != 20 {
            return Err(BlockchainError::InvalidAddress(
                "Address must be 20 bytes".to_string(),
            ));
        }

        let address = bech32_encode(prefix, bytes)?;

        Ok(Self {
            address,
            bytes: bytes.to_vec(),
        })
    }

    /// Parse a bech32 address
    pub fn parse(address: &str) -> Result<Self> {
        let (_, bytes) = bech32_decode(address)?;

        Ok(Self {
            address: address.to_string(),
            bytes,
        })
    }
}

/// Cosmos transaction signer
pub struct CosmosSigner;

impl CosmosSigner {
    /// Sign a Cosmos `SIGN_MODE_DIRECT` transaction.
    ///
    /// # Fail-closed: not implemented
    ///
    /// On-chain `SIGN_MODE_DIRECT` verification requires the signature to be
    /// computed over the **protobuf** encoding of `cosmos.tx.v1beta1.SignDoc`,
    /// whose `body_bytes` and `auth_info_bytes` are themselves the protobuf
    /// encodings of `TxBody` / `AuthInfo` (and every contained `Any` message).
    ///
    /// This crate currently models `TxBody`/`AuthInfo`/messages as JSON
    /// (`serde_json`), not protobuf. Signing those JSON bytes produces a
    /// signature that *looks* valid (correct length, verifies against the same
    /// JSON locally) but that **no Cosmos chain will ever accept**, because the
    /// validator recomputes the sign-bytes from protobuf. Silently emitting
    /// such a signature is a fund-loss footgun, so this path is deliberately
    /// **fail-closed** until canonical protobuf encoding is implemented
    /// (GATE, HIGH #9).
    ///
    /// Use [`CosmosSigner::sign_direct_protobuf`] if you can supply the
    /// canonical protobuf `body_bytes` / `auth_info_bytes` yourself; that path
    /// builds the protobuf `SignDoc` wrapper correctly.
    pub fn sign(_private_key: &[u8], _sign_doc: &super::SignDoc) -> Result<Vec<u8>> {
        Err(BlockchainError::UnsupportedOperation(
            "Cosmos SIGN_MODE_DIRECT protobuf encoding is not implemented; \
             signing the JSON SignDoc would produce a signature that never \
             verifies on-chain. Use CosmosSigner::sign_direct_protobuf with \
             canonical protobuf body_bytes/auth_info_bytes instead."
                .to_string(),
        ))
    }

    /// Sign a `SIGN_MODE_DIRECT` transaction where the caller has already
    /// produced the canonical **protobuf** `body_bytes` and `auth_info_bytes`.
    ///
    /// The sign-bytes are the protobuf encoding of `cosmos.tx.v1beta1.SignDoc`
    /// (see [`super::SignDoc::to_direct_sign_bytes`]); the signature is
    /// `secp256k1(SHA256(sign_bytes))`. This wrapper encoding is canonical and
    /// interoperable; correctness of the result depends on the caller passing
    /// genuine protobuf component bytes.
    pub fn sign_direct_protobuf(private_key: &[u8], sign_doc: &super::SignDoc) -> Result<Vec<u8>> {
        let sign_bytes = sign_doc.to_direct_sign_bytes();
        let hash = Sha256::digest(&sign_bytes);
        sign_secp256k1(private_key, &hash)
    }

    /// Sign an arbitrary message (ADR-036).
    ///
    /// ADR-036 is an *off-chain* arbitrary-data signing standard, so the JSON
    /// representation used here is self-consistent for the local
    /// signer/verifier and is not subject to on-chain protobuf verification.
    pub fn sign_arbitrary(
        private_key: &[u8],
        message: &[u8],
        signer_address: &str,
    ) -> Result<Vec<u8>> {
        // ADR-036 wrapped message (off-chain; JSON is acceptable here).
        let msg_sign_data = MsgSignData {
            signer: signer_address.to_string(),
            data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, message),
        };
        let sign_bytes = serde_json::to_vec(&msg_sign_data)
            .map_err(|e| BlockchainError::SerializationError(e.to_string()))?;
        let hash = Sha256::digest(&sign_bytes);
        sign_secp256k1(private_key, &hash)
    }

    /// Verify a signature
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        // SHA256 hash
        let hash = Sha256::digest(message);

        // Verify with secp256k1
        verify_secp256k1(public_key, &hash, signature)
    }
}

/// Sign with secp256k1
fn sign_secp256k1(private_key: &[u8], message_hash: &[u8]) -> Result<Vec<u8>> {
    use k256::ecdsa::{signature::Signer, Signature, SigningKey};

    if private_key.len() != 32 {
        return Err(BlockchainError::InvalidPrivateKey(
            "Private key must be 32 bytes".to_string(),
        ));
    }

    let signing_key = SigningKey::from_bytes(private_key.into())
        .map_err(|e| BlockchainError::InvalidPrivateKey(e.to_string()))?;

    let signature: Signature = signing_key.sign(message_hash);

    Ok(signature.to_bytes().to_vec())
}

/// Verify with secp256k1
fn verify_secp256k1(public_key: &[u8], message_hash: &[u8], signature: &[u8]) -> Result<bool> {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| BlockchainError::InvalidPublicKey(e.to_string()))?;

    let signature = Signature::from_slice(signature)
        .map_err(|e| BlockchainError::InvalidSignature(e.to_string()))?;

    Ok(verifying_key.verify(message_hash, &signature).is_ok())
}

/// Bech32 encode bytes with a prefix
fn bech32_encode(prefix: &str, data: &[u8]) -> Result<String> {
    use bech32::{Bech32, Hrp};

    let hrp = Hrp::parse(prefix)
        .map_err(|e| BlockchainError::InvalidAddress(format!("Invalid prefix: {}", e)))?;

    bech32::encode::<Bech32>(hrp, data)
        .map_err(|e| BlockchainError::InvalidAddress(format!("Bech32 encode error: {}", e)))
}

/// Bech32 decode an address
fn bech32_decode(address: &str) -> Result<(String, Vec<u8>)> {
    let (hrp, data) = bech32::decode(address)
        .map_err(|e| BlockchainError::InvalidAddress(format!("Bech32 decode error: {}", e)))?;

    Ok((hrp.to_string(), data))
}

/// ADR-036 MsgSignData
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MsgSignData {
    pub signer: String,
    pub data: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bech32_roundtrip() {
        let bytes = [1u8; 20];
        let encoded = bech32_encode("cosmos", &bytes).unwrap();
        assert!(encoded.starts_with("cosmos1"));

        let (prefix, decoded) = bech32_decode(&encoded).unwrap();
        assert_eq!(prefix, "cosmos");
        assert_eq!(decoded, bytes);
    }

    /// HASH160 KAT pinned against an independent reference computation
    /// (pure-Python secp256k1 + RIPEMD160(SHA256) + BIP-0173 bech32).
    ///
    /// The first vector uses the secp256k1 generator point as the public key
    /// (private key = 1). Its compressed encoding is `02 || Gx`, and the
    /// resulting HASH160 is `751e76e8199196d454941c45d1b3a323f1433bd6` — the
    /// canonical BIP-0173 witness-program example — which bech32-encodes under
    /// the `cosmos` HRP to the address below.
    ///
    /// Previously the address was `SHA256(pubkey)[..20]` "for simplicity",
    /// which produces an entirely different, unrecognised address (HIGH #5,
    /// fund loss).
    #[test]
    fn test_cosmos_address_hash160_kat() {
        // priv = 1 -> compressed pubkey = 02 || Gx
        let pubkey =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let addr = CosmosAddress::from_public_key(&pubkey, "cosmos").unwrap();
        assert_eq!(addr, "cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c");

        // HASH160 itself must match the canonical BIP-0173 witness program.
        let h160 = CosmosAddress::hash160_from_public_key(&pubkey).unwrap();
        assert_eq!(
            hex::encode(h160),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );

        // priv = 0x42
        let pubkey2 =
            hex::decode("03079264c4b4bfcd7fe3a7b7b92b6c439f3a5b3abcd29189bf7b54d781ff03d722")
                .unwrap();
        let addr2 = CosmosAddress::from_public_key(&pubkey2, "cosmos").unwrap();
        assert_eq!(addr2, "cosmos1vl47a9arch6ac9pqn9u3su5rlr26yv0rmp7dtm");
    }

    /// The old buggy SHA256[..20] derivation must NOT reproduce the canonical
    /// address — guards against a regression to the broken scheme.
    #[test]
    fn test_cosmos_address_not_sha256_truncation() {
        let pubkey =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let sha_trunc = bech32_encode("cosmos", &Sha256::digest(&pubkey)[..20]).unwrap();
        let correct = CosmosAddress::from_public_key(&pubkey, "cosmos").unwrap();
        assert_ne!(sha_trunc, correct);
    }

    /// An uncompressed (65-byte) key must be re-compressed before hashing, so it
    /// yields the SAME address as the equivalent compressed key.
    #[test]
    fn test_cosmos_address_uncompressed_matches_compressed() {
        use k256::ecdsa::SigningKey;
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 0x42;
        let sk = SigningKey::from_bytes((&sk_bytes).into()).unwrap();
        let vk = sk.verifying_key();
        let compressed = vk.to_encoded_point(true).as_bytes().to_vec();
        let uncompressed = vk.to_encoded_point(false).as_bytes().to_vec();
        assert_eq!(compressed.len(), 33);
        assert_eq!(uncompressed.len(), 65);

        let a_c = CosmosAddress::from_public_key(&compressed, "cosmos").unwrap();
        let a_u = CosmosAddress::from_public_key(&uncompressed, "cosmos").unwrap();
        assert_eq!(a_c, a_u);
        assert_eq!(a_c, "cosmos1vl47a9arch6ac9pqn9u3su5rlr26yv0rmp7dtm");
    }

    /// SIGN_MODE_DIRECT over a JSON SignDoc is fail-closed (GATE, HIGH #9):
    /// the legacy `sign` path must return an explicit error rather than emit a
    /// signature that never verifies on-chain.
    #[test]
    fn test_sign_direct_fail_closed() {
        let key = [0x11u8; 32];
        let doc = super::super::SignDoc {
            body_bytes: vec![1, 2, 3],
            auth_info_bytes: vec![4, 5],
            chain_id: "cosmoshub-4".to_string(),
            account_number: 1,
        };
        assert!(matches!(
            CosmosSigner::sign(&key, &doc),
            Err(BlockchainError::UnsupportedOperation(_))
        ));
    }

    /// The explicit protobuf-wrapper signing path produces a signature that
    /// verifies (round-trip) over the canonical protobuf SignDoc bytes, and a
    /// modified SignDoc does NOT verify against it (negative test).
    #[test]
    fn test_sign_direct_protobuf_round_trip() {
        use k256::ecdsa::SigningKey;
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 0x42;
        let sk = SigningKey::from_bytes((&sk_bytes).into()).unwrap();
        let pubkey = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let doc = super::super::SignDoc {
            body_bytes: vec![0x01, 0x02],
            auth_info_bytes: vec![0x03],
            chain_id: "cosmoshub-4".to_string(),
            account_number: 1,
        };
        let sig = CosmosSigner::sign_direct_protobuf(&sk_bytes, &doc).unwrap();

        let sign_bytes = doc.to_direct_sign_bytes();
        assert!(CosmosSigner::verify(&pubkey, &sign_bytes, &sig).unwrap());

        let doc2 = super::super::SignDoc {
            account_number: 2,
            ..doc.clone()
        };
        assert!(!CosmosSigner::verify(&pubkey, &doc2.to_direct_sign_bytes(), &sig).unwrap());
    }
}
