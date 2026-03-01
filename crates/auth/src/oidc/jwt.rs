//! JWT validation

use super::claims::OidcClaims;
use super::provider::OidcProviderConfig;
use super::token_cache::JwksCache;
use std::sync::Arc;
use thiserror::Error;

/// JWT validation errors
#[derive(Debug, Error)]
pub enum JwtValidationError {
    /// Token format error
    #[error("Invalid token format: {0}")]
    InvalidFormat(String),
    /// Token expired
    #[error("Token expired")]
    Expired,
    /// Token not yet valid
    #[error("Token not yet valid")]
    NotYetValid,
    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,
    /// Invalid issuer
    #[error("Invalid issuer: expected {expected}, got {actual}")]
    InvalidIssuer { expected: String, actual: String },
    /// Invalid audience
    #[error("Invalid audience")]
    InvalidAudience,
    /// Missing required claim
    #[error("Missing required claim: {0}")]
    MissingClaim(String),
    /// Key not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    /// Decoding error
    #[error("Decoding error: {0}")]
    DecodingError(String),
    /// JWKS error
    #[error("JWKS error: {0}")]
    JwksError(String),
}

/// JWT validator
pub struct JwtValidator {
    /// Provider configuration
    config: OidcProviderConfig,
    /// JWKS cache
    jwks_cache: Arc<JwksCache>,
}

impl JwtValidator {
    /// Create a new JWT validator
    pub fn new(config: OidcProviderConfig, jwks_cache: Arc<JwksCache>) -> Self {
        Self { config, jwks_cache }
    }

    /// Validate a JWT token
    pub async fn validate(&self, token: &str) -> Result<OidcClaims, JwtValidationError> {
        // Split token into parts
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtValidationError::InvalidFormat(
                "Token must have 3 parts".to_string(),
            ));
        }

        // Decode header
        let header = self.decode_header(parts[0])?;

        // Get key ID from header
        let kid = header.get("kid").and_then(|v| v.as_str()).ok_or_else(|| {
            JwtValidationError::InvalidFormat("Missing kid in header".to_string())
        })?;

        // Get algorithm
        let alg = header
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("RS256");

        // Fetch JWKS and get key
        let jwks_uri = self
            .config
            .get_jwks_uri()
            .ok_or_else(|| JwtValidationError::JwksError("No JWKS URI configured".to_string()))?;

        let jwk = self
            .jwks_cache
            .get_key(jwks_uri, kid)
            .await
            .map_err(|e| JwtValidationError::JwksError(e.to_string()))?
            .ok_or_else(|| JwtValidationError::KeyNotFound(kid.to_string()))?;

        // Verify signature
        self.verify_signature(parts[0], parts[1], parts[2], &jwk, alg)?;

        // Decode payload
        let claims = self.decode_payload(parts[1])?;

        // Validate claims
        self.validate_claims(&claims)?;

        Ok(claims)
    }

    /// Decode the JWT header
    fn decode_header(&self, header: &str) -> Result<serde_json::Value, JwtValidationError> {
        let decoded = base64_url_decode(header)
            .map_err(|e| JwtValidationError::InvalidFormat(e.to_string()))?;
        serde_json::from_slice(&decoded)
            .map_err(|e| JwtValidationError::InvalidFormat(e.to_string()))
    }

    /// Decode the JWT payload
    fn decode_payload(&self, payload: &str) -> Result<OidcClaims, JwtValidationError> {
        let decoded = base64_url_decode(payload)
            .map_err(|e| JwtValidationError::InvalidFormat(e.to_string()))?;
        serde_json::from_slice(&decoded)
            .map_err(|e| JwtValidationError::DecodingError(e.to_string()))
    }

    /// Verify the JWT signature
    fn verify_signature(
        &self,
        header: &str,
        payload: &str,
        signature: &str,
        jwk: &serde_json::Value,
        alg: &str,
    ) -> Result<(), JwtValidationError> {
        let message = format!("{}.{}", header, payload);
        let sig_bytes = base64_url_decode(signature)
            .map_err(|e| JwtValidationError::InvalidFormat(e.to_string()))?;

        // Get key type
        let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("RSA");

        match (alg, kty) {
            ("RS256", "RSA") | ("RS384", "RSA") | ("RS512", "RSA") => {
                self.verify_rsa_signature(&message, &sig_bytes, jwk, alg)
            }
            ("ES256", "EC") | ("ES384", "EC") | ("ES512", "EC") => {
                self.verify_ec_signature(&message, &sig_bytes, jwk, alg)
            }
            _ => Err(JwtValidationError::InvalidFormat(format!(
                "Unsupported algorithm: {} with key type: {}",
                alg, kty
            ))),
        }
    }

    /// Verify RSA signature using the `rsa` crate
    fn verify_rsa_signature(
        &self,
        message: &str,
        signature: &[u8],
        jwk: &serde_json::Value,
        alg: &str,
    ) -> Result<(), JwtValidationError> {
        use rsa::pkcs1v15::VerifyingKey as RsaVerifyingKey;
        use rsa::signature::Verifier;
        use rsa::BigUint as RsaBigUint;

        // Extract n and e from the JWK
        let n_b64 = jwk.get("n").and_then(|v| v.as_str()).ok_or_else(|| {
            JwtValidationError::InvalidFormat("Missing 'n' in RSA JWK".to_string())
        })?;
        let e_b64 = jwk.get("e").and_then(|v| v.as_str()).ok_or_else(|| {
            JwtValidationError::InvalidFormat("Missing 'e' in RSA JWK".to_string())
        })?;

        let n_bytes = base64_url_decode(n_b64).map_err(|e| {
            JwtValidationError::DecodingError(format!("Failed to decode 'n': {}", e))
        })?;
        let e_bytes = base64_url_decode(e_b64).map_err(|e| {
            JwtValidationError::DecodingError(format!("Failed to decode 'e': {}", e))
        })?;

        let n = RsaBigUint::from_bytes_be(&n_bytes);
        let e = RsaBigUint::from_bytes_be(&e_bytes);

        let public_key = rsa::RsaPublicKey::new(n, e).map_err(|e| {
            JwtValidationError::DecodingError(format!("Invalid RSA public key: {}", e))
        })?;

        match alg {
            "RS256" => {
                let verifying_key = RsaVerifyingKey::<sha2::Sha256>::new(public_key);
                let sig = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|_| JwtValidationError::InvalidSignature)?;
                verifying_key
                    .verify(message.as_bytes(), &sig)
                    .map_err(|_| JwtValidationError::InvalidSignature)
            }
            "RS384" => {
                let verifying_key = RsaVerifyingKey::<sha2::Sha384>::new(public_key);
                let sig = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|_| JwtValidationError::InvalidSignature)?;
                verifying_key
                    .verify(message.as_bytes(), &sig)
                    .map_err(|_| JwtValidationError::InvalidSignature)
            }
            "RS512" => {
                let verifying_key = RsaVerifyingKey::<sha2::Sha512>::new(public_key);
                let sig = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|_| JwtValidationError::InvalidSignature)?;
                verifying_key
                    .verify(message.as_bytes(), &sig)
                    .map_err(|_| JwtValidationError::InvalidSignature)
            }
            _ => Err(JwtValidationError::InvalidFormat(format!(
                "Unsupported RSA algorithm: {}",
                alg
            ))),
        }
    }

    /// Verify EC signature using `p256` / `p384` crates
    fn verify_ec_signature(
        &self,
        message: &str,
        signature: &[u8],
        jwk: &serde_json::Value,
        alg: &str,
    ) -> Result<(), JwtValidationError> {
        // Extract x and y from JWK
        let x_b64 = jwk.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
            JwtValidationError::InvalidFormat("Missing 'x' in EC JWK".to_string())
        })?;
        let y_b64 = jwk.get("y").and_then(|v| v.as_str()).ok_or_else(|| {
            JwtValidationError::InvalidFormat("Missing 'y' in EC JWK".to_string())
        })?;

        let x_bytes = base64_url_decode(x_b64).map_err(|e| {
            JwtValidationError::DecodingError(format!("Failed to decode 'x': {}", e))
        })?;
        let y_bytes = base64_url_decode(y_b64).map_err(|e| {
            JwtValidationError::DecodingError(format!("Failed to decode 'y': {}", e))
        })?;

        match alg {
            "ES256" => {
                use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                use p256::EncodedPoint;

                let point = EncodedPoint::from_affine_coordinates(
                    p256::FieldBytes::from_slice(&x_bytes),
                    p256::FieldBytes::from_slice(&y_bytes),
                    false,
                );
                let verifying_key = VerifyingKey::from_encoded_point(&point).map_err(|e| {
                    JwtValidationError::DecodingError(format!("Invalid EC P-256 key: {}", e))
                })?;

                // JWT uses raw R||S format (not DER) for EC signatures
                let sig = Signature::from_slice(signature)
                    .map_err(|_| JwtValidationError::InvalidSignature)?;
                verifying_key
                    .verify(message.as_bytes(), &sig)
                    .map_err(|_| JwtValidationError::InvalidSignature)
            }
            "ES384" => {
                use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                use p384::EncodedPoint;

                let point = EncodedPoint::from_affine_coordinates(
                    p384::FieldBytes::from_slice(&x_bytes),
                    p384::FieldBytes::from_slice(&y_bytes),
                    false,
                );
                let verifying_key = VerifyingKey::from_encoded_point(&point).map_err(|e| {
                    JwtValidationError::DecodingError(format!("Invalid EC P-384 key: {}", e))
                })?;

                let sig = Signature::from_slice(signature)
                    .map_err(|_| JwtValidationError::InvalidSignature)?;
                verifying_key
                    .verify(message.as_bytes(), &sig)
                    .map_err(|_| JwtValidationError::InvalidSignature)
            }
            _ => Err(JwtValidationError::InvalidFormat(format!(
                "Unsupported EC algorithm: {}",
                alg
            ))),
        }
    }

    /// Validate claims
    fn validate_claims(&self, claims: &OidcClaims) -> Result<(), JwtValidationError> {
        let now = chrono::Utc::now().timestamp();
        let clock_skew = self.config.clock_skew_seconds as i64;

        // Check expiration
        if self.config.validate_exp {
            if let Some(exp) = claims.exp {
                if now > exp + clock_skew {
                    return Err(JwtValidationError::Expired);
                }
            }
        }

        // Check not before
        if let Some(nbf) = claims.nbf {
            if now < nbf - clock_skew {
                return Err(JwtValidationError::NotYetValid);
            }
        }

        // Check issuer
        if let Some(iss) = &claims.iss {
            let expected = self.config.issuer.trim_end_matches('/');
            let actual = iss.trim_end_matches('/');
            if expected != actual {
                return Err(JwtValidationError::InvalidIssuer {
                    expected: expected.to_string(),
                    actual: actual.to_string(),
                });
            }
        }

        // Check audience
        let token_audiences = claims.audiences();
        let has_valid_audience = self
            .config
            .audiences
            .iter()
            .any(|expected| token_audiences.contains(expected));
        if !has_valid_audience {
            return Err(JwtValidationError::InvalidAudience);
        }

        // Check required claims
        for required in &self.config.required_claims {
            match required.as_str() {
                "sub" if claims.sub.is_empty() => {
                    return Err(JwtValidationError::MissingClaim("sub".to_string()));
                }
                "email" if claims.email.is_none() => {
                    return Err(JwtValidationError::MissingClaim("email".to_string()));
                }
                claim => {
                    if claims.get_claim(claim).is_none()
                        && ![
                            "sub", "iss", "aud", "exp", "iat", "nbf", "jti", "email", "name",
                        ]
                        .contains(&claim)
                    {
                        return Err(JwtValidationError::MissingClaim(claim.to_string()));
                    }
                }
            }
        }

        Ok(())
    }
}

/// Base64 URL decode
fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, DecodeError, Engine};

    // Add padding if needed
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };

    URL_SAFE_NO_PAD
        .decode(&padded)
        .or_else(|_: DecodeError| URL_SAFE_NO_PAD.decode(input))
        .map_err(|e: DecodeError| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_url_decode() {
        let encoded = "SGVsbG8gV29ybGQ";
        let decoded = base64_url_decode(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello World");
    }
}
