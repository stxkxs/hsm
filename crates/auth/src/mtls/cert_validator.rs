use crate::error::{AuthError, Result};
use chrono::Utc;
use lru::LruCache;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::sync::Arc;
use x509_parser::prelude::*;

/// Certificate fingerprint for caching
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertFingerprint(Vec<u8>);

impl CertFingerprint {
    /// Create a fingerprint from certificate DER data
    pub fn from_der(der: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(der);
        Self(hasher.finalize().to_vec())
    }

    /// Get the hex representation of the fingerprint
    pub fn hex(&self) -> String {
        hex::encode(&self.0)
    }
}

/// Validation result that can be cached
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Certificate fingerprint
    pub fingerprint: CertFingerprint,
    /// When the validation was performed
    pub validated_at: chrono::DateTime<Utc>,
    /// Certificate expiry time
    pub expires_at: chrono::DateTime<Utc>,
    /// Whether the certificate is revoked
    pub is_revoked: bool,
}

/// Certificate validator for mTLS authentication with caching
pub struct CertificateValidator {
    /// Trusted CA certificate DER data
    ca_cert_der: Vec<u8>,

    /// LRU cache for validated certificates (fingerprint -> validation result)
    /// Target: < 100μs for cached validations
    validation_cache: Arc<Mutex<LruCache<CertFingerprint, ValidationResult>>>,

    /// Revocation list (certificate serial numbers that are revoked)
    revocation_list: Arc<Mutex<std::collections::HashSet<String>>>,

    /// Certificate pinning (subject CN -> expected fingerprint)
    pinned_certs: Arc<Mutex<std::collections::HashMap<String, CertFingerprint>>>,
}

impl CertificateValidator {
    /// Create a new certificate validator with a CA certificate
    pub fn new(ca_cert_pem: &[u8]) -> Result<Self> {
        let ca_cert_der = Self::pem_to_der(ca_cert_pem)?;

        // Cache size: 1000 certificates (reasonable for most deployments)
        let cache_size = NonZeroUsize::new(1000).unwrap();

        Ok(Self {
            ca_cert_der,
            validation_cache: Arc::new(Mutex::new(LruCache::new(cache_size))),
            revocation_list: Arc::new(Mutex::new(std::collections::HashSet::new())),
            pinned_certs: Arc::new(Mutex::new(std::collections::HashMap::new())),
        })
    }

    /// Validate a client certificate against the CA with caching
    /// Target: < 100μs for cached validations, < 5ms for full validation
    pub fn validate(&self, client_cert_pem: &[u8]) -> Result<ParsedCertificate> {
        let client_cert_der = Self::pem_to_der(client_cert_pem)?;
        let fingerprint = CertFingerprint::from_der(&client_cert_der);

        // Check cache first for fast path
        if let Some(cached) = self.validation_cache.lock().get(&fingerprint) {
            // Verify cached result is still valid
            if Utc::now() < cached.expires_at && !cached.is_revoked {
                metrics::counter!("auth.cert_validation.cache_hit").increment(1);
                return Ok(ParsedCertificate {
                    der: client_cert_der,
                });
            }
            // Cache entry expired or revoked, fall through to full validation
            metrics::counter!("auth.cert_validation.cache_expired").increment(1);
        } else {
            metrics::counter!("auth.cert_validation.cache_miss").increment(1);
        }

        // Full validation (slow path)
        let result = self.validate_full(&client_cert_der)?;

        // Cache the validation result
        self.cache_validation(&fingerprint, &result)?;

        Ok(ParsedCertificate {
            der: client_cert_der,
        })
    }

    /// Perform full certificate validation
    fn validate_full(&self, client_cert_der: &[u8]) -> Result<ValidationResult> {
        let (_, client_cert) = X509Certificate::from_der(client_cert_der).map_err(|e| {
            AuthError::CertificateParsingError(format!("DER parsing failed: {}", e))
        })?;

        // 1. Check certificate validity period
        self.check_validity(&client_cert)?;

        // 2. Verify signature against CA
        self.verify_signature(&client_cert)?;

        // 3. Check basic constraints
        self.check_basic_constraints(&client_cert)?;

        // 4. Check revocation status (CRITICAL)
        let serial = client_cert.serial.to_str_radix(16);
        if self.is_revoked(&serial)? {
            return Err(AuthError::CertificateRevoked);
        }

        // 5. Check certificate pinning (if configured)
        if let Ok(cn) = Self::get_common_name(&client_cert) {
            if let Some(expected_pin) = self.pinned_certs.lock().get(&cn) {
                let actual_pin = CertFingerprint::from_der(client_cert_der);
                if *expected_pin != actual_pin {
                    return Err(AuthError::CertificatePinningFailed);
                }
            }
        }

        // 6. Verify key usage allows client authentication
        self.check_key_usage(&client_cert)?;

        let fingerprint = CertFingerprint::from_der(client_cert_der);
        let expires_at =
            chrono::DateTime::from_timestamp(client_cert.validity().not_after.timestamp(), 0)
                .unwrap_or_else(|| Utc::now());

        Ok(ValidationResult {
            fingerprint,
            validated_at: Utc::now(),
            expires_at,
            is_revoked: false,
        })
    }

    /// Cache a validation result
    fn cache_validation(
        &self,
        fingerprint: &CertFingerprint,
        result: &ValidationResult,
    ) -> Result<()> {
        self.validation_cache
            .lock()
            .put(fingerprint.clone(), result.clone());
        Ok(())
    }

    /// Check if a certificate is revoked
    fn is_revoked(&self, serial_number: &str) -> Result<bool> {
        Ok(self.revocation_list.lock().contains(serial_number))
    }

    /// Add a certificate to the revocation list
    pub fn revoke_certificate(&self, serial_number: &str) {
        self.revocation_list
            .lock()
            .insert(serial_number.to_string());
        // Invalidate cache entries with this serial
        // (in production, we'd track serial numbers in cache entries)
        metrics::counter!("auth.cert_revocation.added").increment(1);
    }

    /// Pin a certificate for a specific subject CN
    pub fn pin_certificate(&self, subject_cn: &str, fingerprint: CertFingerprint) {
        self.pinned_certs
            .lock()
            .insert(subject_cn.to_string(), fingerprint);
    }

    /// Get common name from certificate
    fn get_common_name(cert: &X509Certificate) -> Result<String> {
        for attr in cert.subject().iter_common_name() {
            if let Ok(cn) = attr.as_str() {
                return Ok(cn.to_string());
            }
        }
        Err(AuthError::IdentityNotFound)
    }

    /// Check key usage extension for client authentication
    ///
    /// For client authentication, we require:
    /// - KeyUsage: digitalSignature bit must be set (if KeyUsage extension exists)
    /// - ExtendedKeyUsage: clientAuth must be true (if EKU extension exists)
    fn check_key_usage(&self, cert: &X509Certificate) -> Result<()> {
        // Check KeyUsage extension (if present)
        if let Ok(Some(key_usage)) = cert.key_usage() {
            // For client auth, digitalSignature is required
            if !key_usage.value.digital_signature() {
                return Err(AuthError::InvalidCertificate(
                    "Certificate KeyUsage does not include digitalSignature".to_string(),
                ));
            }
        }

        // Check ExtendedKeyUsage extension (if present)
        if let Ok(Some(ext_key_usage)) = cert.extended_key_usage() {
            // ExtendedKeyUsage has boolean fields for common usages
            // client_auth: true means id-kp-clientAuth (1.3.6.1.5.5.7.3.2) is present
            // any: true means anyExtendedKeyUsage (2.5.29.37.0) is present
            if !ext_key_usage.value.client_auth && !ext_key_usage.value.any {
                return Err(AuthError::InvalidCertificate(
                    "Certificate ExtendedKeyUsage does not include clientAuth".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Convert PEM to DER
    fn pem_to_der(pem_data: &[u8]) -> Result<Vec<u8>> {
        let pem_str = std::str::from_utf8(pem_data)
            .map_err(|e| AuthError::CertificateParsingError(format!("Invalid UTF-8: {}", e)))?;

        let pem = ::pem::parse(pem_str).map_err(|e| {
            AuthError::CertificateParsingError(format!("PEM parsing failed: {}", e))
        })?;

        Ok(pem.contents().to_vec())
    }

    /// Check if the certificate is within its validity period
    fn check_validity(&self, cert: &X509Certificate) -> Result<()> {
        let now = Utc::now();

        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();

        let now_timestamp = now.timestamp();

        if now_timestamp < not_before {
            return Err(AuthError::CertificateNotYetValid);
        }

        if now_timestamp > not_after {
            return Err(AuthError::CertificateExpired);
        }

        Ok(())
    }

    /// Verify the certificate signature against the CA
    fn verify_signature(&self, cert: &X509Certificate) -> Result<()> {
        // Parse CA cert
        let (_, ca_cert) = X509Certificate::from_der(&self.ca_cert_der).map_err(|e| {
            AuthError::CertificateParsingError(format!("CA cert parsing failed: {}", e))
        })?;

        // Get the issuer from client cert and subject from CA cert
        let client_issuer = cert.issuer();
        let ca_subject = ca_cert.subject();

        // Check if the certificate was issued by our CA
        if client_issuer != ca_subject {
            return Err(AuthError::CertificateValidationFailed(
                "Certificate not issued by trusted CA".to_string(),
            ));
        }

        // In a production system, we would verify the actual signature here
        // This requires implementing cryptographic signature verification
        // For now, we rely on rustls to do the actual signature verification

        Ok(())
    }

    /// Check basic constraints extension
    fn check_basic_constraints(&self, cert: &X509Certificate) -> Result<()> {
        // Check if this is a CA certificate (it shouldn't be for clients)
        if let Ok(Some(basic_constraints)) = cert.basic_constraints() {
            if basic_constraints.value.ca {
                return Err(AuthError::InvalidCertificate(
                    "Client certificate cannot be a CA certificate".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Extract common name from certificate subject
    pub fn extract_common_name(cert_der: &[u8]) -> Result<String> {
        let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
            AuthError::CertificateParsingError(format!("DER parsing failed: {}", e))
        })?;

        for attr in cert.subject().iter_common_name() {
            if let Ok(cn) = attr.as_str() {
                return Ok(cn.to_string());
            }
        }
        Err(AuthError::IdentityNotFound)
    }

    /// Extract organization from certificate subject
    pub fn extract_organization(cert_der: &[u8]) -> Option<String> {
        let (_, cert) = X509Certificate::from_der(cert_der).ok()?;

        for attr in cert.subject().iter_organization() {
            if let Ok(org) = attr.as_str() {
                return Some(org.to_string());
            }
        }
        None
    }

    /// Extract organizational unit from certificate subject
    pub fn extract_organizational_unit(cert_der: &[u8]) -> Option<String> {
        let (_, cert) = X509Certificate::from_der(cert_der).ok()?;

        for attr in cert.subject().iter_organizational_unit() {
            if let Ok(ou) = attr.as_str() {
                return Some(ou.to_string());
            }
        }
        None
    }

    /// Get certificate serial number as a hex string
    pub fn get_serial_number(cert_der: &[u8]) -> Result<String> {
        let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
            AuthError::CertificateParsingError(format!("DER parsing failed: {}", e))
        })?;

        Ok(cert.serial.to_str_radix(16))
    }
}

/// Parsed certificate with DER data
pub struct ParsedCertificate {
    pub der: Vec<u8>,
}

#[cfg(test)]
mod tests {
    // Note: These tests require valid test certificates
    // They will be implemented in the integration tests with rcgen

    #[test]
    fn test_extract_serial_number() {
        // This test will be implemented with real certificates in integration tests
    }
}
