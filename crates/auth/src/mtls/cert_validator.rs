use crate::error::{AuthError, Result};
use chrono::Utc;
use lru::LruCache;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use x509_parser::prelude::*;

/// Maximum lifetime of a cached positive validation result.
///
/// This is deliberately decoupled from the certificate's own `not_after`
/// (which may be years in the future). Capping the cache TTL to a short window
/// bounds how long a freshly-revoked certificate could remain authenticated via
/// the fast path *even if* the revocation-list recheck were ever bypassed. The
/// fast path also rechecks the live revocation list on every hit, so revocation
/// takes effect immediately; this TTL is defense-in-depth.
const CACHE_ENTRY_TTL: Duration = Duration::from_secs(300);

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
    /// Certificate serial number (hex, lowercase) — used to evict cache entries
    /// when the corresponding serial is added to the revocation list.
    pub serial: String,
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

        // Check cache first for fast path. Clone the cached entry out so we can
        // release the cache lock before consulting the revocation list, avoiding
        // any lock-ordering coupling between the two mutexes.
        let cached = self.validation_cache.lock().get(&fingerprint).cloned();
        if let Some(cached) = cached {
            let now = Utc::now();
            // A cached positive result is only honored when ALL of the following hold:
            //   1. the certificate has not naturally expired,
            //   2. the cache entry itself is within its short TTL (independent of
            //      the cert's own not_after, which may be years out), and
            //   3. the certificate's serial is NOT currently revoked.
            // The revocation check reads the *live* revocation list on every hit
            // rather than trusting the (possibly stale) snapshot captured at
            // validation time, so revoke_certificate() takes effect immediately.
            let cache_age = now.signed_duration_since(cached.validated_at);
            let within_ttl = cache_age >= chrono::Duration::zero()
                && cache_age
                    < chrono::Duration::from_std(CACHE_ENTRY_TTL).unwrap_or(chrono::Duration::MAX);
            let revoked = self.is_revoked(&cached.serial)?;

            if now < cached.expires_at && within_ttl && !revoked {
                metrics::counter!("auth.cert_validation.cache_hit").increment(1);
                return Ok(ParsedCertificate {
                    der: client_cert_der,
                });
            }
            // Cache entry expired, aged out, or revoked: fall through to full
            // validation (which re-checks revocation and will reject if revoked).
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
                .unwrap_or_else(Utc::now);

        Ok(ValidationResult {
            fingerprint,
            serial,
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

    /// Add a certificate to the revocation list.
    ///
    /// This both records the serial in the revocation list (consulted on every
    /// validation, including the cache fast path) and immediately evicts any
    /// cached positive validation results for that serial, so a revoked
    /// certificate cannot continue to authenticate via a stale cache entry.
    pub fn revoke_certificate(&self, serial_number: &str) {
        self.revocation_list
            .lock()
            .insert(serial_number.to_string());

        // Evict any cached validation results matching this serial so the next
        // validate() for that cert takes the slow path and is rejected.
        {
            let mut cache = self.validation_cache.lock();
            let to_evict: Vec<CertFingerprint> = cache
                .iter()
                .filter(|(_, result)| result.serial == serial_number)
                .map(|(fp, _)| fp.clone())
                .collect();
            for fp in to_evict {
                cache.pop(&fp);
            }
        }

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

        // Verify the actual cryptographic signature of the certificate
        // Extract the signature algorithm, TBS data, and CA public key
        let sig_alg = &cert.signature_algorithm;
        let tbs_data = cert.tbs_certificate.as_ref();
        let sig_value = cert.signature_value.as_ref();

        // Get the CA's public key bytes.
        //
        // `ring`'s `UnparsedPublicKey` expects the *public key* itself, not the
        // surrounding SubjectPublicKeyInfo:
        //   - ECDSA: the uncompressed EC point (0x04 || X || Y)
        //   - RSA:   the DER-encoded PKCS#1 RSAPublicKey
        // In an X.509 SPKI both of these live in the `subjectPublicKey` BIT
        // STRING contents. Using `ca_spki.raw` (the whole SPKI SEQUENCE,
        // including the AlgorithmIdentifier) makes ring reject every signature.
        let ca_spki = ca_cert.public_key();
        let ca_pubkey_der: &[u8] = &ca_spki.subject_public_key.data;

        // Map X.509 signature algorithm OID to ring algorithm
        let oid = sig_alg.algorithm.to_id_string();
        let ring_alg: &dyn ring::signature::VerificationAlgorithm = match oid.as_str() {
            // RSA PKCS1 with SHA-256
            "1.2.840.113549.1.1.11" => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            // RSA PKCS1 with SHA-384
            "1.2.840.113549.1.1.12" => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
            // RSA PKCS1 with SHA-512
            "1.2.840.113549.1.1.13" => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
            // ECDSA with SHA-256
            "1.2.840.10045.4.3.2" => &ring::signature::ECDSA_P256_SHA256_ASN1,
            // ECDSA with SHA-384
            "1.2.840.10045.4.3.3" => &ring::signature::ECDSA_P384_SHA384_ASN1,
            // RSA PKCS1 with SHA-1 — explicitly rejected. SHA-1 is broken for
            // signatures (practical collision attacks), and this OID was previously
            // mis-mapped to the SHA-256 verifier, which would verify a SHA-1-signed
            // certificate against the wrong digest. Refuse SHA-1-signed certs.
            "1.2.840.113549.1.1.5" => {
                return Err(AuthError::CertificateValidationFailed(
                    "SHA-1 signed certificates are not supported (insecure)".to_string(),
                ));
            }
            other => {
                return Err(AuthError::CertificateValidationFailed(format!(
                    "Unsupported signature algorithm OID: {}",
                    other
                )));
            }
        };

        let public_key = ring::signature::UnparsedPublicKey::new(ring_alg, ca_pubkey_der);
        public_key.verify(tbs_data, sig_value).map_err(|_| {
            AuthError::CertificateValidationFailed(
                "Certificate signature verification failed".to_string(),
            )
        })?;

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
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair};

    // A self-signed CA together with the material needed to sign client certs.
    struct TestCa {
        params: CertificateParams,
        key: KeyPair,
        pem: Vec<u8>,
    }

    fn generate_test_ca() -> TestCa {
        let mut ca_params = CertificateParams::default();
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem().into_bytes();

        TestCa {
            params: ca_params,
            key: ca_key,
            pem: ca_pem,
        }
    }

    fn generate_client_cert(ca: &TestCa, common_name: &str) -> Vec<u8> {
        let mut client_params = CertificateParams::default();
        client_params.distinguished_name = DistinguishedName::new();
        client_params
            .distinguished_name
            .push(DnType::CommonName, common_name);

        let client_key = KeyPair::generate().unwrap();
        let issuer = Issuer::from_params(&ca.params, &ca.key);
        let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();
        client_cert.pem().into_bytes()
    }

    fn pem_to_der(pem_bytes: &[u8]) -> Vec<u8> {
        let pem = ::pem::parse(std::str::from_utf8(pem_bytes).unwrap()).unwrap();
        pem.contents().to_vec()
    }

    /// Regression test for HIGH #9.
    ///
    /// Before the fix, a successful validation cached `is_revoked: false` with
    /// `expires_at` set to the certificate's own `not_after` (potentially years
    /// out), and the fast path returned success on a cache hit without ever
    /// consulting the live revocation list. As a result, calling
    /// `revoke_certificate()` had no effect until the certificate expired
    /// naturally — a revoked cert kept authenticating.
    ///
    /// After the fix, `revoke_certificate()` evicts the cache entry AND the fast
    /// path rechecks the live revocation list, so the very next `validate()`
    /// must fail with `CertificateRevoked`. This test would FAIL before the fix
    /// (the second validate would return Ok) and PASSES after.
    #[test]
    fn revoked_certificate_is_rejected_promptly_even_after_caching() {
        let ca = generate_test_ca();
        let validator = CertificateValidator::new(&ca.pem).unwrap();
        let client_pem = generate_client_cert(&ca, "revoke-me");

        // 1. First validation succeeds and populates the positive cache entry.
        validator
            .validate(&client_pem)
            .expect("freshly issued cert should validate");

        // 2. A second validation also succeeds via the fast (cached) path.
        validator
            .validate(&client_pem)
            .expect("cached cert should still validate before revocation");

        // 3. Revoke the certificate by its serial (the same value callers obtain
        //    via get_serial_number()).
        let client_der = pem_to_der(&client_pem);
        let serial = CertificateValidator::get_serial_number(&client_der).unwrap();
        validator.revoke_certificate(&serial);

        // 4. The next validation MUST be rejected immediately — not deferred to
        //    natural expiry. This is the crux of the regression.
        let result = validator.validate(&client_pem);
        assert!(
            matches!(result, Err(AuthError::CertificateRevoked)),
            "revoked certificate must be rejected promptly, got: {:?}",
            result.map(|_| "Ok"),
        );

        // 5. Repeated attempts stay rejected (no flapping back to the cache).
        let result2 = validator.validate(&client_pem);
        assert!(
            matches!(result2, Err(AuthError::CertificateRevoked)),
            "revoked certificate must stay rejected on subsequent calls"
        );
    }

    /// A non-revoked, valid certificate continues to validate (guards against
    /// the fix over-rejecting). Confirms the fast path still works.
    #[test]
    fn valid_certificate_still_validates_through_cache() {
        let ca = generate_test_ca();
        let validator = CertificateValidator::new(&ca.pem).unwrap();
        let client_pem = generate_client_cert(&ca, "keep-me");

        validator.validate(&client_pem).expect("first validate");
        validator
            .validate(&client_pem)
            .expect("cached validate should succeed for a non-revoked cert");

        // Revoking a DIFFERENT serial must not affect this cert.
        validator.revoke_certificate("deadbeefcafe");
        validator
            .validate(&client_pem)
            .expect("unrelated revocation must not reject this cert");
    }

    #[test]
    fn test_extract_serial_number() {
        let ca = generate_test_ca();
        let client_pem = generate_client_cert(&ca, "serial-test");
        let der = pem_to_der(&client_pem);
        let serial = CertificateValidator::get_serial_number(&der).unwrap();
        assert!(!serial.is_empty(), "serial number must be extractable");
    }
}
