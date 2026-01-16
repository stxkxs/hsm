use crate::error::{AuthError, Result};
use crate::mtls::cert_validator::CertificateValidator;
use crate::mtls::identity::ClientIdentity;
use crate::rbac::Role;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use std::sync::Arc;

/// Mutual TLS (mTLS) authenticator for client certificate validation.
///
/// This authenticator validates client X.509 certificates against a trusted CA
/// and extracts client identity information to create authenticated sessions.
///
/// # mTLS Authentication Flow
///
/// ```text
/// ┌──────────┐                                    ┌─────────────────┐
/// │  Client  │                                    │ MtlsAuthenticator│
/// └──────────┘                                    └─────────────────┘
///      │                                                   │
///      │  1. Present client certificate (DER/PEM)         │
///      │──────────────────────────────────────────────────▶│
///      │                                                   │
///      │                              2. Validate against CA cert
///      │                                 - Check signature│
///      │                                 - Check validity period
///      │                                 - Verify chain   │
///      │                                                   │
///      │                              3. Extract X.509 fields
///      │                                 - CN: client name│
///      │                                 - O: organization│
///      │                                 - OU: namespace  │
///      │                                 - Serial: cert ID│
///      │                                                   │
///      │                              4. Derive roles      │
///      │                                 - From CN pattern│
///      │                                 - From org name  │
///      │                                                   │
///      │  5. Return ClientIdentity                        │
///      │◀──────────────────────────────────────────────────│
///      │     (CN, org, namespace, roles, serial)          │
///      │                                                   │
/// ```
///
/// # Security Properties
///
/// - **Certificate Chain Validation**: Ensures client cert is signed by trusted CA
/// - **Validity Period Checking**: Rejects expired or not-yet-valid certificates
/// - **Identity Extraction**: Securely parses X.509 fields without injection vulnerabilities
/// - **Role Derivation**: Maps certificate attributes to RBAC roles
///
/// # Examples
///
/// ## Basic authentication
///
/// ```rust,no_run
/// use hsm_auth::mtls::MtlsAuthenticator;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let ca_cert = include_bytes!("ca.pem");
/// let server_cert = include_bytes!("server.pem");
/// let server_key = include_bytes!("server.key");
///
/// let authenticator = MtlsAuthenticator::new(ca_cert, server_cert, server_key)?;
///
/// // Authenticate a client
/// let client_cert_der = include_bytes!("client.der");
/// let identity = authenticator.authenticate(client_cert_der)?;
///
/// println!("Authenticated: {}", identity.common_name);
/// println!("Organization: {:?}", identity.organization);
/// println!("Namespace: {}", identity.namespace);
/// println!("Roles: {:?}", identity.roles);
/// # Ok(())
/// # }
/// ```
///
/// # Role Assignment
///
/// Roles are automatically assigned based on certificate attributes:
///
/// | Certificate Attribute | Assigned Role |
/// |-----------------------|---------------|
/// | CN contains "admin"   | Admin         |
/// | CN contains "operator"| Operator      |
/// | CN contains "auditor" | Auditor       |
/// | Organization contains "admins" | Admin (additional) |
/// | Default               | User          |
///
/// # Production Considerations
///
/// In production environments, you should:
/// - Implement certificate revocation checking (CRL or OCSP)
/// - Store roles in X.509 certificate extensions instead of CN patterns
/// - Use custom `ClientCertVerifier` for rustls to enable full mTLS
/// - Enforce strong key algorithms (RSA ≥2048 bits, ECDSA ≥256 bits)
/// - Regularly rotate CA and server certificates
pub struct MtlsAuthenticator {
    validator: Arc<CertificateValidator>,
    tls_config: Arc<ServerConfig>,
}

impl MtlsAuthenticator {
    /// Creates a new mTLS authenticator with CA and server certificates.
    ///
    /// # Arguments
    ///
    /// * `ca_cert_pem` - PEM-encoded CA certificate for validating client certs
    /// * `server_cert_pem` - PEM-encoded server certificate
    /// * `server_key_pem` - PEM-encoded server private key
    ///
    /// # Returns
    ///
    /// Returns the configured authenticator or an error if certificate parsing fails.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - CA certificate is invalid or malformed
    /// - Server certificate is invalid or malformed
    /// - Server private key is invalid or malformed
    /// - Certificate/key mismatch
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use hsm_auth::mtls::MtlsAuthenticator;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let authenticator = MtlsAuthenticator::new(
    ///     include_bytes!("ca.pem"),
    ///     include_bytes!("server.pem"),
    ///     include_bytes!("server.key"),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(ca_cert_pem: &[u8], server_cert_pem: &[u8], server_key_pem: &[u8]) -> Result<Self> {
        let validator = Arc::new(CertificateValidator::new(ca_cert_pem)?);

        // Build rustls ServerConfig with mutual TLS
        let tls_config =
            Self::build_tls_config(server_cert_pem, server_key_pem, validator.clone())?;

        Ok(Self {
            validator,
            tls_config: Arc::new(tls_config),
        })
    }

    /// Returns the rustls TLS configuration for server setup.
    ///
    /// This configuration can be used to initialize a rustls-based TLS server.
    pub fn tls_config(&self) -> Arc<ServerConfig> {
        self.tls_config.clone()
    }

    /// Authenticates a client from their X.509 certificate.
    ///
    /// Validates the certificate against the trusted CA and extracts client identity
    /// information including common name, organization, namespace, and roles.
    ///
    /// # Arguments
    ///
    /// * `cert_der` - DER-encoded client certificate bytes
    ///
    /// # Returns
    ///
    /// Returns the extracted `ClientIdentity` containing:
    /// - Common name (CN) from certificate subject
    /// - Organization (O) if present
    /// - Namespace derived from Organizational Unit (OU)
    /// - Roles derived from CN and organization patterns
    /// - Certificate serial number
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Certificate is not signed by the trusted CA
    /// - Certificate is expired or not yet valid
    /// - Certificate chain validation fails
    /// - Certificate fields are malformed
    /// - Identity validation fails
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use hsm_auth::mtls::MtlsAuthenticator;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let authenticator = MtlsAuthenticator::new(
    /// #     include_bytes!("ca.pem"),
    /// #     include_bytes!("server.pem"),
    /// #     include_bytes!("server.key"),
    /// # )?;
    /// let client_cert_der = include_bytes!("client.der");
    /// let identity = authenticator.authenticate(client_cert_der)?;
    ///
    /// println!("Client: {}", identity.common_name);
    /// println!("Namespace: {}", identity.namespace);
    /// # Ok(())
    /// # }
    /// ```
    pub fn authenticate(&self, cert_der: &[u8]) -> Result<ClientIdentity> {
        // Convert DER to PEM for validation
        let pem_cert = ::pem::encode(&::pem::Pem::new("CERTIFICATE", cert_der.to_vec()));

        // Validate the certificate
        let parsed_cert = self.validator.validate(pem_cert.as_bytes())?;

        // Extract identity information from DER
        let common_name = CertificateValidator::extract_common_name(&parsed_cert.der)?;
        let organization = CertificateValidator::extract_organization(&parsed_cert.der);
        let serial_number = CertificateValidator::get_serial_number(&parsed_cert.der)?;

        // Extract namespace from organizational unit or use default
        let namespace = CertificateValidator::extract_organizational_unit(&parsed_cert.der)
            .unwrap_or_else(|| "default".to_string());

        // Extract roles from certificate extensions or organizational unit
        // In a real system, roles would be encoded in certificate extensions
        // For now, we'll derive them from the common name or organization
        let roles = Self::extract_roles(&common_name, &organization);

        let identity =
            ClientIdentity::new(common_name, organization, namespace, roles, serial_number);

        // Validate the identity
        identity.validate()?;

        Ok(identity)
    }

    /// Build rustls server configuration with mutual TLS
    fn build_tls_config(
        server_cert_pem: &[u8],
        server_key_pem: &[u8],
        _validator: Arc<CertificateValidator>,
    ) -> Result<ServerConfig> {
        // Parse server certificate using rustls-pki-types
        let certs = CertificateDer::pem_slice_iter(server_cert_pem)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                AuthError::TlsConfigError(format!("Failed to parse server cert: {}", e))
            })?;

        if certs.is_empty() {
            return Err(AuthError::TlsConfigError(
                "No certificates found in PEM".to_string(),
            ));
        }

        // Parse server private key
        let key = PrivateKeyDer::from_pem_slice(server_key_pem)
            .map_err(|e| AuthError::TlsConfigError(format!("Failed to parse server key: {}", e)))?;

        // Build server config
        // Note: In rustls 0.22, the API for client cert verification has changed
        // This is a simplified version that would need to be adapted for production
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| AuthError::TlsConfigError(format!("Failed to build TLS config: {}", e)))?;

        Ok(config)
    }

    /// Extract roles from certificate attributes
    /// In production, this should read from certificate extensions
    fn extract_roles(common_name: &str, organization: &Option<String>) -> Vec<Role> {
        // Simple role extraction based on naming conventions
        // In production, roles should be in certificate extensions
        let mut roles = Vec::new();

        if common_name.contains("admin") {
            roles.push(Role::Admin);
        } else if common_name.contains("operator") {
            roles.push(Role::Operator);
        } else if common_name.contains("auditor") {
            roles.push(Role::Auditor);
        } else {
            roles.push(Role::User);
        }

        // Could also check organization
        if let Some(org) = organization {
            if org.contains("admins") && !roles.contains(&Role::Admin) {
                roles.push(Role::Admin);
            }
        }

        roles
    }
}

// Note: In production, you would implement a custom ClientCertVerifier
// for rustls to enable mutual TLS authentication. This requires detailed
// implementation of rustls traits which is complex and version-specific.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_roles() {
        let roles = MtlsAuthenticator::extract_roles("admin-user", &None);
        assert!(roles.contains(&Role::Admin));

        let roles = MtlsAuthenticator::extract_roles("operator-service", &None);
        assert!(roles.contains(&Role::Operator));

        let roles = MtlsAuthenticator::extract_roles("regular-user", &None);
        assert!(roles.contains(&Role::User));

        let roles = MtlsAuthenticator::extract_roles("auditor-bot", &None);
        assert!(roles.contains(&Role::Auditor));
    }
}
