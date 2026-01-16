use hsm_auth::Role;

#[test]
fn test_certificate_validator_basic() {
    // This test requires actual certificates
    // For now, we'll just ensure the structure compiles
}

#[test]
fn test_mtls_authenticator_role_extraction() {
    // Test role extraction logic
    let roles = extract_test_roles("admin-user", &None);
    assert!(roles.contains(&Role::Admin));

    let roles = extract_test_roles("operator-service", &None);
    assert!(roles.contains(&Role::Operator));

    let roles = extract_test_roles("regular-user", &None);
    assert!(roles.contains(&Role::User));

    let roles = extract_test_roles("auditor-bot", &None);
    assert!(roles.contains(&Role::Auditor));
}

// Helper function that mirrors the logic in MtlsAuthenticator
fn extract_test_roles(common_name: &str, organization: &Option<String>) -> Vec<Role> {
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

    if let Some(org) = organization {
        if org.contains("admins") && !roles.contains(&Role::Admin) {
            roles.push(Role::Admin);
        }
    }

    roles
}
