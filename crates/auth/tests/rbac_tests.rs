use hsm_auth::{Permission, RbacPolicy, Role};

#[test]
fn test_rbac_policy_default_permissions() {
    let policy = RbacPolicy::new();

    // Admin should have all permissions
    assert!(policy.can(&Role::Admin, &Permission::GenerateKey));
    assert!(policy.can(&Role::Admin, &Permission::ExportKey));
    assert!(policy.can(&Role::Admin, &Permission::ManageNamespaces));

    // Operator should have operational permissions
    assert!(policy.can(&Role::Operator, &Permission::GenerateKey));
    assert!(policy.can(&Role::Operator, &Permission::Sign));
    assert!(!policy.can(&Role::Operator, &Permission::ExportKey));
    assert!(!policy.can(&Role::Operator, &Permission::ManageNamespaces));

    // User should have basic crypto permissions
    assert!(policy.can(&Role::User, &Permission::Sign));
    assert!(policy.can(&Role::User, &Permission::Encrypt));
    assert!(!policy.can(&Role::User, &Permission::GenerateKey));
    assert!(!policy.can(&Role::User, &Permission::DeleteKey));

    // Auditor should only have read permissions
    assert!(policy.can(&Role::Auditor, &Permission::ViewMetadata));
    assert!(policy.can(&Role::Auditor, &Permission::ViewAuditLogs));
    assert!(!policy.can(&Role::Auditor, &Permission::Sign));
    assert!(!policy.can(&Role::Auditor, &Permission::GenerateKey));
}

#[test]
fn test_rbac_can_any() {
    let policy = RbacPolicy::new();

    let roles = vec![Role::User, Role::Auditor];
    assert!(policy.can_any(&roles, &Permission::ViewMetadata));
    assert!(!policy.can_any(&roles, &Permission::GenerateKey));

    let roles = vec![Role::Admin, Role::User];
    assert!(policy.can_any(&roles, &Permission::GenerateKey));
}

#[test]
fn test_rbac_require() {
    let policy = RbacPolicy::new();

    assert!(policy
        .require(&Role::Admin, &Permission::GenerateKey)
        .is_ok());
    assert!(policy
        .require(&Role::User, &Permission::GenerateKey)
        .is_err());
}

#[test]
fn test_rbac_grant_revoke() {
    let mut policy = RbacPolicy::new();

    // Grant a new permission
    assert!(!policy.can(&Role::User, &Permission::GenerateKey));
    policy.grant(Role::User, Permission::GenerateKey);
    assert!(policy.can(&Role::User, &Permission::GenerateKey));

    // Revoke the permission
    assert!(policy.revoke(&Role::User, &Permission::GenerateKey));
    assert!(!policy.can(&Role::User, &Permission::GenerateKey));
}

#[test]
fn test_role_hierarchy() {
    assert!(Role::Admin.hierarchy_level() > Role::Operator.hierarchy_level());
    assert!(Role::Operator.hierarchy_level() > Role::User.hierarchy_level());
    assert!(Role::User.hierarchy_level() > Role::Auditor.hierarchy_level());
}

#[test]
fn test_role_can_assume() {
    assert!(Role::Admin.can_assume(&Role::Operator));
    assert!(Role::Admin.can_assume(&Role::User));
    assert!(Role::Admin.can_assume(&Role::Auditor));

    assert!(Role::Operator.can_assume(&Role::User));
    assert!(Role::Operator.can_assume(&Role::Auditor));
    assert!(!Role::Operator.can_assume(&Role::Admin));

    assert!(Role::User.can_assume(&Role::Auditor));
    assert!(!Role::User.can_assume(&Role::Operator));
    assert!(!Role::User.can_assume(&Role::Admin));

    assert!(!Role::Auditor.can_assume(&Role::User));
    assert!(!Role::Auditor.can_assume(&Role::Operator));
    assert!(!Role::Auditor.can_assume(&Role::Admin));
}

#[test]
fn test_permission_privileged() {
    assert!(Permission::ExportKey.is_privileged());
    assert!(Permission::ManageNamespaces.is_privileged());
    assert!(Permission::DeleteKey.is_privileged());
    assert!(!Permission::Sign.is_privileged());
    assert!(!Permission::Encrypt.is_privileged());
    assert!(!Permission::ViewMetadata.is_privileged());
}
