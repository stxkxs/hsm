use hsm_auth::{
    AclManager, ClientIdentity, NamespaceManager, Permission, RbacPolicy, Role, SessionManager,
};

fn create_test_identity(cn: &str, namespace: &str, roles: Vec<Role>) -> ClientIdentity {
    ClientIdentity::new(
        cn.to_string(),
        Some("TestOrg".to_string()),
        namespace.to_string(),
        roles,
        "123456".to_string(),
    )
}

#[test]
fn test_full_authorization_flow() {
    // Setup
    let rbac = RbacPolicy::new();
    let namespaces = NamespaceManager::new();
    let acls = AclManager::new();

    // Create namespace
    namespaces.create_namespace("production").unwrap();
    namespaces
        .grant_access("production", "prod-operator")
        .unwrap();

    // Create key ACL
    acls.create_acl("production:key1".to_string(), true);
    acls.allow_client("production:key1", "prod-operator")
        .unwrap();

    // Create identity
    let identity = create_test_identity("prod-operator", "production", vec![Role::Operator]);

    // Test authorization
    // 1. Check namespace access
    assert!(namespaces.has_access(&identity, "production"));

    // 2. Check RBAC permission
    assert!(rbac.can_any(&identity.roles, &Permission::Sign));

    // 3. Check key ACL
    assert!(acls.can_access("production:key1", &identity));

    // Negative test - wrong namespace
    assert!(!namespaces.has_access(&identity, "development"));
}

#[test]
fn test_session_lifecycle() {
    let sessions = SessionManager::new(3600);

    // Create identity and session
    let identity = create_test_identity("client1", "default", vec![Role::User]);
    let session = sessions.create_session(identity.clone());

    // Validate session
    let validated = sessions.validate_session(&session.id).unwrap();
    assert_eq!(validated.identity.common_name, "client1");

    // Extend session
    sessions.extend_session(&session.id, 1800).unwrap();

    // Delete session
    sessions.delete_session(&session.id).unwrap();
    assert!(sessions.get_session(&session.id).is_err());
}

#[test]
fn test_multi_role_permissions() {
    let rbac = RbacPolicy::new();

    // Create identity with multiple roles
    let identity = create_test_identity(
        "admin-operator",
        "default",
        vec![Role::Admin, Role::Operator],
    );

    // Should have admin permissions
    assert!(rbac.can_any(&identity.roles, &Permission::ExportKey));
    assert!(rbac.can_any(&identity.roles, &Permission::ManageNamespaces));

    // Should also have operator permissions
    assert!(rbac.can_any(&identity.roles, &Permission::GenerateKey));
    assert!(rbac.can_any(&identity.roles, &Permission::Sign));
}

#[test]
fn test_namespace_isolation_enforcement() {
    let namespaces = NamespaceManager::new();
    let acls = AclManager::new();

    // Create two namespaces
    namespaces.create_namespace("tenant-a").unwrap();
    namespaces.create_namespace("tenant-b").unwrap();

    // Create identities for different tenants
    let identity_a = create_test_identity("user-a", "tenant-a", vec![Role::User]);
    let identity_b = create_test_identity("user-b", "tenant-b", vec![Role::User]);

    // Create keys in different namespaces
    acls.create_acl("tenant-a:key1".to_string(), false);
    acls.create_acl("tenant-b:key1".to_string(), false);

    // Verify namespace isolation
    assert!(namespaces.has_access(&identity_a, "tenant-a"));
    assert!(!namespaces.has_access(&identity_a, "tenant-b"));

    assert!(namespaces.has_access(&identity_b, "tenant-b"));
    assert!(!namespaces.has_access(&identity_b, "tenant-a"));
}

#[test]
fn test_acl_deny_overrides_allow() {
    let acls = AclManager::new();
    let identity = create_test_identity("client1", "default", vec![Role::User]);

    // Create ACL and allow client
    acls.create_acl("key1".to_string(), true);
    acls.allow_client("key1", "client1").unwrap();

    assert!(acls.can_access("key1", &identity));

    // Now deny the client - deny should override allow
    acls.deny_client("key1", "client1").unwrap();
    assert!(!acls.can_access("key1", &identity));
}

#[test]
fn test_session_cleanup() {
    let sessions = SessionManager::new(-1); // Create expired sessions

    // Create multiple sessions
    let identity1 = create_test_identity("client1", "default", vec![Role::User]);
    let identity2 = create_test_identity("client2", "default", vec![Role::User]);

    sessions.create_session(identity1);
    sessions.create_session(identity2);

    // All sessions should be expired
    assert_eq!(sessions.active_session_count(), 0);

    // Cleanup should remove them
    let cleaned = sessions.cleanup_expired();
    assert_eq!(cleaned, 2);
}

#[test]
fn test_client_identity_validation() {
    // Valid identity
    let identity = create_test_identity("client1", "namespace1", vec![Role::User]);
    assert!(identity.validate().is_ok());

    // Empty common name
    let mut identity = create_test_identity("", "namespace1", vec![Role::User]);
    assert!(identity.validate().is_err());

    // Empty namespace
    identity = create_test_identity("client1", "", vec![Role::User]);
    assert!(identity.validate().is_err());

    // No roles
    identity = create_test_identity("client1", "namespace1", vec![]);
    assert!(identity.validate().is_err());
}

#[test]
fn test_rbac_privilege_escalation_prevention() {
    let rbac = RbacPolicy::new();

    // User should not be able to manage namespaces
    assert!(!rbac.can(&Role::User, &Permission::ManageNamespaces));

    // User should not be able to export keys
    assert!(!rbac.can(&Role::User, &Permission::ExportKey));

    // Operator should not be able to manage namespaces
    assert!(!rbac.can(&Role::Operator, &Permission::ManageNamespaces));

    // Only Admin should have these permissions
    assert!(rbac.can(&Role::Admin, &Permission::ManageNamespaces));
    assert!(rbac.can(&Role::Admin, &Permission::ExportKey));
}

#[test]
fn test_namespace_get_accessible_for_client() {
    let namespaces = NamespaceManager::new();

    namespaces.create_namespace("ns1").unwrap();
    namespaces.create_namespace("ns2").unwrap();
    namespaces.create_namespace("ns3").unwrap();

    namespaces.grant_access("ns1", "client1").unwrap();
    namespaces.grant_access("ns2", "client1").unwrap();

    let identity = create_test_identity("client1", "ns1", vec![Role::User]);
    let accessible = namespaces.get_accessible_namespaces(&identity);

    // Should have access to ns1 and ns2, but not ns3
    assert!(accessible.contains(&"ns1".to_string()));
    assert!(!accessible.contains(&"ns3".to_string()));
}
