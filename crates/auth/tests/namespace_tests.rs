use hsm_auth::{ClientIdentity, NamespaceManager, Role};

fn create_test_identity(cn: &str, namespace: &str) -> ClientIdentity {
    ClientIdentity::new(
        cn.to_string(),
        None,
        namespace.to_string(),
        vec![Role::User],
        "123456".to_string(),
    )
}

#[test]
fn test_namespace_creation() {
    let manager = NamespaceManager::new();
    assert!(manager.create_namespace("test-ns").is_ok());
    assert!(manager.create_namespace("test-ns").is_err()); // Already exists
}

#[test]
fn test_namespace_deletion() {
    let manager = NamespaceManager::new();
    manager.create_namespace("test-ns").unwrap();
    assert!(manager.delete_namespace("test-ns").is_ok());
    assert!(manager.delete_namespace("test-ns").is_err()); // Already deleted
}

#[test]
fn test_namespace_access_control() {
    let manager = NamespaceManager::new();
    manager.create_namespace("test-ns").unwrap();
    manager.grant_access("test-ns", "client1").unwrap();

    let identity1 = create_test_identity("client1", "test-ns");
    let identity2 = create_test_identity("client2", "test-ns");

    // client1 should have access
    assert!(manager.has_access(&identity1, "test-ns"));

    // client2 should not have access (not in ACL)
    assert!(!manager.has_access(&identity2, "test-ns"));
}

#[test]
fn test_namespace_isolation() {
    let manager = NamespaceManager::new();
    let identity = create_test_identity("client1", "ns1");

    // Should have access to own namespace
    assert!(manager.has_access(&identity, "ns1"));

    // Should not have access to different namespace
    assert!(!manager.has_access(&identity, "ns2"));
}

#[test]
fn test_namespace_auto_creation() {
    let manager = NamespaceManager::new();
    let identity = create_test_identity("client1", "auto-ns");

    // Should have access to namespace even if not explicitly created
    assert!(manager.has_access(&identity, "auto-ns"));
}

#[test]
fn test_get_accessible_namespaces() {
    let manager = NamespaceManager::new();
    manager.create_namespace("ns1").unwrap();
    manager.create_namespace("ns2").unwrap();
    manager.grant_access("ns1", "client1").unwrap();

    let identity = create_test_identity("client1", "ns1");
    let namespaces = manager.get_accessible_namespaces(&identity);

    assert!(namespaces.contains(&"ns1".to_string()));
    assert!(!namespaces.contains(&"ns2".to_string()));
}

#[test]
fn test_list_namespaces() {
    let manager = NamespaceManager::new();
    manager.create_namespace("ns1").unwrap();
    manager.create_namespace("ns2").unwrap();

    let namespaces = manager.list_namespaces();
    assert_eq!(namespaces.len(), 2);
    assert!(namespaces.contains(&"ns1".to_string()));
    assert!(namespaces.contains(&"ns2".to_string()));
}

#[test]
fn test_revoke_namespace_access() {
    let manager = NamespaceManager::new();
    manager.create_namespace("test-ns").unwrap();
    manager.grant_access("test-ns", "client1").unwrap();

    let identity = create_test_identity("client1", "test-ns");
    assert!(manager.has_access(&identity, "test-ns"));

    manager.revoke_access("test-ns", "client1").unwrap();
    assert!(!manager.has_access(&identity, "test-ns"));
}
