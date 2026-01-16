// Security tests to verify no auth bypasses
// Tests include:
// - Authorization bypass attempts
// - Namespace isolation violations
// - Session hijacking attempts
// - Rate limit evasion
// - Permission escalation

use hsm_auth::*;

fn create_test_identity(cn: &str, namespace: &str, roles: Vec<Role>) -> ClientIdentity {
    ClientIdentity::new(
        cn.to_string(),
        None,
        namespace.to_string(),
        roles,
        "123456".to_string(),
    )
}

#[test]
fn test_no_authorization_bypass_without_role() {
    let policy = RbacPolicy::new();
    let identity = create_test_identity("client1", "default", vec![Role::User]);

    // User role should not have admin permissions by default
    assert!(!policy.can_any(&identity.roles, &Permission::ManageRoles));
    assert!(!policy.can_any(&identity.roles, &Permission::ManageNamespaces));
    assert!(!policy.can_any(&identity.roles, &Permission::ExportKey));
}

#[test]
fn test_namespace_isolation_enforced() {
    let namespace_manager = NamespaceManager::new();
    namespace_manager.create_namespace("ns1").unwrap();
    namespace_manager.create_namespace("ns2").unwrap();

    let identity1 = create_test_identity("client1", "ns1", vec![Role::User]);
    let identity2 = create_test_identity("client2", "ns2", vec![Role::User]);

    // Client 1 should only access ns1
    assert!(namespace_manager.has_access(&identity1, "ns1"));
    assert!(!namespace_manager.has_access(&identity1, "ns2"));

    // Client 2 should only access ns2
    assert!(namespace_manager.has_access(&identity2, "ns2"));
    assert!(!namespace_manager.has_access(&identity2, "ns1"));
}

#[test]
fn test_namespace_isolation_with_acl() {
    let namespace_manager = NamespaceManager::new();
    namespace_manager.create_namespace("restricted").unwrap();
    namespace_manager
        .grant_access("restricted", "authorized-client")
        .unwrap();

    let authorized = create_test_identity("authorized-client", "restricted", vec![Role::User]);
    let unauthorized = create_test_identity("unauthorized-client", "restricted", vec![Role::User]);

    // Only authorized client should have access
    assert!(namespace_manager.has_access(&authorized, "restricted"));
    assert!(!namespace_manager.has_access(&unauthorized, "restricted"));
}

#[test]
fn test_require_access_blocks_unauthorized() {
    let namespace_manager = NamespaceManager::new();
    namespace_manager.create_namespace("secure").unwrap();
    namespace_manager
        .grant_access("secure", "authorized")
        .unwrap();

    let authorized = create_test_identity("authorized", "secure", vec![Role::User]);
    let unauthorized = create_test_identity("unauthorized", "secure", vec![Role::User]);

    // Authorized should succeed
    assert!(namespace_manager
        .require_access(&authorized, "secure")
        .is_ok());

    // Unauthorized should fail
    assert!(namespace_manager
        .require_access(&unauthorized, "secure")
        .is_err());
}

#[test]
fn test_session_hijacking_detection_ip_mismatch() {
    let session_manager = SessionManager::new(3600);
    let identity = create_test_identity("client1", "default", vec![Role::User]);

    // Create session with IP
    let session = session_manager.create_session_with_metadata(
        identity.clone(),
        Some("192.168.1.1".to_string()),
        Some("Mozilla/5.0".to_string()),
    );

    // Validation with same IP should succeed
    assert!(session_manager
        .validate_session_with_metadata(
            &session.id,
            Some("192.168.1.1".to_string()),
            Some("Mozilla/5.0".to_string())
        )
        .is_ok());

    // Validation with different IP should fail (hijacking detected)
    assert!(session_manager
        .validate_session_with_metadata(
            &session.id,
            Some("192.168.1.2".to_string()),
            Some("Mozilla/5.0".to_string())
        )
        .is_err());
}

#[test]
fn test_expired_session_rejected() {
    let session_manager = SessionManager::new(-1); // Expired immediately
    let identity = create_test_identity("client1", "default", vec![Role::User]);

    let session = session_manager.create_session(identity);

    // Expired session should be rejected
    assert!(session_manager.validate_session(&session.id).is_err());
}

#[test]
fn test_deleted_session_rejected() {
    let session_manager = SessionManager::new(3600);
    let identity = create_test_identity("client1", "default", vec![Role::User]);

    let session = session_manager.create_session(identity);

    // Delete session
    session_manager.delete_session(&session.id).unwrap();

    // Deleted session should be rejected
    assert!(session_manager.validate_session(&session.id).is_err());
}

#[test]
fn test_rate_limiting_prevents_dos() {
    let config = RateLimitConfig {
        global_rps: 1000,
        per_identity_rps: 5, // Very low limit for testing
        per_namespace_rps: 100,
    };
    let rate_limiter = RateLimiter::with_config(config);
    let identity = create_test_identity("attacker", "default", vec![Role::User]);

    // First few requests should succeed
    for _ in 0..5 {
        let _ = rate_limiter.check(&identity, "default");
    }

    // Additional requests should be blocked
    let result = rate_limiter.check(&identity, "default");
    assert!(result.is_err());

    if let Err(AuthError::RateLimitExceeded(_)) = result {
        // Expected
    } else {
        panic!("Expected rate limit error");
    }
}

#[test]
fn test_rate_limiting_per_namespace() {
    let config = RateLimitConfig {
        global_rps: 1000,
        per_identity_rps: 100,
        per_namespace_rps: 5, // Very low limit for testing
    };
    let rate_limiter = RateLimiter::with_config(config);
    let identity = create_test_identity("client1", "limited-ns", vec![Role::User]);

    // First few requests should succeed
    for _ in 0..5 {
        let _ = rate_limiter.check(&identity, "limited-ns");
    }

    // Additional requests to the same namespace should be blocked
    let result = rate_limiter.check(&identity, "limited-ns");
    assert!(result.is_err());
}

#[test]
fn test_acl_deny_overrides_allow() {
    let acl_manager = AclManager::new();
    let _acl = acl_manager.create_acl("key1".to_string(), true);

    let identity = create_test_identity("client1", "default", vec![Role::User]);

    // Allow client
    acl_manager.allow_client("key1", "client1").unwrap();
    assert!(acl_manager.can_access("key1", &identity));

    // Deny client (should override allow)
    acl_manager.deny_client("key1", "client1").unwrap();
    assert!(!acl_manager.can_access("key1", &identity));
}

#[test]
fn test_privilege_escalation_prevented() {
    let _policy = RbacPolicy::new();

    // User should not be able to assume admin or operator roles
    assert!(!Role::User.can_assume(&Role::Admin));
    assert!(!Role::User.can_assume(&Role::Operator));

    // Operator should not be able to assume admin role
    assert!(!Role::Operator.can_assume(&Role::Admin));

    // Auditor should not be able to assume any other role
    assert!(!Role::Auditor.can_assume(&Role::Admin));
    assert!(!Role::Auditor.can_assume(&Role::Operator));
    assert!(!Role::Auditor.can_assume(&Role::User));
}

#[test]
fn test_permission_checks_enforce_privileges() {
    let policy = RbacPolicy::new();

    // User should not have privileged permissions
    let user_identity = create_test_identity("user", "default", vec![Role::User]);

    assert!(policy
        .require_any(&user_identity.roles, &Permission::ExportKey)
        .is_err());
    assert!(policy
        .require_any(&user_identity.roles, &Permission::ManageRoles)
        .is_err());
    assert!(policy
        .require_any(&user_identity.roles, &Permission::ManageNamespaces)
        .is_err());
}

#[test]
fn test_audit_logs_security_events() {
    use hsm_auth::audit::*;

    let logger = InMemoryAuditLogger::new();

    // Log authentication failure
    let event = AuditEvent::new(
        AuditEventType::AuthenticationFailure,
        AuditSeverity::Warning,
        "Invalid certificate".to_string(),
    );
    logger.log(event);

    // Log rate limit exceeded
    let identity = create_test_identity("attacker", "default", vec![Role::User]);
    let event = AuditEvent::new(
        AuditEventType::RateLimitExceeded,
        AuditSeverity::Warning,
        "Too many requests".to_string(),
    )
    .with_identity(identity.clone());
    logger.log(event);

    // Log session hijacking attempt
    let event = AuditEvent::new(
        AuditEventType::SessionHijackingAttempt,
        AuditSeverity::Critical,
        "IP mismatch detected".to_string(),
    )
    .with_identity(identity.clone());
    logger.log(event);

    // Verify events were logged
    assert_eq!(logger.event_count(), 3);

    // Verify we can filter by severity
    let critical_events = logger.get_events_by_severity(AuditSeverity::Critical);
    assert_eq!(critical_events.len(), 1);

    let warning_events = logger.get_events_by_severity(AuditSeverity::Warning);
    assert_eq!(warning_events.len(), 2);
}

#[test]
fn test_no_permission_bypass_through_multiple_roles() {
    let policy = RbacPolicy::new();

    // Even with multiple non-admin roles, should not have admin permissions
    let identity = create_test_identity(
        "client1",
        "default",
        vec![Role::User, Role::Operator, Role::Auditor],
    );

    assert!(policy
        .require_any(&identity.roles, &Permission::ManageRoles)
        .is_err());
}

#[test]
fn test_namespace_cross_access_prevented() {
    let acl_manager = AclManager::new();
    let namespace_manager = NamespaceManager::new();

    namespace_manager.create_namespace("ns1").unwrap();
    namespace_manager.create_namespace("ns2").unwrap();

    let _identity_ns1 = create_test_identity("client-ns1", "ns1", vec![Role::User]);
    let identity_ns2 = create_test_identity("client-ns2", "ns2", vec![Role::User]);

    // Create key in ns1
    acl_manager.create_acl("ns1-key".to_string(), false);

    // Client from ns2 should not have implicit access to ns1 resources
    assert!(namespace_manager
        .require_access(&identity_ns2, "ns1")
        .is_err());
}

#[test]
fn test_session_cleanup_removes_expired() {
    let session_manager = SessionManager::new(-1); // All sessions expired
    let identity1 = create_test_identity("client1", "default", vec![Role::User]);
    let identity2 = create_test_identity("client2", "default", vec![Role::User]);

    session_manager.create_session(identity1);
    session_manager.create_session(identity2);

    // Before cleanup
    assert_eq!(session_manager.get_active_sessions().len(), 0); // All expired

    // Cleanup should remove expired sessions
    let removed = session_manager.cleanup_expired();
    assert_eq!(removed, 2);
}

#[test]
fn test_permission_flags_bitwise_operations() {
    let perms = PermissionFlags::from_permissions(&[Permission::Sign, Permission::Encrypt]);

    // Should have both permissions
    assert!(perms.has_permission(&Permission::Sign));
    assert!(perms.has_permission(&Permission::Encrypt));

    // Should not have other permissions
    assert!(!perms.has_permission(&Permission::DeleteKey));
    assert!(!perms.has_permission(&Permission::ManageRoles));
}

#[test]
fn test_concurrent_session_access_safe() {
    use std::sync::Arc;
    use std::thread;

    let session_manager = Arc::new(SessionManager::new(3600));
    let identity = create_test_identity("client1", "default", vec![Role::User]);

    let session = session_manager.create_session(identity.clone());
    let session_id = session.id.clone();

    // Spawn multiple threads accessing the same session
    let mut handles = vec![];
    for _ in 0..10 {
        let manager = Arc::clone(&session_manager);
        let sid = session_id.clone();
        let handle = thread::spawn(move || {
            // Should not panic or corrupt data
            let _ = manager.validate_session(&sid);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Session should still be valid
    assert!(session_manager.validate_session(&session_id).is_ok());
}
