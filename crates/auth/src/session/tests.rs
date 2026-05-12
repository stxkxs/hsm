use super::*;
use crate::mtls::ClientIdentity;
use crate::rbac::{Permission, Role};

fn create_test_identity(cn: &str) -> ClientIdentity {
    ClientIdentity::new(
        cn.to_string(),
        None,
        "default".to_string(),
        vec![Role::User],
        "123456".to_string(),
    )
}

#[test]
fn test_create_session() {
    let identity = create_test_identity("client1");
    let result = Session::create(identity.clone(), 3600);

    assert_eq!(result.session.identity.common_name, "client1");
    assert!(result.session.is_valid());
    assert!(!result.session.is_expired());
}

#[test]
fn test_session_token_verification() {
    let identity = create_test_identity("client1");
    let result = Session::create(identity, 3600);

    // Token should verify against the session
    assert!(result.session.verify_token(&result.token));

    // Wrong token should not verify
    let wrong_token = SessionToken::new();
    assert!(!result.session.verify_token(&wrong_token));
}

#[test]
fn test_hashed_token_constant_time() {
    let token = SessionToken::new();
    let hash = HashedToken::from_token(&token);

    // Same token should verify
    assert!(hash.verify(&token));

    // Different token should not verify
    let other_token = SessionToken::new();
    assert!(!hash.verify(&other_token));
}

#[test]
fn test_session_expiration() {
    let identity = create_test_identity("client1");
    let result = Session::create(identity, -1); // Already expired
    let mut session = result.session;

    assert!(!session.is_valid());
    assert!(session.is_expired());

    // Extend the session
    session.extend(3600);
    assert!(session.is_valid());
}

#[test]
fn test_session_manager_create() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");
    let result = manager.create_session(identity);

    assert!(manager.get_session(&result.session.id).is_ok());
}

#[test]
fn test_session_manager_validate_with_token() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");
    let result = manager.create_session(identity);

    // Should validate with correct token
    assert!(manager
        .validate_session_with_token(&result.session.id, &result.token)
        .is_ok());

    // Should fail with wrong token
    let wrong_token = SessionToken::new();
    assert!(manager
        .validate_session_with_token(&result.session.id, &wrong_token)
        .is_err());

    // Should fail with wrong session ID
    assert!(manager
        .validate_session_with_token("invalid-id", &result.token)
        .is_err());
}

#[test]
#[allow(deprecated)]
fn test_session_manager_validate() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");
    let result = manager.create_session(identity);

    assert!(manager.validate_session(&result.session.id).is_ok());
    assert!(manager.validate_session("invalid-id").is_err());
}

#[test]
fn test_session_manager_delete() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");
    let result = manager.create_session(identity);

    assert!(manager.delete_session(&result.session.id).is_ok());
    assert!(manager.get_session(&result.session.id).is_err());
}

#[test]
fn test_session_manager_extend() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");
    let result = manager.create_session(identity);

    let original_expires = result.session.expires_at;
    manager
        .extend_session(&result.session.id, 1800)
        .expect("extend should succeed");

    let updated = manager
        .get_session(&result.session.id)
        .expect("session should exist");
    assert!(updated.expires_at > original_expires);
}

#[test]
fn test_token_rotation() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");
    let result = manager.create_session(identity);

    // Original token should work
    assert!(manager
        .validate_session_with_token(&result.session.id, &result.token)
        .is_ok());

    // Rotate the token
    let new_token = manager
        .rotate_session_token(&result.session.id)
        .expect("rotation should succeed");

    // Old token should no longer work
    assert!(manager
        .validate_session_with_token(&result.session.id, &result.token)
        .is_err());

    // New token should work
    assert!(manager
        .validate_session_with_token(&result.session.id, &new_token)
        .is_ok());
}

#[test]
fn test_operation_count_for_rotation() {
    let identity = create_test_identity("client1");
    let result = Session::create(identity, 3600);
    let mut session = result.session;

    // Operation count starts at 0
    assert_eq!(session.operation_count, 0);

    // Should not recommend rotation initially
    for _ in 0..999 {
        assert!(!session.increment_operation());
    }

    // Should recommend rotation at 1000 operations
    assert!(session.increment_operation());
}

#[test]
fn test_cleanup_expired() {
    let manager = SessionManager::new(-1); // Create expired sessions
    let identity1 = create_test_identity("client1");
    let identity2 = create_test_identity("client2");

    manager.create_session(identity1);
    manager.create_session(identity2);

    let cleaned = manager.cleanup_expired();
    assert_eq!(cleaned, 2);
    assert_eq!(manager.active_session_count(), 0);
}

#[test]
fn test_get_client_sessions() {
    let manager = SessionManager::new(3600);
    let identity1 = create_test_identity("client1");
    let identity2 = create_test_identity("client2");

    manager.create_session(identity1.clone());
    manager.create_session(identity1.clone());
    manager.create_session(identity2);

    let client1_sessions = manager.get_client_sessions("client1");
    assert_eq!(client1_sessions.len(), 2);

    let client2_sessions = manager.get_client_sessions("client2");
    assert_eq!(client2_sessions.len(), 1);
}

#[test]
fn test_delete_client_sessions() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");

    manager.create_session(identity.clone());
    manager.create_session(identity.clone());

    let deleted = manager.delete_client_sessions("client1");
    assert_eq!(deleted, 2);
    assert_eq!(manager.get_client_sessions("client1").len(), 0);
}

#[test]
fn test_active_session_count() {
    let manager = SessionManager::new(3600);
    assert_eq!(manager.active_session_count(), 0);

    let identity = create_test_identity("client1");
    manager.create_session(identity);
    assert_eq!(manager.active_session_count(), 1);
}

#[test]
fn test_rotate_client_tokens() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");

    let result1 = manager.create_session(identity.clone());
    let result2 = manager.create_session(identity.clone());

    // Rotate all tokens for client1
    let rotated = manager.rotate_client_tokens("client1");
    assert_eq!(rotated.len(), 2);

    // Old tokens should no longer work
    assert!(manager
        .validate_session_with_token(&result1.session.id, &result1.token)
        .is_err());
    assert!(manager
        .validate_session_with_token(&result2.session.id, &result2.token)
        .is_err());

    // New tokens should work
    for (session_id, new_token) in rotated {
        assert!(manager
            .validate_session_with_token(&session_id, &new_token)
            .is_ok());
    }
}

#[test]
fn test_hijacking_detection_ip() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");
    let result = manager.create_session_with_metadata(
        identity,
        Some("192.168.1.100".to_string()),
        Some("TestClient/1.0".to_string()),
        None,
    );

    // Same IP should work
    assert!(manager
        .validate_session_with_metadata(
            &result.session.id,
            &result.token,
            Some("192.168.1.100".to_string()),
            Some("TestClient/1.0".to_string()),
            None,
        )
        .is_ok());

    // Different IP should fail (hijacking detection)
    assert!(manager
        .validate_session_with_metadata(
            &result.session.id,
            &result.token,
            Some("10.0.0.1".to_string()),
            Some("TestClient/1.0".to_string()),
            None,
        )
        .is_err());
}

#[test]
fn test_session_token_debug_redacts() {
    let token = SessionToken::new();
    let debug_output = format!("{:?}", token);
    assert!(debug_output.contains("REDACTED"));
    assert!(!debug_output.contains(token.as_str()));
}

// === Session Scope Tests ===

#[test]
fn test_session_scope_default() {
    let scope = SessionScope::new();
    // Default scope allows everything
    assert!(scope.is_operation_allowed(&Permission::Sign));
    assert!(scope.is_operation_allowed(&Permission::DeleteKey));
    assert!(scope.is_key_allowed("any-key"));
    assert!(scope.is_namespace_allowed("any-namespace"));
}

#[test]
fn test_session_scope_operations() {
    let scope = SessionScope::new().with_operations(vec![Permission::Sign, Permission::Encrypt]);

    assert!(scope.is_operation_allowed(&Permission::Sign));
    assert!(scope.is_operation_allowed(&Permission::Encrypt));
    assert!(!scope.is_operation_allowed(&Permission::DeleteKey));
    assert!(!scope.is_operation_allowed(&Permission::Decrypt));
}

#[test]
fn test_session_scope_keys() {
    let scope = SessionScope::new().with_keys(vec!["key-1".to_string(), "key-2".to_string()]);

    assert!(scope.is_key_allowed("key-1"));
    assert!(scope.is_key_allowed("key-2"));
    assert!(!scope.is_key_allowed("key-3"));
}

#[test]
fn test_session_scope_namespaces() {
    let scope =
        SessionScope::new().with_namespaces(vec!["prod".to_string(), "staging".to_string()]);

    assert!(scope.is_namespace_allowed("prod"));
    assert!(scope.is_namespace_allowed("staging"));
    assert!(!scope.is_namespace_allowed("dev"));
}

#[test]
fn test_session_scope_is_subset() {
    let parent = SessionScope::new()
        .with_operations(vec![
            Permission::Sign,
            Permission::Encrypt,
            Permission::Decrypt,
        ])
        .with_keys(vec![
            "key-1".to_string(),
            "key-2".to_string(),
            "key-3".to_string(),
        ])
        .with_max_operations(1000)
        .with_rate_limit(100);

    // Valid subset
    let child = SessionScope::new()
        .with_operations(vec![Permission::Sign])
        .with_keys(vec!["key-1".to_string()])
        .with_max_operations(500)
        .with_rate_limit(50);
    assert!(child.is_subset_of(&parent));

    // Invalid: operation not in parent
    let invalid_ops =
        SessionScope::new().with_operations(vec![Permission::Sign, Permission::DeleteKey]);
    assert!(!invalid_ops.is_subset_of(&parent));

    // Invalid: key not in parent
    let invalid_keys =
        SessionScope::new().with_keys(vec!["key-1".to_string(), "key-unknown".to_string()]);
    assert!(!invalid_keys.is_subset_of(&parent));

    // Invalid: max_operations exceeds parent
    let invalid_max = SessionScope::new().with_max_operations(2000);
    assert!(!invalid_max.is_subset_of(&parent));
}

#[test]
fn test_session_scope_intersect() {
    let scope1 = SessionScope::new()
        .with_operations(vec![Permission::Sign, Permission::Encrypt])
        .with_keys(vec!["key-1".to_string(), "key-2".to_string()])
        .with_max_operations(1000)
        .with_rate_limit(100);

    let scope2 = SessionScope::new()
        .with_operations(vec![Permission::Sign, Permission::Decrypt])
        .with_keys(vec!["key-2".to_string(), "key-3".to_string()])
        .with_max_operations(500)
        .with_rate_limit(50);

    let intersection = scope1.intersect(&scope2);

    // Only Sign is in both
    assert!(intersection.is_operation_allowed(&Permission::Sign));
    assert!(!intersection.is_operation_allowed(&Permission::Encrypt));
    assert!(!intersection.is_operation_allowed(&Permission::Decrypt));

    // Only key-2 is in both
    assert!(intersection.is_key_allowed("key-2"));
    assert!(!intersection.is_key_allowed("key-1"));
    assert!(!intersection.is_key_allowed("key-3"));

    // Takes minimum
    assert_eq!(intersection.max_operations, Some(500));
    assert_eq!(intersection.rate_limit, Some(50));
}

// === Session Template Tests ===

#[test]
fn test_session_template_creation() {
    let template = SessionTemplate::new("signing-only", "Signing Only")
        .with_scope(
            SessionScope::new()
                .with_operations(vec![Permission::Sign])
                .with_rate_limit(100),
        )
        .with_ttl(3600)
        .with_description("Template for signing-only sessions")
        .with_delegation(2);

    assert_eq!(template.id, "signing-only");
    assert_eq!(template.name, "Signing Only");
    assert_eq!(template.default_ttl_seconds, 3600);
    assert!(template.allow_delegation);
    assert_eq!(template.max_delegation_depth, 2);
}

#[test]
fn test_template_registration() {
    let manager = SessionManager::new(3600);

    let template = SessionTemplate::new("test-template", "Test Template");
    assert!(manager.register_template(template.clone()).is_ok());

    // Duplicate registration should fail
    assert!(manager.register_template(template).is_err());

    // Get template
    let retrieved = manager.get_template("test-template");
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().name, "Test Template");
}

#[test]
fn test_template_crud() {
    let manager = SessionManager::new(3600);

    let template = SessionTemplate::new("test", "Test");
    manager.register_template(template).unwrap();

    // List templates
    let templates = manager.list_templates();
    assert_eq!(templates.len(), 1);

    // Update template
    let updated = SessionTemplate::new("test", "Updated Test");
    assert!(manager.update_template(updated).is_ok());

    let retrieved = manager.get_template("test").unwrap();
    assert_eq!(retrieved.name, "Updated Test");

    // Delete template
    assert!(manager.delete_template("test").is_ok());
    assert!(manager.get_template("test").is_none());
}

// === Scoped Session Tests ===

#[test]
fn test_create_scoped_session() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");

    let scope = SessionScope::new()
        .with_operations(vec![Permission::Sign])
        .with_keys(vec!["key-1".to_string()]);

    let result = manager.create_scoped_session(identity, scope, None);

    assert!(result.session.scope.is_some());
    assert!(result.session.is_operation_allowed(&Permission::Sign));
    assert!(!result.session.is_operation_allowed(&Permission::DeleteKey));
    assert!(result.session.is_key_allowed("key-1"));
    assert!(!result.session.is_key_allowed("key-2"));
}

#[test]
fn test_create_session_from_template() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");

    let template = SessionTemplate::new("signing-only", "Signing Only")
        .with_scope(
            SessionScope::new()
                .with_operations(vec![Permission::Sign])
                .with_rate_limit(100),
        )
        .with_ttl(1800)
        .with_delegation(1);

    manager.register_template(template).unwrap();

    let result = manager
        .create_session_from_template(identity, "signing-only")
        .unwrap();

    assert!(result.session.is_operation_allowed(&Permission::Sign));
    assert!(!result.session.is_operation_allowed(&Permission::Encrypt));
    assert_eq!(result.session.template_id, Some("signing-only".to_string()));
    assert!(result.session.allow_delegation);
}

#[test]
fn test_validate_scoped_session() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");

    let scope = SessionScope::new()
        .with_operations(vec![Permission::Sign])
        .with_keys(vec!["key-1".to_string()]);

    let result = manager.create_scoped_session(identity, scope, None);

    // Allowed operation and key
    assert!(manager
        .validate_scoped_session(
            &result.session.id,
            &result.token,
            Some(&Permission::Sign),
            Some("key-1"),
        )
        .is_ok());

    // Disallowed operation
    assert!(manager
        .validate_scoped_session(
            &result.session.id,
            &result.token,
            Some(&Permission::DeleteKey),
            None,
        )
        .is_err());

    // Disallowed key
    assert!(manager
        .validate_scoped_session(&result.session.id, &result.token, None, Some("key-2"),)
        .is_err());
}

#[test]
fn test_scoped_session_operation_limit() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");

    let scope = SessionScope::new().with_max_operations(3);

    let result = manager.create_scoped_session(identity, scope, None);

    // First 3 operations should succeed
    for _ in 0..3 {
        assert!(manager
            .validate_scoped_session(&result.session.id, &result.token, None, None)
            .is_ok());
    }

    // 4th operation should fail due to limit
    assert!(manager
        .validate_scoped_session(&result.session.id, &result.token, None, None)
        .is_err());
}

// === Session Delegation Tests ===

#[test]
fn test_session_delegation() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");

    // Create parent session with delegation enabled
    let scope = SessionScope::new().with_operations(vec![Permission::Sign, Permission::Encrypt]);

    let parent_result = manager.create_scoped_session(identity, scope, None);
    let parent_id = parent_result.session.id.clone();

    // Manually enable delegation on parent
    {
        let mut parent = manager.sessions.get_mut(&parent_id).unwrap();
        parent.allow_delegation = true;
        parent.max_delegation_depth = 2;
    }

    // Delegate with more restricted scope
    let child_scope = SessionScope::new().with_operations(vec![Permission::Sign]);

    let child_result = manager
        .delegate_session(&parent_id, child_scope, 1800)
        .unwrap();

    assert_eq!(
        child_result.session.parent_session_id,
        Some(parent_id.clone())
    );
    assert_eq!(child_result.session.delegation_depth, 1);
    assert!(child_result.session.is_operation_allowed(&Permission::Sign));
    assert!(!child_result
        .session
        .is_operation_allowed(&Permission::Encrypt));
}

#[test]
fn test_delegation_cannot_exceed_parent_scope() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");

    // Parent only allows Sign
    let scope = SessionScope::new().with_operations(vec![Permission::Sign]);

    let parent_result = manager.create_scoped_session(identity, scope, None);
    let parent_id = parent_result.session.id.clone();

    // Enable delegation
    {
        let mut parent = manager.sessions.get_mut(&parent_id).unwrap();
        parent.allow_delegation = true;
        parent.max_delegation_depth = 1;
    }

    // Try to delegate with operations not in parent (should fail)
    let invalid_scope =
        SessionScope::new().with_operations(vec![Permission::Sign, Permission::Encrypt]); // Encrypt not allowed

    let result = manager.delegate_session(&parent_id, invalid_scope, 1800);
    assert!(result.is_err());
}

#[test]
fn test_delegation_without_permission() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");

    // Create session without delegation enabled
    let result = manager.create_session(identity);

    // Try to delegate (should fail)
    let scope = SessionScope::new();
    assert!(manager
        .delegate_session(&result.session.id, scope, 1800)
        .is_err());
}

#[test]
fn test_delegation_depth_limit() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");

    // Create parent with max depth of 1
    let scope = SessionScope::new();
    let parent_result = manager.create_scoped_session(identity, scope, None);
    let parent_id = parent_result.session.id.clone();

    {
        let mut parent = manager.sessions.get_mut(&parent_id).unwrap();
        parent.allow_delegation = true;
        parent.max_delegation_depth = 1;
    }

    // First delegation should succeed
    let child_result = manager
        .delegate_session(&parent_id, SessionScope::new(), 1800)
        .unwrap();
    assert_eq!(child_result.session.delegation_depth, 1);
    assert!(!child_result.session.allow_delegation); // Can't delegate further

    // Child cannot delegate (depth limit reached)
    assert!(manager
        .delegate_session(&child_result.session.id, SessionScope::new(), 900)
        .is_err());
}

#[test]
fn test_revoke_session_cascade() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");

    // Create parent
    let scope = SessionScope::new();
    let parent_result = manager.create_scoped_session(identity.clone(), scope, None);
    let parent_id = parent_result.session.id.clone();

    {
        let mut parent = manager.sessions.get_mut(&parent_id).unwrap();
        parent.allow_delegation = true;
        parent.max_delegation_depth = 3;
    }

    // Create children
    let child1 = manager
        .delegate_session(&parent_id, SessionScope::new(), 1800)
        .unwrap();
    let child2 = manager
        .delegate_session(&parent_id, SessionScope::new(), 1800)
        .unwrap();

    // Create grandchild from child1
    {
        let mut child = manager.sessions.get_mut(&child1.session.id).unwrap();
        child.allow_delegation = true;
    }
    let grandchild = manager
        .delegate_session(&child1.session.id, SessionScope::new(), 900)
        .unwrap();

    // Total: 4 sessions (parent + 2 children + 1 grandchild)
    assert_eq!(manager.active_session_count(), 4);

    // Revoke parent - should cascade to all descendants
    let revoked = manager.revoke_session_cascade(&parent_id);
    assert_eq!(revoked, 4);
    assert_eq!(manager.active_session_count(), 0);

    // All sessions should be gone
    assert!(manager.get_session(&parent_id).is_err());
    assert!(manager.get_session(&child1.session.id).is_err());
    assert!(manager.get_session(&child2.session.id).is_err());
    assert!(manager.get_session(&grandchild.session.id).is_err());
}

#[test]
fn test_get_delegated_sessions() {
    let manager = SessionManager::new(3600);
    let identity = create_test_identity("client1");

    // Create parent
    let parent_result = manager.create_scoped_session(identity.clone(), SessionScope::new(), None);
    let parent_id = parent_result.session.id.clone();

    {
        let mut parent = manager.sessions.get_mut(&parent_id).unwrap();
        parent.allow_delegation = true;
        parent.max_delegation_depth = 2;
    }

    // Create children
    manager
        .delegate_session(&parent_id, SessionScope::new(), 1800)
        .unwrap();
    manager
        .delegate_session(&parent_id, SessionScope::new(), 1800)
        .unwrap();

    // Get delegated sessions
    let delegated = manager.get_delegated_sessions(&parent_id);
    assert_eq!(delegated.len(), 2);
}

// === Rate Limiter Tests ===

#[test]
fn test_rate_limiter() {
    let limiter = RateLimiterState::new(3);

    // First 3 should succeed
    assert!(limiter.check_and_increment().is_ok());
    assert!(limiter.check_and_increment().is_ok());
    assert!(limiter.check_and_increment().is_ok());

    // 4th should fail
    assert!(limiter.check_and_increment().is_err());

    assert_eq!(limiter.current_count(), 3);
}
