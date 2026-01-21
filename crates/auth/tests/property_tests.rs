use hsm_auth::rbac::{Permission, PermissionFlags, RbacPolicy, Role};
use hsm_auth::session::{HashedToken, Session, SessionManager, SessionToken};
use hsm_auth::ClientIdentity;
use proptest::prelude::*;
use std::collections::HashSet;

// Helper function to create test identity
fn create_test_identity(cn: &str) -> ClientIdentity {
    ClientIdentity::new(
        cn.to_string(),
        None,
        "default".to_string(),
        vec![Role::User],
        "serial-123".to_string(),
    )
}

// Session token property tests
proptest! {
    #[test]
    fn prop_session_token_uniqueness(_seed in any::<u64>()) {
        // Generate two session tokens
        let token1 = SessionToken::new();
        let token2 = SessionToken::new();

        // They should be different (with overwhelming probability)
        prop_assert_ne!(token1.as_str(), token2.as_str());
    }

    #[test]
    fn prop_session_token_length(_seed in any::<u64>()) {
        // Session token should be 64 hex characters (32 bytes = 64 hex chars)
        let token = SessionToken::new();
        prop_assert_eq!(token.as_str().len(), 64);
    }

    #[test]
    fn prop_session_token_is_hex(_seed in any::<u64>()) {
        // Session token should be valid hex
        let token = SessionToken::new();
        for c in token.as_str().chars() {
            prop_assert!(c.is_ascii_hexdigit());
        }
    }

    #[test]
    fn prop_hashed_token_verify_roundtrip(_seed in any::<u64>()) {
        // A token should verify against its own hash
        let token = SessionToken::new();
        let hash = HashedToken::from_token(&token);

        prop_assert!(hash.verify(&token));
    }

    #[test]
    fn prop_hashed_token_different_tokens_different_hashes(_seed in any::<u64>()) {
        // Different tokens should produce different hashes that don't verify
        let token1 = SessionToken::new();
        let token2 = SessionToken::new();
        let hash1 = HashedToken::from_token(&token1);

        // token2 should NOT verify against hash1
        prop_assert!(!hash1.verify(&token2));
    }

    #[test]
    fn prop_session_token_from_string_roundtrip(s in "[a-f0-9]{64}") {
        // Any 64 hex char string should roundtrip through SessionToken
        let token = SessionToken::from_string(s.clone());
        prop_assert_eq!(token.as_str(), &s);
    }
}

// Session creation property tests
proptest! {
    #[test]
    fn prop_session_creation_valid(ttl in 1i64..86400) {
        let identity = create_test_identity("client1");
        let result = Session::create(identity.clone(), ttl);

        // Session should be valid
        prop_assert!(result.session.is_valid());
        prop_assert!(!result.session.is_expired());

        // Token should verify
        prop_assert!(result.session.verify_token(&result.token));
    }

    #[test]
    fn prop_session_creation_expired(ttl in -3600i64..-1) {
        let identity = create_test_identity("client1");
        let result = Session::create(identity.clone(), ttl);

        // Session should be expired
        prop_assert!(!result.session.is_valid());
        prop_assert!(result.session.is_expired());
    }

    #[test]
    fn prop_session_operation_count(ops in 1usize..2000) {
        let identity = create_test_identity("client1");
        let result = Session::create(identity, 3600);
        let mut session = result.session;

        // Increment operations and check threshold
        for i in 0..ops {
            let needs_rotation = session.increment_operation();
            if i < 999 {
                prop_assert!(!needs_rotation);
            } else {
                prop_assert!(needs_rotation);
            }
        }
        prop_assert_eq!(session.operation_count, ops as u64);
    }

    #[test]
    fn prop_session_ids_unique(_seed in any::<u64>()) {
        let identity = create_test_identity("client1");
        let result1 = Session::create(identity.clone(), 3600);
        let result2 = Session::create(identity.clone(), 3600);

        // Session IDs should be unique
        prop_assert_ne!(result1.session.id, result2.session.id);
    }
}

// SessionManager property tests
proptest! {
    #[test]
    fn prop_session_manager_create_validate(_seed in any::<u64>()) {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let result = manager.create_session(identity);

        // Should be able to validate the session
        let validated = manager.validate_session(&result.session.id);
        prop_assert!(validated.is_ok());
        prop_assert_eq!(validated.expect("session validation should succeed").id, result.session.id);
    }

    #[test]
    fn prop_session_manager_validate_with_token(_seed in any::<u64>()) {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let result = manager.create_session(identity);

        // Should validate with correct token
        let validated = manager.validate_session_with_token(&result.session.id, &result.token);
        prop_assert!(validated.is_ok());

        // Should fail with wrong token
        let wrong_token = SessionToken::new();
        let invalid = manager.validate_session_with_token(&result.session.id, &wrong_token);
        prop_assert!(invalid.is_err());
    }

    #[test]
    fn prop_session_manager_token_rotation(_seed in any::<u64>()) {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let result = manager.create_session(identity);
        let old_token = result.token;

        // Rotate token
        let new_token = manager.rotate_session_token(&result.session.id).expect("rotation should succeed");

        // Old token should no longer work
        let old_invalid = manager.validate_session_with_token(&result.session.id, &old_token);
        prop_assert!(old_invalid.is_err());

        // New token should work
        let new_valid = manager.validate_session_with_token(&result.session.id, &new_token);
        prop_assert!(new_valid.is_ok());
    }

    #[test]
    fn prop_session_manager_delete(_seed in any::<u64>()) {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let result = manager.create_session(identity);

        // Delete the session
        prop_assert!(manager.delete_session(&result.session.id).is_ok());

        // Should no longer be able to validate
        prop_assert!(manager.validate_session(&result.session.id).is_err());
    }
}

// RBAC Policy property tests
proptest! {
    #[test]
    fn prop_rbac_grant_check_consistency(role_idx in 0usize..4, perm_idx in 0usize..15) {
        let mut policy = RbacPolicy::new();
        let roles = Role::all();
        let permissions = Permission::all();

        let role = roles[role_idx];
        let permission = permissions[perm_idx];

        // After granting, permission should be available
        policy.grant(role, permission);
        prop_assert!(policy.can(&role, &permission));
    }

    #[test]
    fn prop_rbac_revoke_check_consistency(role_idx in 0usize..4, perm_idx in 0usize..15) {
        let mut policy = RbacPolicy::new();
        let roles = Role::all();
        let permissions = Permission::all();

        let role = roles[role_idx];
        let permission = permissions[perm_idx];

        // Grant first
        policy.grant(role, permission);
        prop_assert!(policy.can(&role, &permission));

        // After revoking, permission should not be available
        policy.revoke(&role, &permission);
        prop_assert!(!policy.can(&role, &permission));
    }

    #[test]
    fn prop_rbac_admin_has_all_permissions(perm_idx in 0usize..15) {
        let policy = RbacPolicy::new();
        let permissions = Permission::all();
        let permission = permissions[perm_idx];

        // Admin should have all permissions by default
        prop_assert!(policy.can(&Role::Admin, &permission));
    }

    #[test]
    fn prop_rbac_can_any_with_admin(perm_idx in 0usize..15, other_role_idx in 1usize..4) {
        let policy = RbacPolicy::new();
        let permissions = Permission::all();
        let permission = permissions[perm_idx];
        let roles = Role::all();
        let other_role = roles[other_role_idx];

        // With Admin in the list, can_any should always return true
        let roles_with_admin = vec![Role::Admin, other_role];
        prop_assert!(policy.can_any(&roles_with_admin, &permission));
    }

    #[test]
    fn prop_rbac_require_returns_ok_when_can(role_idx in 0usize..4, perm_idx in 0usize..15) {
        let policy = RbacPolicy::new();
        let roles = Role::all();
        let permissions = Permission::all();

        let role = roles[role_idx];
        let permission = permissions[perm_idx];

        // require() should return Ok iff can() returns true
        let can_result = policy.can(&role, &permission);
        let require_result = policy.require(&role, &permission);

        if can_result {
            prop_assert!(require_result.is_ok());
        } else {
            prop_assert!(require_result.is_err());
        }
    }
}

// Role hierarchy property tests
proptest! {
    #[test]
    fn prop_role_hierarchy_transitivity(role_idx in 0usize..4) {
        let roles = Role::all();
        let role = roles[role_idx];

        // If A can assume B and B can assume C, then A can assume C
        for mid_role in &roles {
            if role.can_assume(mid_role) {
                for low_role in &roles {
                    if mid_role.can_assume(low_role) {
                        prop_assert!(role.can_assume(low_role));
                    }
                }
            }
        }
    }

    #[test]
    fn prop_role_hierarchy_level_ordering(role1_idx in 0usize..4, role2_idx in 0usize..4) {
        let roles = Role::all();
        let role1 = roles[role1_idx];
        let role2 = roles[role2_idx];

        // If role1 has higher hierarchy level, it should be able to assume role2
        if role1.hierarchy_level() > role2.hierarchy_level() {
            prop_assert!(role1.can_assume(&role2));
        }
    }

    #[test]
    fn prop_role_parse_roundtrip(role_idx in 0usize..4) {
        let roles = Role::all();
        let role = roles[role_idx];

        // Parse should roundtrip
        let parsed: Role = role.as_str().parse().expect("parse should succeed");
        prop_assert_eq!(role, parsed);
    }

    #[test]
    fn prop_role_all_unique(_seed in any::<u64>()) {
        let roles = Role::all();
        let unique: HashSet<Role> = roles.iter().copied().collect();
        prop_assert_eq!(roles.len(), unique.len());
    }
}

// Permission property tests
proptest! {
    #[test]
    fn prop_permission_all_unique(_seed in any::<u64>()) {
        let permissions = Permission::all();
        let unique: HashSet<Permission> = permissions.iter().copied().collect();
        prop_assert_eq!(permissions.len(), unique.len());
    }

    #[test]
    fn prop_permission_flags_roundtrip(perm_idx in 0usize..15) {
        let permissions = Permission::all();
        let permission = permissions[perm_idx];

        // Converting to flags and checking should work
        let flag = permission.to_flag();
        let flags = PermissionFlags::from_permissions(&[permission]);

        prop_assert!(flags.contains(flag));
        prop_assert!(flags.has_permission(&permission));
    }

    #[test]
    fn prop_permission_flags_multiple(indices in prop::collection::vec(0usize..15, 1..15)) {
        let all_permissions = Permission::all();
        let selected: Vec<Permission> = indices.iter()
            .map(|&i| all_permissions[i % all_permissions.len()])
            .collect();

        let flags = PermissionFlags::from_permissions(&selected);

        // All selected permissions should be present in flags
        for perm in &selected {
            prop_assert!(flags.has_permission(perm));
        }
    }

    #[test]
    fn prop_permission_as_str_not_empty(perm_idx in 0usize..15) {
        let permissions = Permission::all();
        let permission = permissions[perm_idx];

        prop_assert!(!permission.as_str().is_empty());
        prop_assert!(permission.to_string().len() > 0);
    }

    #[test]
    fn prop_permission_privileged_consistency(perm_idx in 0usize..15) {
        let permissions = Permission::all();
        let permission = permissions[perm_idx];

        // is_privileged should be consistent with the list
        let privileged_perms = [
            Permission::ExportKey,
            Permission::ManageNamespaces,
            Permission::ManageRoles,
            Permission::DeleteKey,
            Permission::BackupKeys,
            Permission::RestoreKeys,
        ];

        let is_in_list = privileged_perms.contains(&permission);
        prop_assert_eq!(permission.is_privileged(), is_in_list);
    }
}

// Session with metadata property tests
proptest! {
    #[test]
    fn prop_session_metadata_ip_match(
        ip in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
    ) {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let result = manager.create_session_with_metadata(
            identity,
            Some(ip.clone()),
            Some("TestAgent/1.0".to_string()),
            None,
        );

        // Same IP should validate
        let validated = manager.validate_session_with_metadata(
            &result.session.id,
            &result.token,
            Some(ip),
            Some("TestAgent/1.0".to_string()),
            None,
        );
        prop_assert!(validated.is_ok());
    }

    #[test]
    fn prop_session_metadata_ip_mismatch(
        ip1 in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}",
        ip2 in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
    ) {
        prop_assume!(ip1 != ip2);

        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let result = manager.create_session_with_metadata(
            identity,
            Some(ip1),
            Some("TestAgent/1.0".to_string()),
            None,
        );

        // Different IP should fail (hijacking detection)
        let validated = manager.validate_session_with_metadata(
            &result.session.id,
            &result.token,
            Some(ip2),
            Some("TestAgent/1.0".to_string()),
            None,
        );
        prop_assert!(validated.is_err());
    }
}

// Constant-time comparison property tests (indirect through session token)
proptest! {
    #[test]
    fn prop_session_token_equality_reflexive(_seed in any::<u64>()) {
        let token = SessionToken::new();
        let token_copy = SessionToken::from_string(token.as_str().to_string());

        // Token should equal itself
        prop_assert_eq!(token, token_copy);
    }

    #[test]
    fn prop_session_token_equality_symmetric(_seed in any::<u64>()) {
        let token1 = SessionToken::new();
        let token1_copy = SessionToken::from_string(token1.as_str().to_string());

        // Equality should be symmetric
        prop_assert_eq!(token1 == token1_copy, token1_copy == token1);
    }
}
