#![no_main]

use libfuzzer_sys::fuzz_target;
use hsm_auth::rbac::{Role, Permission, RbacPolicy};

fuzz_target!(|data: &[u8]| {
    // Test RBAC policy operations with arbitrary data
    // These should never panic

    if data.is_empty() {
        return;
    }

    // Use first byte to select role, second for permission type
    let role = match data[0] % 4 {
        0 => Role::Admin,
        1 => Role::Operator,
        2 => Role::User,
        _ => Role::Auditor,
    };

    // Create permission from byte value
    let permission = match data.get(1).unwrap_or(&0) % 8 {
        0 => Permission::GenerateKey,
        1 => Permission::ImportKey,
        2 => Permission::DeleteKey,
        3 => Permission::Sign,
        4 => Permission::Encrypt,
        5 => Permission::Decrypt,
        6 => Permission::RotateKey,
        _ => Permission::GenerateKey,
    };

    // Test policy operations
    let mut policy = RbacPolicy::new();

    // Grant permission
    policy.grant(role, permission.clone());

    // Check permission
    let _ = policy.can(&role, &permission);

    // Revoke permission
    let _ = policy.revoke(&role, &permission);

    // Check hierarchy
    let _ = role.can_assume(&Role::User);
    let _ = role.hierarchy_level();
});
