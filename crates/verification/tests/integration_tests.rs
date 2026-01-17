//! Integration tests for formal verification framework
//!
//! These tests verify that all cryptographic operations satisfy their
//! formal properties using SMT-based bounded model checking.

use hsm_verification::*;
use z3::ast::Ast;

#[test]
fn test_comprehensive_ed25519_verification() {
    println!("\n========================================");
    println!("Testing Ed25519 Formal Verification");
    println!("========================================\n");

    let result = ed25519::verify_ed25519_correctness();

    match result {
        Ok(()) => println!("✓ Ed25519 verification completed successfully"),
        Err(e) => panic!("✗ Ed25519 verification failed: {}", e),
    }
}

#[test]
fn test_comprehensive_ecdsa_verification() {
    println!("\n========================================");
    println!("Testing ECDSA Formal Verification");
    println!("========================================\n");

    let result = ecdsa::verify_ecdsa_correctness();

    match result {
        Ok(()) => println!("✓ ECDSA verification completed successfully"),
        Err(e) => panic!("✗ ECDSA verification failed: {}", e),
    }
}

#[test]
fn test_comprehensive_rsa_verification() {
    println!("\n========================================");
    println!("Testing RSA Formal Verification");
    println!("========================================\n");

    let result = rsa::verify_rsa_correctness();

    match result {
        Ok(()) => println!("✓ RSA verification completed successfully"),
        Err(e) => panic!("✗ RSA verification failed: {}", e),
    }
}

#[test]
fn test_comprehensive_shamir_verification() {
    println!("\n========================================");
    println!("Testing Shamir's Secret Sharing Formal Verification");
    println!("========================================\n");

    let result = shamir::verify_shamir_correctness();

    match result {
        Ok(()) => println!("✓ Shamir's Secret Sharing verification completed successfully"),
        Err(e) => panic!("✗ Shamir verification failed: {}", e),
    }
}

#[test]
fn test_all_crypto_operations() {
    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║  HSM Comprehensive Formal Verification Suite          ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    let mut all_passed = true;

    // Ed25519 verification
    println!("[1/4] Running Ed25519 verification...");
    if let Err(e) = ed25519::verify_ed25519_correctness() {
        println!("      ✗ Failed: {}", e);
        all_passed = false;
    } else {
        println!("      ✓ Passed");
    }

    // ECDSA verification
    println!("\n[2/4] Running ECDSA verification...");
    if let Err(e) = ecdsa::verify_ecdsa_correctness() {
        println!("      ✗ Failed: {}", e);
        all_passed = false;
    } else {
        println!("      ✓ Passed");
    }

    // RSA verification
    println!("\n[3/4] Running RSA verification...");
    if let Err(e) = rsa::verify_rsa_correctness() {
        println!("      ✗ Failed: {}", e);
        all_passed = false;
    } else {
        println!("      ✓ Passed");
    }

    // Shamir's Secret Sharing verification
    println!("\n[4/4] Running Shamir's Secret Sharing verification...");
    if let Err(e) = shamir::verify_shamir_correctness() {
        println!("      ✗ Failed: {}", e);
        all_passed = false;
    } else {
        println!("      ✓ Passed");
    }

    println!("\n╔════════════════════════════════════════════════════════╗");
    if all_passed {
        println!("║  ✓ ALL FORMAL VERIFICATION CHECKS PASSED             ║");
    } else {
        println!("║  ✗ SOME FORMAL VERIFICATION CHECKS FAILED            ║");
    }
    println!("╚════════════════════════════════════════════════════════╝\n");

    assert!(all_passed, "Some verification checks failed");
}

#[test]
fn test_verification_context_operations() {
    use hsm_verification::VerificationContext;

    let ctx = VerificationContext::new();
    let z3_ctx = ctx.create_z3_context();

    // Test that Z3 context works
    use z3::ast::{Ast, Int};
    let x = Int::new_const(&z3_ctx, "x");
    let y = Int::new_const(&z3_ctx, "y");

    // Simple constraint: x + y = 10, x = 3
    use z3::Solver;
    let solver = Solver::new(&z3_ctx);
    solver.assert(&Int::add(&z3_ctx, &[&x, &y])._eq(&Int::from_i64(&z3_ctx, 10)));
    solver.assert(&x._eq(&Int::from_i64(&z3_ctx, 3)));

    assert_eq!(solver.check(), z3::SatResult::Sat);

    let model = solver.get_model().unwrap();
    let y_val = model.eval(&y, true).unwrap().as_i64().unwrap();
    assert_eq!(y_val, 7);
}

#[test]
fn test_bounded_checker_basic_properties() {
    use hsm_verification::bounded_check::BoundedChecker;
    use z3::{Config, Context};

    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let checker = BoundedChecker::new(&ctx, 8);

    // Property: x = x (tautology)
    let x = checker.encoder().bv_const("x");
    let property = x._eq(&x);

    let result = checker.verify_property(&property).unwrap();
    assert_eq!(
        result,
        hsm_verification::bounded_check::VerificationResult::Verified
    );
}

#[test]
fn test_smt_encoder_field_operations() {
    use hsm_verification::smt_encoder::FiniteFieldEncoder;
    use z3::{Config, Context, Solver};

    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let encoder = FiniteFieldEncoder::new(&ctx, 8);

    // Test modular addition
    let a = encoder.bv_from_u64(250);
    let b = encoder.bv_from_u64(10);
    let modulus = encoder.bv_from_u64(256);

    let result = encoder.mod_add(&a, &b, &modulus);

    let solver = Solver::new(&ctx);
    solver.assert(&result._eq(&encoder.bv_from_u64(4))); // (250 + 10) mod 256 = 4

    assert_eq!(solver.check(), z3::SatResult::Sat);
}

#[test]
fn test_ed25519_field_parameters() {
    use hsm_verification::smt_encoder::Ed25519Field;
    use num_bigint::BigUint;
    use num_traits::One;

    let field = Ed25519Field::new();

    // Verify p = 2^255 - 19
    let expected_p = (BigUint::one() << 255) - BigUint::from(19u32);
    assert_eq!(field.p, expected_p);

    // Verify l (curve order) is non-zero and large
    assert!(field.l > (BigUint::one() << 252));
}

#[test]
fn test_p256_field_parameters() {
    use hsm_verification::smt_encoder::P256Field;
    use num_bigint::BigUint;
    use num_traits::One;

    let field = P256Field::new();

    // Verify p and n are large enough
    assert!(field.p > (BigUint::one() << 255));
    assert!(field.n > (BigUint::one() << 255));
}
