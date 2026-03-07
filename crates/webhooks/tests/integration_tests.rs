//! Integration tests for the HSM Webhooks crate.
//!
//! Covers: webhook registration/deregistration, event filtering, HMAC signature
//! generation and verification, configuration validation, and dispatcher event matching.

use hsm_webhooks::{
    EventFilter, Webhook, WebhookConfig, WebhookDispatcher, WebhookEvent, WebhookEventType,
    WebhookRegistry, WebhookSigner,
};
use hsm_webhooks::filter::{event_severity, presets, EventSeverity};
use hsm_webhooks::delivery::{DeliveryResult, DeliveryStatus};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------------------
// 1. Webhook Registration and Deregistration
// ---------------------------------------------------------------------------

#[test]
fn test_register_single_webhook() {
    let registry = WebhookRegistry::new();
    let config = WebhookConfig::new("https://example.com/hook", "secret_key_12345678");
    let webhook = Webhook::new("Audit Hook", config, "admin");

    let id = registry.register(webhook);
    assert!(!id.is_empty());
    assert_eq!(registry.count(), 1);
}

#[test]
fn test_register_multiple_webhooks() {
    let registry = WebhookRegistry::new();

    for i in 0..5 {
        let config = WebhookConfig::new(
            &format!("https://example.com/hook{}", i),
            "secret_key_12345678",
        );
        let webhook = Webhook::new(&format!("Hook {}", i), config, "admin");
        registry.register(webhook);
    }

    assert_eq!(registry.count(), 5);
    assert_eq!(registry.list().len(), 5);
}

#[test]
fn test_deregister_webhook() {
    let registry = WebhookRegistry::new();
    let config = WebhookConfig::new("https://example.com/hook", "secret_key_12345678");
    let webhook = Webhook::new("To Delete", config, "admin");
    let id = registry.register(webhook);

    assert_eq!(registry.count(), 1);

    let deleted = registry.delete(&id);
    assert!(deleted.is_some());
    assert_eq!(deleted.unwrap().name, "To Delete");
    assert_eq!(registry.count(), 0);
}

#[test]
fn test_deregister_nonexistent_webhook() {
    let registry = WebhookRegistry::new();
    let deleted = registry.delete("nonexistent-id");
    assert!(deleted.is_none());
}

#[test]
fn test_get_webhook_by_id() {
    let registry = WebhookRegistry::new();
    let config = WebhookConfig::new("https://example.com/hook", "secret_key_12345678");
    let webhook = Webhook::new("My Hook", config, "admin");
    let id = registry.register(webhook);

    let retrieved = registry.get(&id);
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.name, "My Hook");
    assert_eq!(retrieved.owner, "admin");
}

#[test]
fn test_get_nonexistent_webhook() {
    let registry = WebhookRegistry::new();
    assert!(registry.get("no-such-id").is_none());
}

#[test]
fn test_update_webhook() {
    let registry = WebhookRegistry::new();
    let config = WebhookConfig::new("https://example.com/hook", "secret_key_12345678");
    let webhook = Webhook::new("Original", config, "admin");
    let id = registry.register(webhook);

    let updated = registry.update(&id, |w| {
        w.name = "Updated Name".to_string();
    });
    assert!(updated.is_some());
    assert_eq!(registry.get(&id).unwrap().name, "Updated Name");
}

#[test]
fn test_enable_disable_webhook() {
    let registry = WebhookRegistry::new();
    let config = WebhookConfig::new("https://example.com/hook", "secret_key_12345678");
    let webhook = Webhook::new("Toggle Hook", config, "admin");
    let id = registry.register(webhook);

    assert_eq!(registry.count_enabled(), 1);

    registry.disable(&id);
    assert_eq!(registry.count_enabled(), 0);
    assert!(!registry.get(&id).unwrap().config.enabled);

    registry.enable(&id);
    assert_eq!(registry.count_enabled(), 1);
    assert!(registry.get(&id).unwrap().config.enabled);
}

#[test]
fn test_list_by_owner() {
    let registry = WebhookRegistry::new();

    let cfg1 = WebhookConfig::new("https://example.com/a", "secret_key_12345678");
    registry.register(Webhook::new("A1", cfg1, "alice"));

    let cfg2 = WebhookConfig::new("https://example.com/b", "secret_key_12345678");
    registry.register(Webhook::new("A2", cfg2, "alice"));

    let cfg3 = WebhookConfig::new("https://example.com/c", "secret_key_12345678");
    registry.register(Webhook::new("B1", cfg3, "bob"));

    let alice_hooks = registry.list_by_owner("alice");
    assert_eq!(alice_hooks.len(), 2);

    let bob_hooks = registry.list_by_owner("bob");
    assert_eq!(bob_hooks.len(), 1);

    let unknown = registry.list_by_owner("charlie");
    assert_eq!(unknown.len(), 0);
}

#[test]
fn test_delivery_tracking_and_health() {
    let registry = WebhookRegistry::new();
    let config = WebhookConfig::new("https://example.com/hook", "secret_key_12345678");
    let webhook = Webhook::new("Tracked", config, "admin");
    let id = registry.register(webhook);

    // Record mixed deliveries
    for _ in 0..8 {
        registry.record_delivery(&id, true);
    }
    for _ in 0..2 {
        registry.record_delivery(&id, false);
    }

    let wh = registry.get(&id).unwrap();
    assert_eq!(wh.delivery_count, 10);
    assert_eq!(wh.success_count, 8);
    assert_eq!(wh.failure_count, 2);
    assert!((wh.success_rate() - 0.8).abs() < 0.001);
    // 80% < 90%, so not healthy with 10+ deliveries
    assert!(!wh.is_healthy());
}

#[test]
fn test_webhook_healthy_with_few_deliveries() {
    let config = WebhookConfig::new("https://example.com/hook", "secret_key_12345678");
    let mut webhook = Webhook::new("Few", config, "admin");

    // Even all failures, < 10 deliveries should still be "healthy"
    for _ in 0..5 {
        webhook.record_delivery(false);
    }
    assert!(webhook.is_healthy());
}

#[test]
fn test_get_unhealthy_webhooks() {
    let registry = WebhookRegistry::new();

    let cfg1 = WebhookConfig::new("https://example.com/healthy", "secret_key_12345678");
    let wh1 = Webhook::new("Healthy", cfg1, "admin");
    let id1 = registry.register(wh1);

    let cfg2 = WebhookConfig::new("https://example.com/unhealthy", "secret_key_12345678");
    let wh2 = Webhook::new("Unhealthy", cfg2, "admin");
    let id2 = registry.register(wh2);

    // Make id1 healthy (all successes)
    for _ in 0..20 {
        registry.record_delivery(&id1, true);
    }

    // Make id2 unhealthy (all failures, > 10 deliveries)
    for _ in 0..15 {
        registry.record_delivery(&id2, false);
    }

    let unhealthy = registry.get_unhealthy();
    assert_eq!(unhealthy.len(), 1);
    assert_eq!(unhealthy[0].name, "Unhealthy");
}

// ---------------------------------------------------------------------------
// 2. Event Filtering
// ---------------------------------------------------------------------------

#[test]
fn test_filter_all_passes_everything() {
    let filter = EventFilter::all();
    for event_type in WebhookEventType::all() {
        assert!(filter.matches(*event_type, "any-namespace"));
    }
}

#[test]
fn test_filter_specific_events() {
    let filter = EventFilter::events(&[WebhookEventType::KeyCreated, WebhookEventType::KeyDeleted]);

    assert!(filter.matches(WebhookEventType::KeyCreated, "default"));
    assert!(filter.matches(WebhookEventType::KeyDeleted, "default"));
    assert!(!filter.matches(WebhookEventType::KeyRotated, "default"));
    assert!(!filter.matches(WebhookEventType::BackupStarted, "default"));
}

#[test]
fn test_filter_include_and_exclude_events() {
    // Include key events, but exclude KeyUsed
    let filter = EventFilter::events(&[
        WebhookEventType::KeyCreated,
        WebhookEventType::KeyDeleted,
        WebhookEventType::KeyUsed,
    ])
    .exclude_event(WebhookEventType::KeyUsed);

    assert!(filter.matches(WebhookEventType::KeyCreated, "default"));
    assert!(!filter.matches(WebhookEventType::KeyUsed, "default"));
}

#[test]
fn test_filter_namespace_inclusion() {
    let filter = EventFilter::all()
        .include_namespace("production")
        .include_namespace("staging");

    assert!(filter.matches(WebhookEventType::KeyCreated, "production"));
    assert!(filter.matches(WebhookEventType::KeyCreated, "staging"));
    assert!(!filter.matches(WebhookEventType::KeyCreated, "development"));
}

#[test]
fn test_filter_namespace_exclusion() {
    let filter = EventFilter::all()
        .exclude_namespace("test")
        .exclude_namespace("development");

    assert!(filter.matches(WebhookEventType::KeyCreated, "production"));
    assert!(!filter.matches(WebhookEventType::KeyCreated, "test"));
    assert!(!filter.matches(WebhookEventType::KeyCreated, "development"));
}

#[test]
fn test_filter_combined_event_and_namespace() {
    let filter = EventFilter::events(&[WebhookEventType::KeyCreated])
        .include_namespace("production");

    // Must match both: correct event AND correct namespace
    assert!(filter.matches(WebhookEventType::KeyCreated, "production"));
    assert!(!filter.matches(WebhookEventType::KeyCreated, "staging"));
    assert!(!filter.matches(WebhookEventType::KeyDeleted, "production"));
}

#[test]
fn test_filter_severity_threshold() {
    let filter = EventFilter::all().with_min_severity(EventSeverity::Warning);

    // Debug-level event should be rejected
    assert!(!filter.matches_with_severity(
        WebhookEventType::KeyUsed,
        "default",
        EventSeverity::Debug,
    ));

    // Info-level event should be rejected
    assert!(!filter.matches_with_severity(
        WebhookEventType::KeyCreated,
        "default",
        EventSeverity::Info,
    ));

    // Warning-level event should pass
    assert!(filter.matches_with_severity(
        WebhookEventType::KeyDeleted,
        "default",
        EventSeverity::Warning,
    ));

    // Critical-level event should pass
    assert!(filter.matches_with_severity(
        WebhookEventType::PolicyViolated,
        "default",
        EventSeverity::Critical,
    ));
}

#[test]
fn test_event_severity_mapping() {
    assert_eq!(
        event_severity(WebhookEventType::AuthenticationFailed),
        EventSeverity::Critical
    );
    assert_eq!(
        event_severity(WebhookEventType::KeyDeleted),
        EventSeverity::Warning
    );
    assert_eq!(
        event_severity(WebhookEventType::KeyCreated),
        EventSeverity::Info
    );
    assert_eq!(
        event_severity(WebhookEventType::KeyUsed),
        EventSeverity::Debug
    );
}

#[test]
fn test_preset_security_filter() {
    let filter = presets::security_only();

    assert!(filter.matches(WebhookEventType::AuthenticationFailed, "default"));
    assert!(filter.matches(WebhookEventType::AuthorizationDenied, "default"));
    assert!(filter.matches(WebhookEventType::PolicyViolated, "default"));
    assert!(filter.matches(WebhookEventType::RateLimitExceeded, "default"));
    assert!(filter.matches(WebhookEventType::KeyDeleted, "default"));
    assert!(filter.matches(WebhookEventType::KeyExported, "default"));

    // Non-security events should not match
    assert!(!filter.matches(WebhookEventType::KeyCreated, "default"));
    assert!(!filter.matches(WebhookEventType::BackupStarted, "default"));
    assert!(!filter.matches(WebhookEventType::SystemStartup, "default"));
}

#[test]
fn test_preset_key_lifecycle_filter() {
    let filter = presets::key_lifecycle();

    assert!(filter.matches(WebhookEventType::KeyCreated, "default"));
    assert!(filter.matches(WebhookEventType::KeyDeleted, "default"));
    assert!(filter.matches(WebhookEventType::KeyRotated, "default"));
    assert!(filter.matches(WebhookEventType::KeyExported, "default"));
    assert!(!filter.matches(WebhookEventType::KeyUsed, "default"));
    assert!(!filter.matches(WebhookEventType::SessionCreated, "default"));
}

#[test]
fn test_preset_backup_filter() {
    let filter = presets::backup_events();

    assert!(filter.matches(WebhookEventType::BackupStarted, "default"));
    assert!(filter.matches(WebhookEventType::BackupCompleted, "default"));
    assert!(filter.matches(WebhookEventType::BackupFailed, "default"));
    assert!(!filter.matches(WebhookEventType::KeyCreated, "default"));
}

#[test]
fn test_preset_system_filter() {
    let filter = presets::system_events();

    assert!(filter.matches(WebhookEventType::SystemStartup, "default"));
    assert!(filter.matches(WebhookEventType::SystemShutdown, "default"));
    assert!(!filter.matches(WebhookEventType::KeyCreated, "default"));
}

// ---------------------------------------------------------------------------
// 3. HMAC Signature Generation and Verification
// ---------------------------------------------------------------------------

#[test]
fn test_sign_and_verify_basic() {
    let signer = WebhookSigner::new("my_webhook_secret_key");
    let payload = b"hello world";

    let signature = signer.sign(payload);
    assert!(signature.starts_with("sha256="));
    assert!(signer.verify(payload, &signature));
}

#[test]
fn test_different_secrets_produce_different_signatures() {
    let signer_a = WebhookSigner::new("secret_a_1234567890");
    let signer_b = WebhookSigner::new("secret_b_1234567890");
    let payload = b"same payload";

    let sig_a = signer_a.sign(payload);
    let sig_b = signer_b.sign(payload);

    assert_ne!(sig_a, sig_b);
}

#[test]
fn test_verify_fails_with_wrong_secret() {
    let signer_a = WebhookSigner::new("correct_secret_key_1");
    let signer_b = WebhookSigner::new("wrong_secret_key_abc");
    let payload = b"test payload";

    let signature = signer_a.sign(payload);
    assert!(!signer_b.verify(payload, &signature));
}

#[test]
fn test_verify_fails_with_tampered_payload() {
    let signer = WebhookSigner::new("webhook_secret_key_1");
    let original = b"original payload data";
    let tampered = b"tampered payload data";

    let signature = signer.sign(original);
    assert!(!signer.verify(tampered, &signature));
}

#[test]
fn test_verify_fails_with_invalid_signature_format() {
    let signer = WebhookSigner::new("webhook_secret_key_1");
    let payload = b"test";

    assert!(!signer.verify(payload, "not-a-valid-signature"));
    assert!(!signer.verify(payload, "sha256=0000"));
    assert!(!signer.verify(payload, ""));
}

#[test]
fn test_sign_with_timestamp() {
    let signer = WebhookSigner::new("timestamp_secret_key");
    let payload = b"payload with timestamp";
    let timestamp = 1700000000i64;

    let signature = signer.sign_with_timestamp(payload, timestamp);
    assert!(signature.starts_with("sha256="));

    // Same timestamp should verify
    assert!(signer.verify_with_timestamp(payload, timestamp, &signature));

    // Different timestamp should fail
    assert!(!signer.verify_with_timestamp(payload, timestamp + 1, &signature));
    assert!(!signer.verify_with_timestamp(payload, timestamp - 1, &signature));
}

#[test]
fn test_verify_fresh_signature() {
    let signer = WebhookSigner::new("fresh_secret_key_abc");
    let payload = b"fresh payload";
    let now = chrono::Utc::now().timestamp();

    let signature = signer.sign_with_timestamp(payload, now);

    // Recent signature within 300 second window should pass
    assert!(signer.verify_fresh(payload, now, &signature, 300));
}

#[test]
fn test_verify_fresh_rejects_old_signature() {
    let signer = WebhookSigner::new("fresh_secret_key_abc");
    let payload = b"old payload";
    let now = chrono::Utc::now().timestamp();
    let old_timestamp = now - 600; // 10 minutes ago

    let signature = signer.sign_with_timestamp(payload, old_timestamp);

    // Should fail with 5-minute tolerance
    assert!(!signer.verify_fresh(payload, old_timestamp, &signature, 300));
}

#[test]
fn test_verify_fresh_rejects_future_signature() {
    let signer = WebhookSigner::new("fresh_secret_key_abc");
    let payload = b"future payload";
    let future_timestamp = chrono::Utc::now().timestamp() + 600;

    let signature = signer.sign_with_timestamp(payload, future_timestamp);

    // Future timestamp should fail
    assert!(!signer.verify_fresh(payload, future_timestamp, &signature, 300));
}

#[test]
fn test_sign_deterministic() {
    let signer = WebhookSigner::new("deterministic_secret!");
    let payload = b"deterministic payload";

    let sig1 = signer.sign(payload);
    let sig2 = signer.sign(payload);

    assert_eq!(sig1, sig2);
}

#[test]
fn test_sign_empty_payload() {
    let signer = WebhookSigner::new("empty_payload_secret");
    let payload = b"";

    let signature = signer.sign(payload);
    assert!(signature.starts_with("sha256="));
    assert!(signer.verify(payload, &signature));
}

#[test]
fn test_signer_from_bytes() {
    let secret_bytes = b"binary_secret_data__";
    let signer = WebhookSigner::from_bytes(secret_bytes);
    let payload = b"test payload";

    let signature = signer.sign(payload);
    assert!(signer.verify(payload, &signature));
}

#[test]
fn test_generate_secret_uniqueness() {
    let s1 = hsm_webhooks::signature::generate_secret(32);
    let s2 = hsm_webhooks::signature::generate_secret(32);

    assert_eq!(s1.len(), 64); // 32 bytes -> 64 hex chars
    assert_ne!(s1, s2);
}

#[test]
fn test_signature_header_constants() {
    assert_eq!(hsm_webhooks::signature::headers::SIGNATURE, "X-Webhook-Signature");
    assert_eq!(hsm_webhooks::signature::headers::TIMESTAMP, "X-Webhook-Timestamp");
    assert_eq!(hsm_webhooks::signature::headers::ID, "X-Webhook-ID");
    assert_eq!(hsm_webhooks::signature::headers::EVENT_TYPE, "X-Webhook-Event");
}

// ---------------------------------------------------------------------------
// 4. Configuration Validation
// ---------------------------------------------------------------------------

#[test]
fn test_valid_config() {
    let config = WebhookConfig::new("https://example.com/webhook", "super_secret_key_123");
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_rejects_empty_url() {
    let config = WebhookConfig::new("", "super_secret_key_123");
    let err = config.validate().unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn test_config_rejects_invalid_url() {
    let config = WebhookConfig::new("not-a-url", "super_secret_key_123");
    assert!(config.validate().is_err());
}

#[test]
fn test_config_rejects_http_url() {
    let config = WebhookConfig::new("http://example.com/webhook", "super_secret_key_123");
    let err = config.validate().unwrap_err();
    assert!(err.contains("https"));
}

#[test]
fn test_config_rejects_short_secret() {
    let config = WebhookConfig::new("https://example.com/webhook", "short");
    let err = config.validate().unwrap_err();
    assert!(err.contains("16"));
}

#[test]
fn test_config_rejects_localhost() {
    let config = WebhookConfig::new("https://localhost/webhook", "super_secret_key_123");
    let err = config.validate().unwrap_err();
    assert!(err.contains("not allowed"));
}

#[test]
fn test_config_rejects_local_domain() {
    let config = WebhookConfig::new("https://myhost.local/webhook", "super_secret_key_123");
    assert!(config.validate().is_err());
}

#[test]
fn test_config_rejects_internal_domain() {
    let config = WebhookConfig::new(
        "https://service.internal/webhook",
        "super_secret_key_123",
    );
    assert!(config.validate().is_err());
}

#[test]
fn test_config_rejects_private_ip_10() {
    let config = WebhookConfig::new("https://10.0.0.1/webhook", "super_secret_key_123");
    assert!(config.validate().is_err());
}

#[test]
fn test_config_rejects_private_ip_172() {
    let config = WebhookConfig::new("https://172.16.0.1/webhook", "super_secret_key_123");
    assert!(config.validate().is_err());
}

#[test]
fn test_config_rejects_private_ip_192() {
    let config = WebhookConfig::new("https://192.168.1.1/webhook", "super_secret_key_123");
    assert!(config.validate().is_err());
}

#[test]
fn test_config_rejects_loopback_ip() {
    let config = WebhookConfig::new("https://127.0.0.1/webhook", "super_secret_key_123");
    assert!(config.validate().is_err());
}

#[test]
fn test_config_builder_methods() {
    let config = WebhookConfig::new("https://example.com/hook", "super_secret_key_123")
        .with_timeout(Duration::from_secs(60))
        .with_max_retries(5)
        .with_retry_delay(Duration::from_secs(2))
        .with_header("Authorization", "Bearer token123");

    assert_eq!(config.timeout, Duration::from_secs(60));
    assert_eq!(config.max_retries, 5);
    assert_eq!(config.retry_delay, Duration::from_secs(2));
    assert_eq!(
        config.headers.get("Authorization"),
        Some(&"Bearer token123".to_string())
    );
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_default_values() {
    let config = WebhookConfig::new("https://example.com/hook", "super_secret_key_123");

    assert_eq!(config.timeout, Duration::from_secs(30));
    assert_eq!(config.max_retries, 3);
    assert_eq!(config.retry_delay, Duration::from_secs(1));
    assert!(config.enabled);
    assert!(config.headers.is_empty());
}

#[test]
fn test_config_set_enabled() {
    let mut config = WebhookConfig::new("https://example.com/hook", "super_secret_key_123");
    assert!(config.enabled);

    config.set_enabled(false);
    assert!(!config.enabled);

    config.set_enabled(true);
    assert!(config.enabled);
}

// ---------------------------------------------------------------------------
// 5. Dispatcher Event Matching
// ---------------------------------------------------------------------------

#[test]
fn test_registry_get_matching_all_events() {
    let registry = WebhookRegistry::new();

    let config = WebhookConfig::new("https://example.com/all", "secret_key_12345678");
    let webhook = Webhook::new("All Events", config, "admin");
    registry.register(webhook);

    // An "all" filter webhook should match any event type
    for event_type in WebhookEventType::all() {
        let matches = registry.get_matching(*event_type, "default");
        assert_eq!(matches.len(), 1, "Should match event type: {:?}", event_type);
    }
}

#[test]
fn test_registry_get_matching_filtered_events() {
    let registry = WebhookRegistry::new();

    // Webhook for key events only
    let cfg1 = WebhookConfig::new("https://example.com/keys", "secret_key_12345678");
    let wh1 = Webhook::new("Key Events", cfg1, "admin")
        .with_filter(presets::key_lifecycle());
    registry.register(wh1);

    // Webhook for security events only
    let cfg2 = WebhookConfig::new("https://example.com/security", "secret_key_12345678");
    let wh2 = Webhook::new("Security Events", cfg2, "admin")
        .with_filter(presets::security_only());
    registry.register(wh2);

    // KeyCreated should match only key lifecycle webhook
    let key_matches = registry.get_matching(WebhookEventType::KeyCreated, "default");
    assert_eq!(key_matches.len(), 1);
    assert_eq!(key_matches[0].name, "Key Events");

    // AuthenticationFailed should match only security webhook
    let sec_matches = registry.get_matching(WebhookEventType::AuthenticationFailed, "default");
    assert_eq!(sec_matches.len(), 1);
    assert_eq!(sec_matches[0].name, "Security Events");

    // KeyDeleted appears in both filters
    let key_del = registry.get_matching(WebhookEventType::KeyDeleted, "default");
    assert_eq!(key_del.len(), 2);

    // BackupStarted not in either filter
    let backup_matches = registry.get_matching(WebhookEventType::BackupStarted, "default");
    assert_eq!(backup_matches.len(), 0);
}

#[test]
fn test_registry_get_matching_disabled_webhooks_excluded() {
    let registry = WebhookRegistry::new();

    let config = WebhookConfig::new("https://example.com/hook", "secret_key_12345678");
    let webhook = Webhook::new("Disabled Hook", config, "admin");
    let id = registry.register(webhook);

    // Initially matches
    let matches = registry.get_matching(WebhookEventType::KeyCreated, "default");
    assert_eq!(matches.len(), 1);

    // Disable the webhook
    registry.disable(&id);

    // Now should not match
    let matches = registry.get_matching(WebhookEventType::KeyCreated, "default");
    assert_eq!(matches.len(), 0);
}

#[test]
fn test_registry_get_matching_namespace_filtering() {
    let registry = WebhookRegistry::new();

    let config = WebhookConfig::new("https://example.com/prod", "secret_key_12345678");
    let webhook = Webhook::new("Prod Only", config, "admin")
        .with_filter(EventFilter::all().include_namespace("production"));
    registry.register(webhook);

    let prod_matches = registry.get_matching(WebhookEventType::KeyCreated, "production");
    assert_eq!(prod_matches.len(), 1);

    let staging_matches = registry.get_matching(WebhookEventType::KeyCreated, "staging");
    assert_eq!(staging_matches.len(), 0);
}

#[test]
fn test_registry_get_matching_mixed_filters() {
    let registry = WebhookRegistry::new();

    // All events, all namespaces
    let cfg1 = WebhookConfig::new("https://example.com/all", "secret_key_12345678");
    registry.register(Webhook::new("All", cfg1, "admin"));

    // Key events only, production namespace
    let cfg2 = WebhookConfig::new("https://example.com/prod-keys", "secret_key_12345678");
    let wh2 = Webhook::new("Prod Keys", cfg2, "admin").with_filter(
        EventFilter::events(&[WebhookEventType::KeyCreated, WebhookEventType::KeyDeleted])
            .include_namespace("production"),
    );
    registry.register(wh2);

    // KeyCreated in production -> both match
    let matches = registry.get_matching(WebhookEventType::KeyCreated, "production");
    assert_eq!(matches.len(), 2);

    // KeyCreated in staging -> only "All" matches
    let matches = registry.get_matching(WebhookEventType::KeyCreated, "staging");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].name, "All");

    // BackupStarted in production -> only "All" matches (not a key event)
    let matches = registry.get_matching(WebhookEventType::BackupStarted, "production");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].name, "All");
}

// ---------------------------------------------------------------------------
// 6. WebhookEvent and WebhookEventType
// ---------------------------------------------------------------------------

#[test]
fn test_event_type_roundtrip_str() {
    for event_type in WebhookEventType::all() {
        let as_str = event_type.as_str();
        let parsed = WebhookEventType::parse(as_str);
        assert_eq!(parsed, Some(*event_type), "Roundtrip failed for {:?}", event_type);
    }
}

#[test]
fn test_event_type_parse_unknown() {
    assert_eq!(WebhookEventType::parse("unknown.event"), None);
    assert_eq!(WebhookEventType::parse(""), None);
}

#[test]
fn test_event_type_display() {
    assert_eq!(WebhookEventType::KeyCreated.to_string(), "key.created");
    assert_eq!(
        WebhookEventType::AuthenticationFailed.to_string(),
        "security.auth_failed"
    );
}

#[test]
fn test_webhook_event_creation() {
    let event = WebhookEvent::new(
        WebhookEventType::KeyCreated,
        "production",
        json!({"key_id": "key-abc", "algorithm": "Ed25519"}),
    );

    assert!(!event.id.is_empty());
    assert_eq!(event.event_type, WebhookEventType::KeyCreated);
    assert_eq!(event.namespace, "production");
    assert_eq!(event.data["key_id"], "key-abc");
}

#[test]
fn test_webhook_event_serialization_roundtrip() {
    let event = WebhookEvent::new(
        WebhookEventType::BackupCompleted,
        "default",
        json!({"backup_id": "bk-123", "keys_count": 42}),
    );

    let serialized = serde_json::to_string(&event).unwrap();
    let deserialized: WebhookEvent = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.id, event.id);
    assert_eq!(deserialized.event_type, event.event_type);
    assert_eq!(deserialized.namespace, event.namespace);
    assert_eq!(deserialized.data["keys_count"], 42);
}

// ---------------------------------------------------------------------------
// 7. Delivery types
// ---------------------------------------------------------------------------

#[test]
fn test_delivery_result_serialization() {
    let result = DeliveryResult {
        webhook_id: "wh-001".to_string(),
        event_id: "evt-001".to_string(),
        status: DeliveryStatus::Success,
        http_status: Some(200),
        attempt: 1,
        timestamp: chrono::Utc::now(),
        duration_ms: 120,
        error: None,
    };

    let json = serde_json::to_string(&result).unwrap();
    let parsed: DeliveryResult = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.webhook_id, "wh-001");
    assert_eq!(parsed.status, DeliveryStatus::Success);
    assert_eq!(parsed.http_status, Some(200));
}

#[test]
fn test_delivery_status_variants() {
    let success = DeliveryStatus::Success;
    let failed = DeliveryStatus::Failed;
    let pending = DeliveryStatus::PendingRetry;

    assert_ne!(success, failed);
    assert_ne!(success, pending);
    assert_ne!(failed, pending);
}

// ---------------------------------------------------------------------------
// 8. Dispatcher (async tests)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dispatcher_creation_with_empty_registry() {
    let registry = Arc::new(WebhookRegistry::new());
    let dispatcher = WebhookDispatcher::new(registry);
    assert_eq!(dispatcher.registry().count(), 0);
}

#[tokio::test]
async fn test_dispatcher_emit_returns_event_id() {
    let registry = Arc::new(WebhookRegistry::new());
    let dispatcher = WebhookDispatcher::new(registry);

    let event_id = dispatcher
        .emit(
            WebhookEventType::KeyCreated,
            "default",
            json!({"key_id": "k-1"}),
        )
        .await
        .unwrap();

    assert!(!event_id.is_empty());
}

#[tokio::test]
async fn test_dispatcher_dispatch_sync() {
    let registry = Arc::new(WebhookRegistry::new());
    let dispatcher = WebhookDispatcher::new(registry);

    let event = WebhookEvent::new(
        WebhookEventType::SystemStartup,
        "default",
        json!({"version": "1.0"}),
    );

    let result = dispatcher.dispatch_sync(event);
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_dispatcher_builder() {
    let registry = Arc::new(WebhookRegistry::new());
    let dispatcher = hsm_webhooks::dispatcher::WebhookDispatcherBuilder::new()
        .registry(registry)
        .channel_size(500)
        .build();

    assert_eq!(dispatcher.registry().count(), 0);
}

#[tokio::test]
async fn test_dispatcher_with_registered_webhooks() {
    let registry = Arc::new(WebhookRegistry::new());

    let config = WebhookConfig::new("https://example.com/hook", "secret_key_12345678");
    let webhook = Webhook::new("Test Hook", config, "admin")
        .with_filter(presets::key_lifecycle());
    registry.register(webhook);

    let dispatcher = WebhookDispatcher::new(registry.clone());

    // Emit an event (it will fail to deliver since example.com won't respond,
    // but the dispatch itself should succeed)
    let event_id = dispatcher
        .emit(
            WebhookEventType::KeyCreated,
            "default",
            json!({"key_id": "k-new"}),
        )
        .await
        .unwrap();

    assert!(!event_id.is_empty());
    assert_eq!(dispatcher.registry().count(), 1);
}

// ---------------------------------------------------------------------------
// 9. Webhook builder pattern
// ---------------------------------------------------------------------------

#[test]
fn test_webhook_with_description() {
    let config = WebhookConfig::new("https://example.com/hook", "secret_key_12345678");
    let webhook = Webhook::new("Described", config, "admin")
        .with_description("This webhook monitors key events");

    assert_eq!(
        webhook.description,
        Some("This webhook monitors key events".to_string())
    );
}

#[test]
fn test_webhook_with_filter() {
    let config = WebhookConfig::new("https://example.com/hook", "secret_key_12345678");
    let filter = EventFilter::events(&[WebhookEventType::BackupFailed]);
    let webhook = Webhook::new("Backup Alerts", config, "ops").with_filter(filter);

    assert!(webhook
        .filter
        .matches(WebhookEventType::BackupFailed, "any"));
    assert!(!webhook
        .filter
        .matches(WebhookEventType::BackupStarted, "any"));
}

#[test]
fn test_webhook_success_rate_no_deliveries() {
    let config = WebhookConfig::new("https://example.com/hook", "secret_key_12345678");
    let webhook = Webhook::new("Fresh", config, "admin");
    // Success rate should be 1.0 with no deliveries
    assert!((webhook.success_rate() - 1.0).abs() < f64::EPSILON);
}
