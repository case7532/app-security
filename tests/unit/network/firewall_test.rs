use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::{ModuleConfig, ModuleEvent, ModuleStatus, SecurityModule};
use app_security::network::firewall::config::{FirewallAction as ConfigAction, FirewallConfig, FirewallRuleConfig};
use app_security::network::firewall::platform::{FirewallPlatform, MockFirewallPlatform};
use app_security::network::firewall::rules::{FirewallAction, FirewallDirection, FirewallError, FirewallRule};
use app_security::network::firewall::FirewallModule;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn setup() -> (EventBus, Arc<MockFirewallPlatform>) {
    let event_bus = EventBus::new(32);
    let platform = Arc::new(MockFirewallPlatform::new());
    (event_bus, platform)
}

fn sample_rule(id: &str) -> FirewallRule {
    FirewallRule {
        id: id.to_string(),
        action: FirewallAction::Allow,
        direction: FirewallDirection::Inbound,
        src_ip: Some("192.168.1.0/24".to_string()),
        dst_ip: None,
        dst_port: Some(443),
        protocol: Some("tcp".to_string()),
        description: format!("Allow HTTPS from LAN ({})", id),
    }
}

// ---------------------------------------------------------------------------
// Module identity and lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_firewall_module_id_and_metadata() {
    let (event_bus, platform) = setup();
    let module = FirewallModule::new(event_bus, platform);

    assert_eq!(module.id(), "firewall");
    assert_eq!(module.name(), "Firewall Module");
    assert_eq!(module.priority(), 5);
    assert!(module.dependencies().is_empty());
}

#[tokio::test]
async fn test_firewall_module_lifecycle() {
    let (event_bus, platform) = setup();
    let mut module = FirewallModule::new(event_bus, platform);

    assert_eq!(module.status(), ModuleStatus::Created);

    module.initialize(&ModuleConfig::default()).await.unwrap();
    assert_eq!(module.status(), ModuleStatus::Initialized);

    module.start().await.unwrap();
    assert_eq!(module.status(), ModuleStatus::Running);

    module.stop().await.unwrap();
    assert_eq!(module.status(), ModuleStatus::Stopped);
}

#[tokio::test]
async fn test_firewall_module_start_stop_idempotent() {
    let (event_bus, platform) = setup();
    let mut module = FirewallModule::new(event_bus, platform);

    module.initialize(&ModuleConfig::default()).await.unwrap();
    module.start().await.unwrap();
    module.start().await.unwrap(); // idempotent
    assert_eq!(module.status(), ModuleStatus::Running);

    module.stop().await.unwrap();
    module.stop().await.unwrap(); // idempotent
    assert_eq!(module.status(), ModuleStatus::Stopped);
}

// ---------------------------------------------------------------------------
// Rule management
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_add_rule() {
    let (event_bus, platform) = setup();
    let module = FirewallModule::new(event_bus, platform);

    module.add_rule(sample_rule("https-in")).await.unwrap();
    assert_eq!(module.rule_count().await, 1);

    let rules = module.list_rules().await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, "https-in");
}

#[tokio::test]
async fn test_add_multiple_rules() {
    let (event_bus, platform) = setup();
    let module = FirewallModule::new(event_bus, platform);

    module.add_rule(sample_rule("rule-1")).await.unwrap();
    module.add_rule(sample_rule("rule-2")).await.unwrap();
    module.add_rule(sample_rule("rule-3")).await.unwrap();

    assert_eq!(module.rule_count().await, 3);
}

#[tokio::test]
async fn test_add_duplicate_rule_fails() {
    let (event_bus, platform) = setup();
    let module = FirewallModule::new(event_bus, platform);

    module.add_rule(sample_rule("dup")).await.unwrap();
    let err = module.add_rule(sample_rule("dup")).await.unwrap_err();

    assert!(matches!(err, FirewallError::RuleAlreadyExists(_)));
    assert_eq!(module.rule_count().await, 1);
}

#[tokio::test]
async fn test_remove_rule() {
    let (event_bus, platform) = setup();
    let module = FirewallModule::new(event_bus, platform);

    module.add_rule(sample_rule("to-remove")).await.unwrap();
    assert_eq!(module.rule_count().await, 1);

    module.remove_rule("to-remove").await.unwrap();
    assert_eq!(module.rule_count().await, 0);
}

#[tokio::test]
async fn test_remove_nonexistent_rule_fails() {
    let (event_bus, platform) = setup();
    let module = FirewallModule::new(event_bus, platform);

    let err = module.remove_rule("ghost").await.unwrap_err();
    assert!(matches!(err, FirewallError::RuleNotFound(_)));
}

#[tokio::test]
async fn test_remove_only_affects_target() {
    let (event_bus, platform) = setup();
    let module = FirewallModule::new(event_bus, platform);

    module.add_rule(sample_rule("keep")).await.unwrap();
    module.add_rule(sample_rule("remove")).await.unwrap();
    assert_eq!(module.rule_count().await, 2);

    module.remove_rule("remove").await.unwrap();
    assert_eq!(module.rule_count().await, 1);

    let rules = module.list_rules().await.unwrap();
    assert_eq!(rules[0].id, "keep");
}

#[tokio::test]
async fn test_flush_rules() {
    let (event_bus, platform) = setup();
    let module = FirewallModule::new(event_bus, platform);

    for i in 0..5 {
        module.add_rule(sample_rule(&format!("rule-{}", i))).await.unwrap();
    }
    assert_eq!(module.rule_count().await, 5);

    module.flush_rules().await.unwrap();
    assert_eq!(module.rule_count().await, 0);
}

#[tokio::test]
async fn test_list_rules_returns_all() {
    let (event_bus, platform) = setup();
    let module = FirewallModule::new(event_bus, platform);

    module.add_rule(sample_rule("a")).await.unwrap();
    module.add_rule(sample_rule("b")).await.unwrap();

    let rules = module.list_rules().await.unwrap();
    assert_eq!(rules.len(), 2);
    let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"a"));
    assert!(ids.contains(&"b"));
}

// ---------------------------------------------------------------------------
// Rule types and serialization
// ---------------------------------------------------------------------------

#[test]
fn test_firewall_rule_variants() {
    let rule = FirewallRule {
        id: "test".to_string(),
        action: FirewallAction::Reject,
        direction: FirewallDirection::Both,
        src_ip: Some("10.0.0.0/8".to_string()),
        dst_ip: Some("172.16.0.0/12".to_string()),
        dst_port: Some(8080),
        protocol: Some("udp".to_string()),
        description: "Block internal UDP".to_string(),
    };

    assert_eq!(rule.action, FirewallAction::Reject);
    assert_eq!(rule.direction, FirewallDirection::Both);
}

#[test]
fn test_firewall_action_equality() {
    assert_eq!(FirewallAction::Allow, FirewallAction::Allow);
    assert_ne!(FirewallAction::Allow, FirewallAction::Block);
    assert_ne!(FirewallAction::Block, FirewallAction::Reject);
}

#[test]
fn test_firewall_direction_equality() {
    assert_eq!(FirewallDirection::Inbound, FirewallDirection::Inbound);
    assert_ne!(FirewallDirection::Inbound, FirewallDirection::Outbound);
    assert_ne!(FirewallDirection::Outbound, FirewallDirection::Both);
}

#[test]
fn test_firewall_error_display() {
    let err = FirewallError::RuleNotFound("r1".to_string());
    assert_eq!(format!("{}", err), "Rule not found: r1");

    let err = FirewallError::RuleAlreadyExists("r2".to_string());
    assert!(format!("{}", err).contains("r2"));

    let err = FirewallError::PlatformError("pfctl failed".to_string());
    assert!(format!("{}", err).contains("pfctl failed"));

    let err = FirewallError::InvalidRule("bad port".to_string());
    assert!(format!("{}", err).contains("bad port"));

    let err = FirewallError::ServiceUnavailable("not running".to_string());
    assert!(format!("{}", err).contains("not running"));
}

#[test]
fn test_firewall_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(FirewallError::PlatformError("test".to_string()));
    assert!(format!("{}", err).contains("test"));
}

#[test]
fn test_firewall_rule_serialization_roundtrip() {
    let rule = FirewallRule {
        id: "ser-test".to_string(),
        action: FirewallAction::Block,
        direction: FirewallDirection::Outbound,
        src_ip: None,
        dst_ip: Some("10.0.0.0/8".to_string()),
        dst_port: Some(53),
        protocol: Some("udp".to_string()),
        description: "Block DNS to internal".to_string(),
    };

    let json = serde_json::to_string(&rule).unwrap();
    let deserialized: FirewallRule = serde_json::from_str(&json).unwrap();

    assert_eq!(rule.id, deserialized.id);
    assert_eq!(rule.action, deserialized.action);
    assert_eq!(rule.direction, deserialized.direction);
    assert_eq!(rule.src_ip, deserialized.src_ip);
    assert_eq!(rule.dst_ip, deserialized.dst_ip);
    assert_eq!(rule.dst_port, deserialized.dst_port);
    assert_eq!(rule.protocol, deserialized.protocol);
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[test]
fn test_firewall_config_default() {
    let config = FirewallConfig::default();
    assert!(config.enabled);
    assert_eq!(config.default_action, ConfigAction::Block);
    assert!(config.log_blocked);
    assert!(config.rules.is_empty());
}

#[test]
fn test_firewall_config_serialization() {
    let config = FirewallConfig {
        enabled: true,
        default_action: ConfigAction::Block,
        log_blocked: false,
        rules: vec![FirewallRuleConfig {
            id: "cfg-rule".to_string(),
            action: "allow".to_string(),
            direction: "inbound".to_string(),
            src_ip: Some("192.168.1.0/24".to_string()),
            dst_ip: None,
            dst_port: Some(443),
            protocol: Some("tcp".to_string()),
            description: "Allow HTTPS".to_string(),
        }],
    };

    let json = serde_json::to_string(&config).unwrap();
    let deserialized: FirewallConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(config.enabled, deserialized.enabled);
    assert_eq!(config.default_action, deserialized.default_action);
    assert_eq!(config.rules.len(), deserialized.rules.len());
    assert_eq!(config.rules[0].id, deserialized.rules[0].id);
}

#[test]
fn test_firewall_config_toml_roundtrip() {
    let config = FirewallConfig {
        enabled: true,
        default_action: ConfigAction::Block,
        log_blocked: true,
        rules: vec![FirewallRuleConfig {
            id: "toml-rule".to_string(),
            action: "block".to_string(),
            direction: "outbound".to_string(),
            src_ip: None,
            dst_ip: Some("10.0.0.0/8".to_string()),
            dst_port: Some(53),
            protocol: Some("udp".to_string()),
            description: "Block DNS leaks".to_string(),
        }],
    };

    let toml_str = toml::to_string_pretty(&config).unwrap();
    let deserialized: FirewallConfig = toml::from_str(&toml_str).unwrap();

    assert_eq!(config.enabled, deserialized.enabled);
    assert_eq!(config.rules.len(), deserialized.rules.len());
    assert_eq!(config.rules[0].id, deserialized.rules[0].id);
}

// ---------------------------------------------------------------------------
// Mock platform behavior
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mock_platform_add_and_list() {
    let platform = MockFirewallPlatform::new();
    let rule = sample_rule("mock-1");

    platform.add_rule(&rule).await.unwrap();
    let rules = platform.list_rules().await.unwrap();

    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, "mock-1");
}

#[tokio::test]
async fn test_mock_platform_duplicate_rejected() {
    let platform = MockFirewallPlatform::new();
    let rule = sample_rule("dup");

    platform.add_rule(&rule).await.unwrap();
    let err = platform.add_rule(&rule).await.unwrap_err();
    assert!(matches!(err, FirewallError::RuleAlreadyExists(_)));
}

#[tokio::test]
async fn test_mock_platform_remove() {
    let platform = MockFirewallPlatform::new();
    platform.add_rule(&sample_rule("rm")).await.unwrap();

    platform.remove_rule("rm").await.unwrap();
    assert_eq!(platform.list_rules().await.unwrap().len(), 0);
}

#[tokio::test]
async fn test_mock_platform_remove_nonexistent() {
    let platform = MockFirewallPlatform::new();
    let err = platform.remove_rule("ghost").await.unwrap_err();
    assert!(matches!(err, FirewallError::RuleNotFound(_)));
}

#[tokio::test]
async fn test_mock_platform_flush() {
    let platform = MockFirewallPlatform::new();
    for i in 0..10 {
        platform.add_rule(&sample_rule(&format!("f-{}", i))).await.unwrap();
    }
    assert_eq!(platform.list_rules().await.unwrap().len(), 10);

    platform.flush_rules().await.unwrap();
    assert_eq!(platform.list_rules().await.unwrap().len(), 0);
}

#[tokio::test]
async fn test_mock_platform_check_exists() {
    let platform = MockFirewallPlatform::new();
    assert!(!platform.check_rule_exists("nope").await.unwrap());

    platform.add_rule(&sample_rule("exists")).await.unwrap();
    assert!(platform.check_rule_exists("exists").await.unwrap());
}

// ---------------------------------------------------------------------------
// Event emission
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_add_rule_emits_event() {
    let event_bus = EventBus::new(32);
    let mut receiver = event_bus.subscribe();
    let platform = Arc::new(MockFirewallPlatform::new());
    let module = FirewallModule::new(event_bus, platform);

    module.add_rule(sample_rule("evt-rule")).await.unwrap();

    let event = receiver.recv().await.unwrap();
    match event {
        ModuleEvent::FirewallRuleAdded { rule_id, description } => {
            assert_eq!(rule_id, "evt-rule");
            assert!(!description.is_empty());
        }
        _ => panic!("Expected FirewallRuleAdded, got {:?}", event),
    }
}

#[tokio::test]
async fn test_remove_rule_emits_event() {
    let event_bus = EventBus::new(32);
    let mut receiver = event_bus.subscribe();
    let platform = Arc::new(MockFirewallPlatform::new());
    let module = FirewallModule::new(event_bus, platform);

    module.add_rule(sample_rule("rm-evt")).await.unwrap();
    // Drain the add event
    let _ = receiver.recv().await.unwrap();

    module.remove_rule("rm-evt").await.unwrap();

    let event = receiver.recv().await.unwrap();
    match event {
        ModuleEvent::FirewallRuleRemoved { rule_id } => {
            assert_eq!(rule_id, "rm-evt");
        }
        _ => panic!("Expected FirewallRuleRemoved, got {:?}", event),
    }
}

// ---------------------------------------------------------------------------
// Stop flushes rules
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_stop_flushes_active_rules() {
    let (event_bus, platform) = setup();
    let mut module = FirewallModule::new(event_bus, platform);

    module.add_rule(sample_rule("cleanup-1")).await.unwrap();
    module.add_rule(sample_rule("cleanup-2")).await.unwrap();
    module.start().await.unwrap();
    assert_eq!(module.rule_count().await, 2);

    module.stop().await.unwrap();
    assert_eq!(module.rule_count().await, 0);
}

// ---------------------------------------------------------------------------
// on_event is a no-op
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_on_event_is_noop() {
    let (event_bus, platform) = setup();
    let mut module = FirewallModule::new(event_bus, platform);

    let events = vec![
        ModuleEvent::VpnConnected {
            server: "test".to_string(),
            ip: "1.2.3.4".to_string(),
        },
        ModuleEvent::VpnDisconnected {
            reason: "test".to_string(),
        },
        ModuleEvent::DnsLeakDetected {
            dns_server: "8.8.8.8".to_string(),
            interface: "en0".to_string(),
        },
        ModuleEvent::ArpSpoofDetected {
            attacker_mac: "aa:bb:cc:dd:ee:ff".to_string(),
            victim_ip: "192.168.1.1".to_string(),
        },
    ];

    for event in &events {
        assert!(module.on_event(event).await.is_ok());
    }
}

// ---------------------------------------------------------------------------
// Load config applies rules
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_load_config_applies_rules() {
    let (event_bus, platform) = setup();
    let mut module = FirewallModule::new(event_bus, platform);

    let config = FirewallConfig {
        enabled: true,
        default_action: ConfigAction::Block,
        log_blocked: true,
        rules: vec![
            FirewallRuleConfig {
                id: "cfg-https".to_string(),
                action: "allow".to_string(),
                direction: "inbound".to_string(),
                src_ip: Some("192.168.1.0/24".to_string()),
                dst_ip: None,
                dst_port: Some(443),
                protocol: Some("tcp".to_string()),
                description: "Allow HTTPS".to_string(),
            },
            FirewallRuleConfig {
                id: "cfg-dns".to_string(),
                action: "block".to_string(),
                direction: "outbound".to_string(),
                src_ip: None,
                dst_ip: None,
                dst_port: Some(53),
                protocol: Some("udp".to_string()),
                description: "Block DNS".to_string(),
            },
        ],
    };

    module.load_config(config).await.unwrap();
    assert_eq!(module.rule_count().await, 2);
}

#[tokio::test]
async fn test_load_config_skips_invalid_action() {
    let (event_bus, platform) = setup();
    let mut module = FirewallModule::new(event_bus, platform);

    let config = FirewallConfig {
        enabled: true,
        default_action: ConfigAction::Block,
        log_blocked: true,
        rules: vec![
            FirewallRuleConfig {
                id: "valid".to_string(),
                action: "allow".to_string(),
                direction: "inbound".to_string(),
                src_ip: None,
                dst_ip: None,
                dst_port: Some(443),
                protocol: None,
                description: "Valid".to_string(),
            },
            FirewallRuleConfig {
                id: "invalid-action".to_string(),
                action: "invalid_action".to_string(),
                direction: "inbound".to_string(),
                src_ip: None,
                dst_ip: None,
                dst_port: None,
                protocol: None,
                description: "Invalid".to_string(),
            },
            FirewallRuleConfig {
                id: "invalid-dir".to_string(),
                action: "allow".to_string(),
                direction: "bad_direction".to_string(),
                src_ip: None,
                dst_ip: None,
                dst_port: None,
                protocol: None,
                description: "Invalid dir".to_string(),
            },
        ],
    };

    module.load_config(config).await.unwrap();
    // Only the valid rule should have been added
    assert_eq!(module.rule_count().await, 1);
}

// ---------------------------------------------------------------------------
// Rule action variants through config
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_load_config_reject_action() {
    let (event_bus, platform) = setup();
    let mut module = FirewallModule::new(event_bus, platform);

    let config = FirewallConfig {
        enabled: true,
        default_action: ConfigAction::Block,
        log_blocked: true,
        rules: vec![FirewallRuleConfig {
            id: "reject-rule".to_string(),
            action: "reject".to_string(),
            direction: "inbound".to_string(),
            src_ip: None,
            dst_ip: None,
            dst_port: Some(22),
            protocol: Some("tcp".to_string()),
            description: "Reject SSH".to_string(),
        }],
    };

    module.load_config(config).await.unwrap();
    assert_eq!(module.rule_count().await, 1);

    let rules = module.list_rules().await.unwrap();
    assert_eq!(rules[0].action, FirewallAction::Reject);
}

#[tokio::test]
async fn test_load_config_direction_variants() {
    let (event_bus, platform) = setup();
    let mut module = FirewallModule::new(event_bus, platform);

    let config = FirewallConfig {
        enabled: true,
        default_action: ConfigAction::Block,
        log_blocked: true,
        rules: vec![
            FirewallRuleConfig {
                id: "inbound".to_string(),
                action: "allow".to_string(),
                direction: "inbound".to_string(),
                src_ip: None,
                dst_ip: None,
                dst_port: None,
                protocol: None,
                description: "Inbound".to_string(),
            },
            FirewallRuleConfig {
                id: "outbound".to_string(),
                action: "allow".to_string(),
                direction: "outbound".to_string(),
                src_ip: None,
                dst_ip: None,
                dst_port: None,
                protocol: None,
                description: "Outbound".to_string(),
            },
            FirewallRuleConfig {
                id: "both".to_string(),
                action: "block".to_string(),
                direction: "both".to_string(),
                src_ip: None,
                dst_ip: None,
                dst_port: None,
                protocol: None,
                description: "Both".to_string(),
            },
        ],
    };

    module.load_config(config).await.unwrap();
    assert_eq!(module.rule_count().await, 3);

    let rules = module.list_rules().await.unwrap();
    let inbound = rules.iter().find(|r| r.id == "inbound").unwrap();
    let outbound = rules.iter().find(|r| r.id == "outbound").unwrap();
    let both = rules.iter().find(|r| r.id == "both").unwrap();

    assert_eq!(inbound.direction, FirewallDirection::Inbound);
    assert_eq!(outbound.direction, FirewallDirection::Outbound);
    assert_eq!(both.direction, FirewallDirection::Both);
}
