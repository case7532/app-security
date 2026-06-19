use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::{ModuleConfig, ModuleEvent, ModuleStatus, SecurityModule};
use app_security::network::dns::DnsModule;
use app_security::network::dns::doh::DohClient;
use app_security::network::dns::config::DnsConfig;

// ---------------------------------------------------------------------------
// Basic lifecycle tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dns_module_initialization() {
    let event_bus = EventBus::new(100);
    let mut dns = DnsModule::new(event_bus);

    assert_eq!(dns.status(), ModuleStatus::Created);

    dns.initialize(&ModuleConfig::default()).await.unwrap();
    assert_eq!(dns.status(), ModuleStatus::Initialized);
}

#[tokio::test]
async fn test_dns_module_start_stop() {
    let event_bus = EventBus::new(100);
    let mut dns = DnsModule::new(event_bus);

    dns.initialize(&ModuleConfig::default()).await.unwrap();
    dns.start().await.unwrap();
    assert_eq!(dns.status(), ModuleStatus::Running);

    dns.stop().await.unwrap();
    assert_eq!(dns.status(), ModuleStatus::Stopped);
}

// ---------------------------------------------------------------------------
// Module metadata
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dns_module_metadata() {
    let event_bus = EventBus::new(100);
    let dns = DnsModule::new(event_bus);

    assert_eq!(dns.id(), "dns");
    assert_eq!(dns.name(), "DNS Module");
    assert_eq!(dns.priority(), 4);
    assert!(dns.dependencies().is_empty());
}

// ---------------------------------------------------------------------------
// Event publishing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dns_module_start_publishes_doh_connected() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let mut dns = DnsModule::new(event_bus);

    dns.initialize(&ModuleConfig::default()).await.unwrap();
    dns.start().await.unwrap();

    let event = receiver.recv().await.unwrap();
    match event {
        ModuleEvent::DohConnected { server } => {
            assert_eq!(server, "1.1.1.1");
        }
        _ => panic!("Expected DohConnected event, got {:?}", event),
    }
}

// ---------------------------------------------------------------------------
// on_event handler
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dns_module_on_event_noop() {
    let event_bus = EventBus::new(100);
    let mut dns = DnsModule::new(event_bus);

    dns.initialize(&ModuleConfig::default()).await.unwrap();
    dns.start().await.unwrap();

    // on_event should accept any event without error
    let result = dns
        .on_event(&ModuleEvent::VpnConnected {
            server: "test".to_string(),
            ip: "10.0.0.1".to_string(),
        })
        .await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// DoH Client
// ---------------------------------------------------------------------------

#[test]
fn test_doh_client_creation() {
    let client = DohClient::new("https://1.1.1.1/dns-query".to_string());
    assert_eq!(client.resolver_url(), "https://1.1.1.1/dns-query");
}

#[test]
fn test_doh_client_custom_url() {
    let client = DohClient::new("https://dns.google/dns-query".to_string());
    assert_eq!(client.resolver_url(), "https://dns.google/dns-query");
}

// ---------------------------------------------------------------------------
// DNS Config
// ---------------------------------------------------------------------------

#[test]
fn test_dns_config_default() {
    let config = DnsConfig::default();
    assert_eq!(config.resolver_url, "https://1.1.1.1/dns-query");
    assert_eq!(config.timeout_secs, 5);
}

#[test]
fn test_dns_config_custom() {
    let config = DnsConfig {
        resolver_url: "https://dns.google/dns-query".to_string(),
        timeout_secs: 10,
    };
    assert_eq!(config.resolver_url, "https://dns.google/dns-query");
    assert_eq!(config.timeout_secs, 10);
}

// ---------------------------------------------------------------------------
// DnsEvent variants in ModuleEvent
// ---------------------------------------------------------------------------

#[test]
fn test_dns_leak_detected_event_serialization() {
    let event = ModuleEvent::DnsLeakDetected {
        dns_server: "8.8.8.8".to_string(),
        interface: "en0".to_string(),
    };
    let serialized = serde_json::to_string(&event).unwrap();
    assert!(serialized.contains("DnsLeakDetected"));
    assert!(serialized.contains("8.8.8.8"));
    assert!(serialized.contains("en0"));

    let deserialized: ModuleEvent = serde_json::from_str(&serialized).unwrap();
    match deserialized {
        ModuleEvent::DnsLeakDetected { dns_server, interface } => {
            assert_eq!(dns_server, "8.8.8.8");
            assert_eq!(interface, "en0");
        }
        _ => panic!("Expected DnsLeakDetected event after deserialization"),
    }
}

#[test]
fn test_doh_connected_event_serialization() {
    let event = ModuleEvent::DohConnected {
        server: "1.1.1.1".to_string(),
    };
    let serialized = serde_json::to_string(&event).unwrap();
    assert!(serialized.contains("DohConnected"));

    let deserialized: ModuleEvent = serde_json::from_str(&serialized).unwrap();
    match deserialized {
        ModuleEvent::DohConnected { server } => {
            assert_eq!(server, "1.1.1.1");
        }
        _ => panic!("Expected DohConnected event after deserialization"),
    }
}
