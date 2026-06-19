mod mocks {
    pub mod mock_platform;
}

use mocks::mock_platform::MockPlatform;
use app_security::platform::{Platform, NetworkInterface, FirewallRule, FirewallAction};

#[tokio::test]
async fn test_mock_get_network_interfaces() {
    let platform = MockPlatform::new();
    let interfaces = platform.get_network_interfaces().await.unwrap();
    assert_eq!(interfaces.len(), 1);
    assert_eq!(interfaces[0].name, "eth0");
    assert_eq!(interfaces[0].mac, "00:11:22:33:44:55");
    assert!(interfaces[0].is_up);
}

#[tokio::test]
async fn test_mock_get_active_interface() {
    let platform = MockPlatform::new();
    let active = platform.get_active_interface().await.unwrap();
    assert_eq!(active.name, "eth0");
    assert!(active.is_up);
}

#[tokio::test]
async fn test_mock_get_active_interface_none_up() {
    let mut platform = MockPlatform::new();
    platform.interfaces[0].is_up = false;
    assert!(platform.get_active_interface().await.is_err());
}

#[tokio::test]
async fn test_mock_get_mac_address() {
    let platform = MockPlatform::new();
    let mac = platform.get_mac_address("eth0").await.unwrap();
    assert_eq!(mac, "00:11:22:33:44:55");
}

#[tokio::test]
async fn test_mock_get_mac_address_not_found() {
    let platform = MockPlatform::new();
    assert!(platform.get_mac_address("nonexistent").await.is_err());
}

#[tokio::test]
async fn test_mock_set_mac_address() {
    let mut platform = MockPlatform::new();
    platform.set_mac_address("eth0", "AA:BB:CC:DD:EE:FF").await.unwrap();
    let mac = platform.get_mac_address("eth0").await.unwrap();
    assert_eq!(mac, "AA:BB:CC:DD:EE:FF");
}

#[tokio::test]
async fn test_mock_restore_mac_address() {
    let mut platform = MockPlatform::new();
    platform.set_mac_address("eth0", "AA:BB:CC:DD:EE:FF").await.unwrap();
    platform.restore_mac_address("eth0").await.unwrap();
    let mac = platform.get_mac_address("eth0").await.unwrap();
    assert_eq!(mac, "00:11:22:33:44:55");
}

#[tokio::test]
async fn test_mock_hostname() {
    let mut platform = MockPlatform::new();
    let hostname = platform.get_hostname().await.unwrap();
    assert_eq!(hostname, "testcomputer");

    platform.set_hostname("newhost").await.unwrap();
    let hostname = platform.get_hostname().await.unwrap();
    assert_eq!(hostname, "newhost");

    platform.restore_hostname().await.unwrap();
    let hostname = platform.get_hostname().await.unwrap();
    assert_eq!(hostname, "testcomputer");
}

#[tokio::test]
async fn test_mock_firewall_rules() {
    let mut platform = MockPlatform::new();
    assert!(platform.firewall_rules.is_empty());

    let rule = FirewallRule {
        id: "rule1".to_string(),
        action: FirewallAction::Allow,
        src_ip: None,
        dst_ip: Some("192.168.1.1".to_string()),
        dst_port: Some(443),
        protocol: Some("tcp".to_string()),
        description: "Allow HTTPS".to_string(),
    };

    platform.add_firewall_rule(rule).await.unwrap();
    assert_eq!(platform.firewall_rules.len(), 1);

    platform.remove_firewall_rule("rule1").await.unwrap();
    assert!(platform.firewall_rules.is_empty());
}

#[tokio::test]
async fn test_mock_admin_privileges() {
    let platform = MockPlatform::new();
    assert!(platform.check_admin_privileges().await.unwrap());
    assert!(platform.request_elevation().await.is_ok());
}

#[tokio::test]
async fn test_network_interface_clone() {
    let iface = NetworkInterface {
        name: "wlan0".to_string(),
        mac: "AA:BB:CC:DD:EE:FF".to_string(),
        ip: Some("10.0.0.1".to_string()),
        is_up: false,
    };
    let cloned = iface.clone();
    assert_eq!(cloned.name, "wlan0");
    assert_eq!(cloned.is_up, false);
}

#[tokio::test]
async fn test_firewall_rule_serialization() {
    let rule = FirewallRule {
        id: "rule1".to_string(),
        action: FirewallAction::Block,
        src_ip: Some("10.0.0.1".to_string()),
        dst_ip: None,
        dst_port: Some(22),
        protocol: Some("tcp".to_string()),
        description: "Block SSH".to_string(),
    };

    let json = serde_json::to_string(&rule).unwrap();
    let deserialized: FirewallRule = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.id, "rule1");
    assert_eq!(deserialized.action, FirewallAction::Block);
    assert_eq!(deserialized.dst_port, Some(22));
}
