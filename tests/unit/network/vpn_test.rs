use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::{ModuleConfig, ModuleEvent, ModuleStatus, SecurityModule};
use app_security::network::vpn::VpnModule;
use app_security::platform::{
    FirewallRule, NetworkInterface, Platform, WireGuardConfig,
};
use async_trait::async_trait;

// ---------------------------------------------------------------------------
// MockPlatform – lightweight mock satisfying the Platform trait for VPN tests.
// ---------------------------------------------------------------------------
struct MockPlatform;

impl MockPlatform {
    fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Platform for MockPlatform {
    async fn get_network_interfaces(&self) -> Result<Vec<NetworkInterface>, String> {
        Ok(vec![])
    }
    async fn get_active_interface(&self) -> Result<NetworkInterface, String> {
        Err("Not implemented".to_string())
    }
    async fn get_mac_address(&self, _iface: &str) -> Result<String, String> {
        Err("Not implemented".to_string())
    }
    async fn set_mac_address(&mut self, _iface: &str, _mac: &str) -> Result<(), String> {
        Err("Not implemented".to_string())
    }
    async fn restore_mac_address(&mut self, _iface: &str) -> Result<(), String> {
        Err("Not implemented".to_string())
    }
    async fn get_hostname(&self) -> Result<String, String> {
        Err("Not implemented".to_string())
    }
    async fn set_hostname(&mut self, _hostname: &str) -> Result<(), String> {
        Err("Not implemented".to_string())
    }
    async fn restore_hostname(&mut self) -> Result<(), String> {
        Err("Not implemented".to_string())
    }
    async fn add_firewall_rule(&mut self, _rule: FirewallRule) -> Result<(), String> {
        Err("Not implemented".to_string())
    }
    async fn remove_firewall_rule(&mut self, _rule_id: &str) -> Result<(), String> {
        Err("Not implemented".to_string())
    }
    async fn check_admin_privileges(&self) -> Result<bool, String> {
        Ok(true)
    }
    async fn request_elevation(&self) -> Result<(), String> {
        Ok(())
    }
    async fn create_wireguard_interface(&self, _config: &WireGuardConfig) -> Result<(), String> {
        Ok(())
    }
    async fn delete_wireguard_interface(&self, _interface: &str) -> Result<(), String> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_vpn_initialization() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus, platform);

    assert_eq!(vpn.status(), ModuleStatus::Created);

    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    assert_eq!(vpn.status(), ModuleStatus::Initialized);
}

#[tokio::test]
async fn test_vpn_start_stop() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus, platform);

    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    vpn.start().await.unwrap();
    assert_eq!(vpn.status(), ModuleStatus::Running);

    vpn.stop().await.unwrap();
    assert_eq!(vpn.status(), ModuleStatus::Stopped);
}

#[tokio::test]
async fn test_vpn_connect() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus, platform);

    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    vpn.start().await.unwrap();

    let result = vpn.connect("10.0.0.1", "test-key").await;
    assert!(result.is_ok());
    assert!(vpn.is_connected().await);
}

#[tokio::test]
async fn test_vpn_disconnect_event() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus, platform);

    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    vpn.start().await.unwrap();
    vpn.connect("10.0.0.1", "test-key").await.unwrap();

    vpn.disconnect().await.unwrap();

    // Drain the VpnConnected event that was published during connect()
    let _ = receiver.recv().await.unwrap();
    // Now check for VpnDisconnected
    let event = receiver.recv().await.unwrap();
    match event {
        ModuleEvent::VpnDisconnected { .. } => {}
        _ => panic!("Expected VpnDisconnected event"),
    }
}

#[tokio::test]
async fn test_vpn_module_id() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let vpn = VpnModule::new(event_bus, platform);

    assert_eq!(vpn.id(), "vpn");
    assert_eq!(vpn.name(), "VPN Module");
}

#[tokio::test]
async fn test_vpn_connect_when_not_running() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus, platform);

    // Don't initialize or start - connect should fail
    let result = vpn.connect("10.0.0.1", "test-key").await;
    assert!(result.is_err());
    assert!(!vpn.is_connected().await);
}

#[tokio::test]
async fn test_vpn_disconnect_when_not_connected() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus, platform);

    // Disconnecting when not connected should be a no-op (Ok)
    let result = vpn.disconnect().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_vpn_stop_disconnects() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus, platform);

    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    vpn.start().await.unwrap();
    vpn.connect("10.0.0.1", "test-key").await.unwrap();
    assert!(vpn.is_connected().await);

    // stop() should auto-disconnect
    vpn.stop().await.unwrap();
    assert!(!vpn.is_connected().await);
    assert_eq!(vpn.status(), ModuleStatus::Stopped);

    // Drain the VpnConnected event that was published during connect()
    let _ = receiver.recv().await.unwrap();
    // Now check for VpnDisconnected
    let event = receiver.recv().await.unwrap();
    match event {
        ModuleEvent::VpnDisconnected { .. } => {}
        _ => panic!("Expected VpnDisconnected event from stop()"),
    }
}

#[tokio::test]
async fn test_vpn_connect_event_published() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus, platform);

    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    vpn.start().await.unwrap();
    vpn.connect("10.0.0.1", "test-key").await.unwrap();

    let event = receiver.recv().await.unwrap();
    match event {
        ModuleEvent::VpnConnected { server, .. } => {
            assert_eq!(server, "10.0.0.1");
        }
        _ => panic!("Expected VpnConnected event"),
    }
}

#[tokio::test]
async fn test_vpn_current_server() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus, platform);

    assert!(vpn.current_server().is_none());

    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    vpn.start().await.unwrap();
    vpn.connect("10.0.0.1", "test-key").await.unwrap();

    assert_eq!(vpn.current_server(), Some("10.0.0.1"));

    vpn.disconnect().await.unwrap();
    assert!(vpn.current_server().is_none());
}
