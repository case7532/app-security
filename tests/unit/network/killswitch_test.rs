use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::{ModuleConfig, ModuleEvent, ModuleStatus, SecurityModule};
use app_security::network::killswitch::KillSwitchModule;
use app_security::platform::{
    FirewallAction, FirewallRule, NetworkInterface, Platform, WireGuardConfig,
};
use async_trait::async_trait;

// ---------------------------------------------------------------------------
// MockPlatform for kill-switch tests (tracks firewall rules)
// ---------------------------------------------------------------------------

struct MockPlatform {
    firewall_rules: Vec<FirewallRule>,
}

impl MockPlatform {
    fn new() -> Self {
        Self {
            firewall_rules: Vec::new(),
        }
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
    async fn add_firewall_rule(&mut self, rule: FirewallRule) -> Result<(), String> {
        self.firewall_rules.push(rule);
        Ok(())
    }
    async fn remove_firewall_rule(&mut self, rule_id: &str) -> Result<(), String> {
        self.firewall_rules.retain(|r| r.id != rule_id);
        Ok(())
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
async fn test_killswitch_initialization() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut killswitch = KillSwitchModule::new(event_bus, platform);

    assert_eq!(killswitch.status(), ModuleStatus::Created);

    killswitch
        .initialize(&ModuleConfig::default())
        .await
        .unwrap();
    assert_eq!(killswitch.status(), ModuleStatus::Initialized);
}

#[tokio::test]
async fn test_killswitch_start_stop() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut killswitch = KillSwitchModule::new(event_bus, platform);

    killswitch
        .initialize(&ModuleConfig::default())
        .await
        .unwrap();
    killswitch.start().await.unwrap();
    assert_eq!(killswitch.status(), ModuleStatus::Running);

    killswitch.stop().await.unwrap();
    assert_eq!(killswitch.status(), ModuleStatus::Stopped);
}

#[tokio::test]
async fn test_killswitch_activates_on_vpn_disconnect() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut killswitch = KillSwitchModule::new(event_bus, platform);

    killswitch
        .initialize(&ModuleConfig::default())
        .await
        .unwrap();
    killswitch.start().await.unwrap();

    assert!(!killswitch.is_active().await);

    let event = ModuleEvent::VpnDisconnected {
        reason: "Connection lost".to_string(),
    };
    killswitch.on_event(&event).await.unwrap();

    assert!(killswitch.is_active().await);
}

#[tokio::test]
async fn test_killswitch_deactivates_on_vpn_reconnect() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut killswitch = KillSwitchModule::new(event_bus, platform);

    killswitch
        .initialize(&ModuleConfig::default())
        .await
        .unwrap();
    killswitch.start().await.unwrap();

    // Activate
    let event = ModuleEvent::VpnDisconnected {
        reason: "test".to_string(),
    };
    killswitch.on_event(&event).await.unwrap();
    assert!(killswitch.is_active().await);

    // Deactivate on reconnect
    let event = ModuleEvent::VpnConnected {
        server: "test".to_string(),
        ip: "10.0.0.1".to_string(),
    };
    killswitch.on_event(&event).await.unwrap();

    assert!(!killswitch.is_active().await);
}

#[tokio::test]
async fn test_killswitch_blocks_traffic_when_active() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut killswitch = KillSwitchModule::new(event_bus, platform);

    killswitch
        .initialize(&ModuleConfig::default())
        .await
        .unwrap();
    killswitch.start().await.unwrap();

    let event = ModuleEvent::VpnDisconnected {
        reason: "test".to_string(),
    };
    killswitch.on_event(&event).await.unwrap();

    let rules = killswitch.get_firewall_rules().await;
    assert!(!rules.is_empty());
    assert!(rules
        .iter()
        .all(|r| r.action == FirewallAction::Block));
}

#[tokio::test]
async fn test_killswitch_removes_rules_on_deactivate() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut killswitch = KillSwitchModule::new(event_bus, platform);

    killswitch
        .initialize(&ModuleConfig::default())
        .await
        .unwrap();
    killswitch.start().await.unwrap();

    // Activate
    let event = ModuleEvent::VpnDisconnected {
        reason: "test".to_string(),
    };
    killswitch.on_event(&event).await.unwrap();
    assert!(!killswitch.get_firewall_rules().await.is_empty());

    // Deactivate
    let event = ModuleEvent::VpnConnected {
        server: "test".to_string(),
        ip: "10.0.0.1".to_string(),
    };
    killswitch.on_event(&event).await.unwrap();
    assert!(killswitch.get_firewall_rules().await.is_empty());
}

#[tokio::test]
async fn test_killswitch_id_and_metadata() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let killswitch = KillSwitchModule::new(event_bus, platform);

    assert_eq!(killswitch.id(), "killswitch");
    assert_eq!(killswitch.name(), "Kill Switch");
    assert_eq!(killswitch.priority(), 2);
    assert_eq!(killswitch.dependencies(), vec!["vpn"]);
}

#[tokio::test]
async fn test_killswitch_ignores_unrelated_events() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut killswitch = KillSwitchModule::new(event_bus, platform);

    killswitch
        .initialize(&ModuleConfig::default())
        .await
        .unwrap();
    killswitch.start().await.unwrap();

    // An unrelated event should not activate the kill switch
    let event = ModuleEvent::ArpSpoofDetected {
        attacker_mac: "aa:bb:cc:dd:ee:ff".to_string(),
        victim_ip: "192.168.1.1".to_string(),
    };
    killswitch.on_event(&event).await.unwrap();

    assert!(!killswitch.is_active().await);
    assert!(killswitch.get_firewall_rules().await.is_empty());
}

#[tokio::test]
async fn test_killswitch_publishes_event_on_activation() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let platform = Box::new(MockPlatform::new());
    let mut killswitch = KillSwitchModule::new(event_bus, platform);

    killswitch
        .initialize(&ModuleConfig::default())
        .await
        .unwrap();
    killswitch.start().await.unwrap();

    let event = ModuleEvent::VpnDisconnected {
        reason: "Connection lost".to_string(),
    };
    killswitch.on_event(&event).await.unwrap();

    // Should have published a ModuleStarted event for the killswitch
    let published = receiver.recv().await.unwrap();
    match published {
        ModuleEvent::ModuleStarted { module_id } => {
            assert_eq!(module_id, "killswitch");
        }
        _ => panic!("Expected ModuleStarted event from kill switch activation"),
    }
}

#[tokio::test]
async fn test_killswitch_deactivation_removes_platform_rules() {
    let event_bus = EventBus::new(100);
    let mut platform = MockPlatform::new();
    // Pre-populate with a rule to verify removal works
    platform.firewall_rules.push(FirewallRule {
        id: "killswitch-block".to_string(),
        action: FirewallAction::Block,
        src_ip: None,
        dst_ip: None,
        dst_port: None,
        protocol: None,
        description: "Kill switch - block all traffic".to_string(),
    });

    let platform_box: Box<dyn Platform> = Box::new(platform);
    let mut killswitch = KillSwitchModule::new(event_bus, platform_box);

    killswitch
        .initialize(&ModuleConfig::default())
        .await
        .unwrap();
    killswitch.start().await.unwrap();

    // Set killswitch as active manually for this test scenario
    let event = ModuleEvent::VpnDisconnected {
        reason: "test".to_string(),
    };
    killswitch.on_event(&event).await.unwrap();

    let event = ModuleEvent::VpnConnected {
        server: "test".to_string(),
        ip: "10.0.0.1".to_string(),
    };
    killswitch.on_event(&event).await.unwrap();

    assert!(!killswitch.is_active().await);
    assert!(killswitch.get_firewall_rules().await.is_empty());
}
