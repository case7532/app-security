mod common;

use app_security::core::manager::ModuleManager;
use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::ModuleStatus;
use app_security::network::vpn::VpnModule;
use app_security::network::killswitch::KillSwitchModule;
use app_security::detection::arp::ArpDetectorModule;
use common::mock_platform::MockPlatform;

#[tokio::test]
async fn test_full_module_lifecycle() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus.clone());

    // Register all three modules
    let platform: Box<dyn app_security::platform::Platform> = Box::new(MockPlatform::new());
    manager.register_module(Box::new(VpnModule::new(event_bus.clone(), platform))).await.unwrap();
    manager.register_module(Box::new(KillSwitchModule::new(event_bus.clone(), Box::new(MockPlatform::new())))).await.unwrap();
    manager.register_module(Box::new(ArpDetectorModule::new(event_bus.clone()))).await.unwrap();

    // Verify all modules are registered
    let ids = manager.get_module_ids().await;
    assert_eq!(ids.len(), 3);
    assert!(ids.contains(&"vpn".to_string()));
    assert!(ids.contains(&"killswitch".to_string()));
    assert!(ids.contains(&"arp_detector".to_string()));

    // Verify initial status is Created
    assert_eq!(manager.get_module_status("vpn").await.unwrap(), ModuleStatus::Created);
    assert_eq!(manager.get_module_status("killswitch").await.unwrap(), ModuleStatus::Created);
    assert_eq!(manager.get_module_status("arp_detector").await.unwrap(), ModuleStatus::Created);

    // Start all modules
    manager.start_all().await.unwrap();

    // Verify all are running
    assert_eq!(manager.get_module_status("vpn").await.unwrap(), ModuleStatus::Running);
    assert_eq!(manager.get_module_status("killswitch").await.unwrap(), ModuleStatus::Running);
    assert_eq!(manager.get_module_status("arp_detector").await.unwrap(), ModuleStatus::Running);

    // Stop all modules
    manager.stop_all().await.unwrap();

    // Verify all are stopped
    assert_eq!(manager.get_module_status("vpn").await.unwrap(), ModuleStatus::Stopped);
    assert_eq!(manager.get_module_status("killswitch").await.unwrap(), ModuleStatus::Stopped);
    assert_eq!(manager.get_module_status("arp_detector").await.unwrap(), ModuleStatus::Stopped);

    // Allow the ARP monitor's spawned task to observe the stop flag and exit
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_start_all_is_idempotent() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus.clone());

    let platform: Box<dyn app_security::platform::Platform> = Box::new(MockPlatform::new());
    manager.register_module(Box::new(VpnModule::new(event_bus.clone(), platform))).await.unwrap();
    manager.register_module(Box::new(KillSwitchModule::new(event_bus.clone(), Box::new(MockPlatform::new())))).await.unwrap();

    // Start all twice -- should not error
    manager.start_all().await.unwrap();
    manager.start_all().await.unwrap();

    assert_eq!(manager.get_module_status("vpn").await.unwrap(), ModuleStatus::Running);
    assert_eq!(manager.get_module_status("killswitch").await.unwrap(), ModuleStatus::Running);

    manager.stop_all().await.unwrap();
}

#[tokio::test]
async fn test_stop_all_is_idempotent() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus.clone());

    let platform: Box<dyn app_security::platform::Platform> = Box::new(MockPlatform::new());
    manager.register_module(Box::new(VpnModule::new(event_bus.clone(), platform))).await.unwrap();

    manager.start_all().await.unwrap();
    manager.stop_all().await.unwrap();
    // Stopping again should not error (module already stopped)
    manager.stop_all().await.unwrap();

    assert_eq!(manager.get_module_status("vpn").await.unwrap(), ModuleStatus::Stopped);
}

#[tokio::test]
async fn test_get_status_unknown_module_returns_error() {
    let event_bus = EventBus::new(100);
    let manager = ModuleManager::new(event_bus);

    let result = manager.get_module_status("nonexistent").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));
}
