use app_security::core::config::AppConfig;
use app_security::core::manager::ModuleManager;
use app_security::core::event_bus::EventBus;

#[tokio::main]
async fn main() {
    env_logger::init();
    log::info!("app-security starting...");

    let _config = AppConfig::default();
    let event_bus = EventBus::new(1000);
    let manager = ModuleManager::new(event_bus);

    // Register modules
    // In a full implementation, VPN, KillSwitch, and ArpDetector modules
    // would be instantiated from config and registered here:
    //
    //   let vpn_module = VpnModule::new(&config.modules["vpn"]);
    //   manager.register_module(Box::new(vpn_module)).await.unwrap();
    //
    //   let ks_module = KillSwitchModule::new(&config.modules["killswitch"]);
    //   manager.register_module(Box::new(ks_module)).await.unwrap();
    //
    //   let arp_module = ArpDetectorModule::new(&config.modules["arp_detector"]);
    //   manager.register_module(Box::new(arp_module)).await.unwrap();

    // Start modules
    if let Err(e) = manager.start_all().await {
        log::error!("Failed to start modules: {}", e);
    }

    // Wait for shutdown signal
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl+c");
    log::info!("Shutting down...");

    if let Err(e) = manager.stop_all().await {
        log::error!("Failed to stop modules: {}", e);
    }
}
