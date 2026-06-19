use app_security::core::config::AppConfig;
use app_security::core::manager::ModuleManager;
use app_security::core::event_bus::EventBus;
use app_security::network::vpn::VpnModule;
use app_security::network::killswitch::KillSwitchModule;
use app_security::network::dns::DnsModule;
use app_security::platform;

#[tokio::main]
async fn main() {
    env_logger::init();
    log::info!("app-security starting...");

    let _config = AppConfig::default();
    let event_bus = EventBus::new(1000);
    let mut manager = ModuleManager::new(event_bus.clone());

    manager
        .register_module(Box::new(VpnModule::new(
            event_bus.clone(),
            platform::create_platform(),
        )))
        .await
        .unwrap();
    manager
        .register_module(Box::new(KillSwitchModule::new(
            event_bus.clone(),
            platform::create_platform(),
        )))
        .await
        .unwrap();
    manager
        .register_module(Box::new(DnsModule::new(event_bus.clone())))
        .await
        .unwrap();

    if let Err(e) = manager.start_all().await {
        log::error!("Failed to start modules: {}", e);
    }

    manager.start_event_dispatch().await;

    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl+c");
    log::info!("Shutting down...");

    if let Err(e) = manager.stop_all().await {
        log::error!("Failed to stop modules: {}", e);
    }
}
