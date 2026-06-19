pub mod config;
pub mod wireguard;

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::event_bus::EventBus;
use crate::core::mod_trait::{ModuleConfig, ModuleEvent, ModuleStatus, SecurityModule};
use crate::platform::{Platform, WireGuardConfig};

use self::config::VpnConfig;
use self::wireguard::WireGuardManager;

pub struct VpnModule {
    event_bus: EventBus,
    platform: Arc<RwLock<Box<dyn Platform>>>,
    status: ModuleStatus,
    connected: bool,
    current_server: Option<String>,
    wg_manager: WireGuardManager,
    vpn_config: VpnConfig,
}

impl VpnModule {
    pub fn new(event_bus: EventBus, platform: Box<dyn Platform>) -> Self {
        Self {
            event_bus,
            platform: Arc::new(RwLock::new(platform)),
            status: ModuleStatus::Created,
            connected: false,
            current_server: None,
            wg_manager: WireGuardManager::new("wg0"),
            vpn_config: VpnConfig::default(),
        }
    }

    /// Connect to a VPN server using the given private key.
    pub async fn connect(
        &mut self,
        server: &str,
        private_key: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.status != ModuleStatus::Running {
            return Err("Module not running".into());
        }

        let wg_config = WireGuardConfig {
            interface: self.wg_manager.interface_name().to_string(),
            private_key: private_key.to_string(),
            listen_port: self.vpn_config.listen_port,
            peers: vec![],
        };

        {
            let platform = self.platform.read().await;
            self.wg_manager.bring_up(platform.as_ref(), &wg_config).await?;
        }

        self.connected = true;
        self.current_server = Some(server.to_string());

        let _ = self.event_bus.publish(ModuleEvent::VpnConnected {
            server: server.to_string(),
            ip: "10.0.0.1".to_string(),
        });

        Ok(())
    }

    /// Disconnect from the current VPN server.
    pub async fn disconnect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.connected {
            return Ok(());
        }

        {
            let platform = self.platform.read().await;
            self.wg_manager.tear_down(platform.as_ref()).await?;
        }

        self.connected = false;
        self.current_server = None;

        let _ = self.event_bus.publish(ModuleEvent::VpnDisconnected {
            reason: "User disconnect".to_string(),
        });

        Ok(())
    }

    /// Returns true if currently connected to a VPN.
    pub async fn is_connected(&self) -> bool {
        self.connected
    }

    /// Returns the current server address, if connected.
    pub fn current_server(&self) -> Option<&str> {
        self.current_server.as_deref()
    }
}

#[async_trait]
impl SecurityModule for VpnModule {
    fn id(&self) -> &str {
        "vpn"
    }

    fn name(&self) -> &str {
        "VPN Module"
    }

    fn priority(&self) -> u32 {
        1
    }

    fn dependencies(&self) -> Vec<&str> {
        vec![]
    }

    async fn initialize(
        &mut self,
        _config: &ModuleConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Initialized;
        Ok(())
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Running;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.connected {
            self.disconnect().await?;
        }
        self.status = ModuleStatus::Stopped;
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    async fn on_event(&mut self, _event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}
