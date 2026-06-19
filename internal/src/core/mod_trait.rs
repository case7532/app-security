use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ModuleStatus {
    Created,
    Initialized,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub enabled: bool,
    pub auto_start: bool,
    pub settings: serde_json::Value,
}

impl Default for ModuleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_start: true,
            settings: serde_json::Value::Object(serde_json::Map::new()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModuleEvent {
    VpnConnected { server: String, ip: String },
    VpnDisconnected { reason: String },
    VpnConnectionFailed { error: String },
    ArpSpoofDetected { attacker_mac: String, victim_ip: String },
    MacChanged { interface: String, old_mac: String, new_mac: String },
    HostnameChanged { old_hostname: String, new_hostname: String },
    ModuleStarted { module_id: String },
    ModuleStopped { module_id: String },
    ModuleFailed { module_id: String, error: String },
    DohConnected { server: String },
    DnsLeakDetected { dns_server: String, interface: String },
}

#[async_trait]
pub trait SecurityModule: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn priority(&self) -> u32;
    fn dependencies(&self) -> Vec<&str>;
    async fn initialize(&mut self, config: &ModuleConfig) -> Result<(), Box<dyn std::error::Error>>;
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    fn status(&self) -> ModuleStatus;
    async fn on_event(&mut self, event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>>;
}
