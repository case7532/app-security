pub mod types;
pub mod macos;
pub mod linux;
pub mod windows;

use async_trait::async_trait;
pub use types::*;

#[async_trait]
pub trait Platform: Send + Sync {
    async fn get_network_interfaces(&self) -> Result<Vec<NetworkInterface>, String>;
    async fn get_active_interface(&self) -> Result<NetworkInterface, String>;
    async fn get_mac_address(&self, iface: &str) -> Result<String, String>;
    async fn set_mac_address(&mut self, iface: &str, mac: &str) -> Result<(), String>;
    async fn restore_mac_address(&mut self, iface: &str) -> Result<(), String>;
    async fn get_hostname(&self) -> Result<String, String>;
    async fn set_hostname(&mut self, hostname: &str) -> Result<(), String>;
    async fn restore_hostname(&mut self) -> Result<(), String>;
    async fn add_firewall_rule(&mut self, rule: FirewallRule) -> Result<(), String>;
    async fn remove_firewall_rule(&mut self, rule_id: &str) -> Result<(), String>;
    async fn check_admin_privileges(&self) -> Result<bool, String>;
    async fn request_elevation(&self) -> Result<(), String>;
    async fn create_wireguard_interface(&self, config: &WireGuardConfig) -> Result<(), String>;
    async fn delete_wireguard_interface(&self, interface: &str) -> Result<(), String>;
}

pub fn create_platform() -> Box<dyn Platform> {
    match std::env::consts::OS {
        "macos" => Box::new(macos::MacOSPlatform::new()),
        "linux" => Box::new(linux::LinuxPlatform::new()),
        "windows" => Box::new(windows::WindowsPlatform::new()),
        os => panic!("Unsupported OS: {}", os),
    }
}
