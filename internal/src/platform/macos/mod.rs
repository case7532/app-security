use async_trait::async_trait;
use crate::platform::{Platform, NetworkInterface, FirewallRule};

pub struct MacOSPlatform;

impl MacOSPlatform {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Platform for MacOSPlatform {
    async fn get_network_interfaces(&self) -> Result<Vec<NetworkInterface>, String> {
        // TODO: Implement using networksetup
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
        Ok(false)
    }

    async fn request_elevation(&self) -> Result<(), String> {
        Err("Not implemented".to_string())
    }
}
