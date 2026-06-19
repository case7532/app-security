use app_security::platform::{Platform, NetworkInterface, FirewallRule, WireGuardConfig};
use async_trait::async_trait;

pub struct MockPlatform {
    pub interfaces: Vec<NetworkInterface>,
    pub mac_addresses: std::collections::HashMap<String, String>,
    pub hostname: String,
    pub firewall_rules: Vec<FirewallRule>,
}

impl MockPlatform {
    pub fn new() -> Self {
        let mut mac_addresses = std::collections::HashMap::new();
        mac_addresses.insert("eth0".to_string(), "00:11:22:33:44:55".to_string());

        Self {
            interfaces: vec![
                NetworkInterface {
                    name: "eth0".to_string(),
                    mac: "00:11:22:33:44:55".to_string(),
                    ip: Some("192.168.1.100".to_string()),
                    is_up: true,
                },
            ],
            mac_addresses,
            hostname: "testcomputer".to_string(),
            firewall_rules: Vec::new(),
        }
    }
}

#[async_trait]
impl Platform for MockPlatform {
    async fn get_network_interfaces(&self) -> Result<Vec<NetworkInterface>, String> {
        Ok(self.interfaces.clone())
    }

    async fn get_active_interface(&self) -> Result<NetworkInterface, String> {
        self.interfaces.iter()
            .find(|i| i.is_up)
            .cloned()
            .ok_or_else(|| "No active interface".to_string())
    }

    async fn get_mac_address(&self, iface: &str) -> Result<String, String> {
        self.mac_addresses.get(iface)
            .cloned()
            .ok_or_else(|| format!("Interface not found: {}", iface))
    }

    async fn set_mac_address(&mut self, iface: &str, mac: &str) -> Result<(), String> {
        self.mac_addresses.insert(iface.to_string(), mac.to_string());
        Ok(())
    }

    async fn restore_mac_address(&mut self, iface: &str) -> Result<(), String> {
        self.mac_addresses.insert(iface.to_string(), "00:11:22:33:44:55".to_string());
        Ok(())
    }

    async fn get_hostname(&self) -> Result<String, String> {
        Ok(self.hostname.clone())
    }

    async fn set_hostname(&mut self, hostname: &str) -> Result<(), String> {
        self.hostname = hostname.to_string();
        Ok(())
    }

    async fn restore_hostname(&mut self) -> Result<(), String> {
        self.hostname = "testcomputer".to_string();
        Ok(())
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
