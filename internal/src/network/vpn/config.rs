use serde::{Deserialize, Serialize};

/// Configuration for a VPN connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    /// The server address (IP or hostname) to connect to.
    pub server: String,
    /// Private key for WireGuard authentication.
    pub private_key: String,
    /// Port to listen on for WireGuard traffic.
    pub listen_port: u16,
    /// DNS servers to use while connected.
    pub dns_servers: Vec<String>,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            private_key: String::new(),
            listen_port: 51820,
            dns_servers: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
        }
    }
}
