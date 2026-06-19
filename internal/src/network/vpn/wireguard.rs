use crate::platform::{Platform, WireGuardConfig};

/// Manages a WireGuard VPN connection through the Platform trait.
pub struct WireGuardManager {
    interface: String,
}

impl WireGuardManager {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
        }
    }

    /// Returns the name of the WireGuard interface.
    pub fn interface_name(&self) -> &str {
        &self.interface
    }

    /// Creates a WireGuard interface via the platform.
    pub async fn bring_up(
        &self,
        platform: &dyn Platform,
        config: &WireGuardConfig,
    ) -> Result<(), String> {
        platform.create_wireguard_interface(config).await
    }

    /// Tears down the WireGuard interface via the platform.
    pub async fn tear_down(&self, platform: &dyn Platform) -> Result<(), String> {
        platform.delete_wireguard_interface(&self.interface).await
    }
}
