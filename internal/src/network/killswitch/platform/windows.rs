// Windows-specific kill switch implementation.
// Uses Windows Filtering Platform (WFP) firewall on Windows.

use crate::platform::FirewallRule;

pub struct WindowsKillSwitch;

impl WindowsKillSwitch {
    pub fn new() -> Self {
        Self
    }

    /// Add a block-all rule using Windows netsh firewall.
    pub async fn apply_rule(&self, _rule: &FirewallRule) -> Result<(), String> {
        // TODO: Implement using netsh advfirewall commands
        // e.g., netsh advfirewall firewall add rule ...
        Ok(())
    }

    /// Remove the kill switch rule from Windows firewall.
    pub async fn remove_rule(&self, _rule_id: &str) -> Result<(), String> {
        // TODO: Implement rule removal via netsh
        Ok(())
    }
}
