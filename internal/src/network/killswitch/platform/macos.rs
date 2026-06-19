// macOS-specific kill switch implementation.
// Uses pf (Packet Filter) firewall on macOS.

use crate::platform::FirewallRule;

pub struct MacOSKillSwitch;

impl MacOSKillSwitch {
    pub fn new() -> Self {
        Self
    }

    /// Add a block-all rule using macOS pf firewall.
    pub async fn apply_rule(&self, _rule: &FirewallRule) -> Result<(), String> {
        // TODO: Implement using pfctl commands
        // e.g., pfctl -f /etc/pf.conf with kill-switch rules
        Ok(())
    }

    /// Remove the kill switch rule from pf.
    pub async fn remove_rule(&self, _rule_id: &str) -> Result<(), String> {
        // TODO: Implement rule removal via pfctl
        Ok(())
    }
}
