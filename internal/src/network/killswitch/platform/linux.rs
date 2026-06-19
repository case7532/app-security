// Linux-specific kill switch implementation.
// Uses iptables/nftables firewall on Linux.

use crate::platform::FirewallRule;

pub struct LinuxKillSwitch;

impl LinuxKillSwitch {
    pub fn new() -> Self {
        Self
    }

    /// Add a block-all rule using iptables.
    pub async fn apply_rule(&self, _rule: &FirewallRule) -> Result<(), String> {
        // TODO: Implement using iptables commands
        // e.g., iptables -A OUTPUT -j DROP
        Ok(())
    }

    /// Remove the kill switch rule from iptables.
    pub async fn remove_rule(&self, _rule_id: &str) -> Result<(), String> {
        // TODO: Implement rule removal via iptables
        Ok(())
    }
}
