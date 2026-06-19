# Phase 2B: Firewall Module Design

> **Date:** 2026-06-19
> **Status:** Approved
> **Scope:** Full firewall with macOS/Linux/Windows implementations

---

## 1. Overview

Firewall module for managing system firewall rules across platforms.

### Scope

| # | Feature | Priority |
|---|---------|----------|
| 1 | FirewallPlatform trait | Critical |
| 2 | FirewallModule (SecurityModule) | Critical |
| 3 | macOS pf implementation | High |
| 4 | Linux iptables implementation | High |
| 5 | Windows netsh implementation | High |
| 6 | Rule management (add/remove/list) | Critical |

---

## 2. Architecture

```
internal/src/network/firewall/
├── mod.rs              # FirewallModule implementing SecurityModule
├── rules.rs            # FirewallRule, FirewallAction types
├── platform/
│   ├── mod.rs          # FirewallPlatform trait
│   ├── macos.rs        # macOS pf implementation
│   ├── linux.rs        # Linux iptables implementation
│   └── windows.rs      # Windows netsh implementation
└── config.rs           # Firewall configuration
```

---

## 3. FirewallPlatform Trait

```rust
#[async_trait]
pub trait FirewallPlatform: Send + Sync {
    async fn add_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError>;
    async fn remove_rule(&self, rule_id: &str) -> Result<(), FirewallError>;
    async fn list_rules(&self) -> Result<Vec<FirewallRule>, FirewallError>;
    async fn flush_rules(&self) -> Result<(), FirewallError>;
    async fn check_rule_exists(&self, rule_id: &str) -> Result<bool, FirewallError>;
}
```

---

## 4. FirewallModule

```rust
pub struct FirewallModule {
    event_bus: EventBus,
    status: ModuleStatus,
    platform: Arc<dyn FirewallPlatform>,
    active_rules: Arc<RwLock<Vec<FirewallRule>>>,
}

impl SecurityModule for FirewallModule {
    fn id(&self) -> &str { "firewall" }
    fn name(&self) -> &str { "Firewall Module" }
    fn priority(&self) -> u32 { 5 }
    fn dependencies(&self) -> Vec<&str> { vec![] }
}
```

---

## 5. Events

| Event | Description |
|-------|-------------|
| `FirewallRuleAdded { rule_id, description }` | Rule added |
| `FirewallRuleRemoved { rule_id }` | Rule removed |
| `FirewallRuleBlocked { src_ip, dst_port }` | Traffic blocked |

---

## 6. Platform Implementations

### macOS (pf)

- Uses `pfctl` command
- Rules in `/etc/pf.conf` or via stdin
- Example: `echo "pass in proto tcp from 192.168.1.0/24 to any port 443" | pfctl -ef -`

### Linux (iptables)

- Uses `iptables` command
- Chain: INPUT, OUTPUT, FORWARD
- Example: `iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 443 -j ACCEPT`

### Windows (netsh)

- Uses `netsh advfirewall firewall` commands
- Example: `netsh advfirewall firewall add rule name="allow-443" dir=in action=allow protocol=TCP localport=443`

---

## 7. Configuration

```toml
[firewall]
enabled = true
default_action = "block"
log_blocked = true
rules = []
```

---

## 8. Implementation Order

| Task | Description | Dependencies |
|------|-------------|--------------|
| 1 | FirewallPlatform trait + types | None |
| 2 | FirewallModule | Task 1 |
| 3 | macOS pf implementation | Task 1 |
| 4 | Linux iptables implementation | Task 1 |
| 5 | Windows netsh implementation | Task 1 |
| 6 | Integration tests | Tasks 2-5 |

---

## 9. Testing Strategy

### Unit Tests

- Rule validation
- Platform trait mock
- Module lifecycle

### Integration Tests

- Add/remove rules via real platform
- Rule persistence across restarts
- Cross-platform compatibility

---

## 10. Non-Goals

- Deep packet inspection
- Application-layer filtering
- IDS/IPS functionality
- Network address translation (NAT)
