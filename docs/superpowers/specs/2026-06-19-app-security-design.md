# App Security — Design Specification

> **Date:** 2026-06-19
> **Status:** Approved
> **Stack:** Rust + Tauri + WireGuard

---

## 1. Overview

Desktop security application for protecting users on public WiFi/LAN networks with active threat detection and device anonymization.

### Target Users
- Freelancers, developers, remote workers at coworking spaces/cafés
- IT skill level: intermediate — needs simple, automated UX

### Decisions
| Decision | Choice |
|----------|--------|
| Platform | Cross-platform (macOS, Linux, Windows) |
| Language | Rust |
| UI Framework | Tauri |
| VPN | WireGuard (boringtun / wireguard-go) |
| Business Model | Open-source / Personal |
| Execution Mode | Flexible (daemon + on-demand) |
| MVP Scope | 8 features |
| Priority | Maximum security |

---

## 2. Architecture

### System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Tauri UI (WebView)                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │Dashboard │ │ Settings │ │  Alerts  │ │   Logs   │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
└─────────────────────────────────────────────────────────┘
                           │
                    Tauri IPC (Rust ↔ JS)
                           │
┌─────────────────────────────────────────────────────────┐
│                    Core Engine (Rust)                    │
│  ┌──────────────────────────────────────────────────┐  │
│  │              Module Manager                       │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐        │  │
│  │  │  VPN     │ │ Firewall │ │   DNS    │ ...    │  │
│  │  │  Module  │ │  Module  │ │  Module  │        │  │
│  │  └──────────┘ └──────────┘ └──────────┘        │  │
│  └──────────────────────────────────────────────────┘  │
│                           │                             │
│  ┌──────────────────────────────────────────────────┐  │
│  │              OS Abstraction Layer                 │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐        │  │
│  │  │  macOS   │ │  Linux   │ │ Windows  │        │  │
│  │  │ Platform │ │ Platform │ │ Platform │        │  │
│  │  └──────────┘ └──────────┘ └──────────┘        │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                           │
                    System Calls (root/admin)
                           │
┌─────────────────────────────────────────────────────────┐
│                    OS Network Stack                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │Firewall  │ │ Network  │ │  Packet  │ │  VPN     │  │
│  │  (pf/    │ │Interfaces│ │ Capture  │ │ WireGuard│  │
│  │ iptables)│ │          │ │ (libpcap)│ │          │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Layer Description

| Layer | Responsibility | Technology |
|-------|----------------|------------|
| **Tauri UI** | User interface, dashboard, settings | WebView + React/Vue/Svelte |
| **Core Engine** | Module management, business logic | Rust |
| **OS Abstraction** | Platform-specific implementations | Rust traits + platform crates |
| **OS Network Stack** | Actual system operations | System calls (root required) |

### Design Principles

1. **Modular** — Each feature is an independent module, disableable without affecting others
2. **Platform-abstracted** — Common interface, OS-specific implementations
3. **Security-first** — Every module validates inputs, logs actions, handles errors safely
4. **Flexible** — Supports both daemon and on-demand execution modes

---

## 3. Module Design

### MVP Modules (8 features)

```
internal/
├── core/                    # Core engine, module manager
│   ├── mod.rs              # Module trait definition
│   ├── manager.rs          # Module lifecycle management
│   ├── config.rs           # Configuration management
│   └── state.rs            # Application state
├── network/
│   ├── vpn/                # [1] VPN auto-connect
│   │   ├── mod.rs
│   │   ├── wireguard.rs    # WireGuard implementation
│   │   └── config.rs
│   ├── killswitch/         # [2] Kill switch
│   │   ├── mod.rs
│   │   └── platform/       # OS-specific implementation
│   ├── firewall/           # [7] Firewall hardening
│   │   ├── mod.rs
│   │   ├── macos.rs        # pf firewall
│   │   ├── linux.rs        # iptables/nftables
│   │   └── windows.rs      # Windows Firewall
│   └── dns/                # [5,14] DoH + DNS leak prevention
│       ├── mod.rs
│       ├── doh.rs          # DNS-over-HTTPS client
│       └── leak.rs         # DNS leak detection
├── detection/
│   ├── arp/                # [4] ARP spoof detection
│   │   ├── mod.rs
│   │   └── monitor.rs      # ARP table monitoring
│   └── monitor.rs          # Network monitoring core
├── anonymity/
│   ├── mac/                # [9] MAC randomization
│   │   ├── mod.rs
│   │   └── platform/       # OS-specific MAC spoofing
│   └── hostname/           # [10] Hostname spoofing
│       ├── mod.rs
│       └── platform/
├── alert/                  # [8] Alert system
│   ├── mod.rs
│   ├── tray.rs             # System tray notifications
│   └── log.rs              # Event logging
└── ui/                     # Tauri commands (IPC bridge)
    ├── mod.rs
    ├── commands.rs          # Tauri command handlers
    └── state.rs             # UI state management
```

### Module Trait

```rust
#[async_trait::async_trait]
pub trait SecurityModule: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn priority(&self) -> u32;
    fn dependencies(&self) -> Vec<&str>;
    async fn initialize(&mut self, config: &ModuleConfig) -> Result<()>;
    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
    fn status(&self) -> ModuleStatus;
    async fn on_event(&mut self, event: &ModuleEvent) -> Result<()>;
}
```

### Module Lifecycle

```
Created → Initialized → Starting → Running → Stopping → Stopped
                          ↑                      │
                          └──────────────────────┘
                            (restart on failure)
```

### MVP Feature → Module Mapping

| # | Feature | Module | Priority | Dependencies |
|---|---------|--------|----------|--------------|
| 1 | VPN auto-connect | `network::vpn` | 1 | None |
| 2 | Kill switch | `network::killswitch` | 2 | VPN [1] |
| 4 | ARP spoof detection | `detection::arp` | 3 | None |
| 5 | DNS-over-HTTPS | `network::dns::doh` | 4 | None |
| 7 | Firewall hardening | `network::firewall` | 5 | None |
| 8 | Alert system | `alert` | 6 | None |
| 9 | MAC randomization | `anonymity::mac` | 7 | None |
| 14 | DNS leak prevention | `network::dns::leak` | 8 | VPN [1], DoH [5] |

---

## 4. OS Abstraction Layer

### Platform Trait

```rust
#[async_trait::async_trait]
pub trait Platform: Send + Sync {
    // Network Interface Operations
    async fn get_network_interfaces(&self) -> Result<Vec<NetworkInterface>>;
    async fn get_active_interface(&self) -> Result<NetworkInterface>;
    async fn set_interface_up(&self, iface: &str) -> Result<()>;
    async fn set_interface_down(&self, iface: &str) -> Result<()>;
    
    // MAC Operations
    async fn get_mac_address(&self, iface: &str) -> Result<String>;
    async fn set_mac_address(&self, iface: &str, mac: &str) -> Result<()>;
    async fn restore_mac_address(&self, iface: &str) -> Result<()>;
    
    // Hostname Operations
    async fn get_hostname(&self) -> Result<String>;
    async fn set_hostname(&self, hostname: &str) -> Result<()>;
    async fn restore_hostname(&self) -> Result<()>;
    
    // Firewall Operations
    async fn add_firewall_rule(&self, rule: &FirewallRule) -> Result<()>;
    async fn remove_firewall_rule(&self, rule_id: &str) -> Result<()>;
    async fn flush_firewall_rules(&self) -> Result<()>;
    
    // Packet Capture
    async fn start_packet_capture(&self, iface: &str, filter: &str) -> Result<PacketReceiver>;
    async fn stop_packet_capture(&self, handle: CaptureHandle) -> Result<()>;
    
    // DNS Operations
    async fn get_dns_servers(&self, iface: &str) -> Result<Vec<String>>;
    async fn set_dns_servers(&self, iface: &str, servers: &[String]) -> Result<()>;
    async fn restore_dns_servers(&self, iface: &str) -> Result<()>;
    
    // VPN Operations
    async fn create_wireguard_interface(&self, config: &WireGuardConfig) -> Result<String>;
    async fn delete_wireguard_interface(&self, iface: &str) -> Result<()>;
    async fn set_wireguard_peer(&self, iface: &str, peer: &WireGuardPeer) -> Result<()>;
    
    // Process Operations
    async fn check_admin_privileges(&self) -> Result<bool>;
    async fn request_elevation(&self) -> Result<()>;
}
```

### Platform Implementations

```
internal/core/platform/
├── mod.rs              # Platform trait + factory
├── macos/
│   ├── mod.rs          # macOS Platform implementation
│   ├── network.rs      # ifconfig, networksetup
│   ├── firewall.rs     # pf (Packet Filter)
│   ├── mac.rs          # ifconfig en0 ether XX:XX:XX:XX
│   ├── hostname.rs     # scutil --set ComputerName
│   └── dns.rs          # networksetup -setdnsservers
├── linux/
│   ├── mod.rs          # Linux Platform implementation
│   ├── network.rs      # ip link, nmcli
│   ├── firewall.rs     # iptables/nftables
│   ├── mac.rs          # ip link set dev eth0 address
│   ├── hostname.rs     # hostnamectl
│   └── dns.rs          # resolvectl, /etc/resolv.conf
└── windows/
    ├── mod.rs          # Windows Platform implementation
    ├── network.rs      # Get-NetAdapter, netsh
    ├── firewall.rs     # netsh advfirewall, Windows Firewall API
    ├── mac.rs          # Registry + netsh
    ├── hostname.rs     # Set-ComputerName
    └── dns.rs          # netsh interface ip set dns
```

### Platform Factory

```rust
pub fn create_platform() -> Box<dyn Platform> {
    match std::env::consts::OS {
        "macos" => Box::new(macos::MacOSPlatform::new()),
        "linux" => Box::new(linux::LinuxPlatform::new()),
        "windows" => Box::new(windows::WindowsPlatform::new()),
        os => panic!("Unsupported OS: {}", os),
    }
}
```

### Safety Mechanism

```rust
pub async fn safe_platform_operation<F, T>(
    platform: &dyn Platform,
    operation: F,
    description: &str,
) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    info!("Executing: {}", description);
    
    if !platform.check_admin_privileges().await? {
        return Err(Error::InsufficientPrivileges {
            operation: description.to_string(),
        });
    }
    
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        operation,
    ).await??;
    
    info!("Completed: {}", description);
    Ok(result)
}
```

---

## 5. Tauri UI Integration

### Tauri Commands (IPC Bridge)

```rust
#[command] pub async fn vpn_connect(state: State<'_, AppState>) -> Result<(), String> { ... }
#[command] pub async fn vpn_disconnect(state: State<'_, AppState>) -> Result<(), String> { ... }
#[command] pub async fn vpn_status(state: State<'_, AppState>) -> Result<VpnStatus, String> { ... }
#[command] pub async fn firewall_enable(state: State<'_, AppState>) -> Result<(), String> { ... }
#[command] pub async fn firewall_disable(state: State<'_, AppState>) -> Result<(), String> { ... }
#[command] pub async fn mac_randomize(state: State<'_, AppState>, iface: String) -> Result<String, String> { ... }
#[command] pub async fn mac_restore(state: State<'_, AppState>, iface: String) -> Result<(), String> { ... }
#[command] pub async fn detection_status(state: State<'_, AppState>) -> Result<DetectionStatus, String> { ... }
#[command] pub async fn get_alerts(state: State<'_, AppState>, limit: Option<usize>) -> Result<Vec<Alert>, String> { ... }
#[command] pub async fn system_status(state: State<'_, AppState>) -> Result<SystemStatus, String> { ... }
```

### Frontend Architecture

```
src/
├── App.tsx
├── components/
│   ├── Dashboard/
│   │   ├── StatusPanel.tsx
│   │   ├── NetworkMap.tsx
│   │   └── ThreatIndicator.tsx
│   ├── Settings/
│   │   ├── VpnSettings.tsx
│   │   ├── FirewallRules.tsx
│   │   └── AnonymitySettings.tsx
│   ├── Alerts/
│   │   ├── AlertList.tsx
│   │   └── AlertDetail.tsx
│   └── common/
│       ├── StatusBadge.tsx
│       └── LoadingSpinner.tsx
├── hooks/
│   ├── useVpn.ts
│   ├── useFirewall.ts
│   └── useDetection.ts
├── api/
│   └── tauri.ts
└── types/
    └── index.ts
```

---

## 6. Data Flow & State Management

### Event System

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModuleEvent {
    // VPN Events
    VpnConnected { server: String, ip: String },
    VpnDisconnected { reason: String },
    VpnConnectionFailed { error: String },
    
    // Detection Events
    ArpSpoofDetected { attacker_mac: String, victim_ip: String },
    EvilTwinDetected { fake_ap_bssid: String, signal_strength: i32 },
    SuspiciousTraffic { src_ip: String, dst_ip: String, protocol: String },
    
    // Anonymity Events
    MacChanged { interface: String, old_mac: String, new_mac: String },
    HostnameChanged { old_hostname: String, new_hostname: String },
    
    // Firewall Events
    FirewallRuleAdded { rule_id: String, description: String },
    FirewallRuleBlocked { src_ip: String, dst_port: u16 },
    
    // DNS Events
    DnsLeakDetected { dns_server: String, interface: String },
    DohConnected { server: String },
    
    // System Events
    ModuleStarted { module_id: String },
    ModuleStopped { module_id: String },
    ModuleFailed { module_id: String, error: String },
}
```

### State Synchronization Flow

```
1. Module emits Event
   ↓
2. EventBus broadcasts to all subscribers
   ↓
3. State Manager updates Global State
   ↓
4. Tauri emits state change to Frontend
   ↓
5. Frontend React State updates
   ↓
6. UI re-renders with new state
```

### Data Persistence

```
config/
├── app.toml
├── modules/
│   ├── vpn.toml
│   ├── firewall.toml
│   └── dns.toml
└── logs/
    ├── app.log
    ├── security.log
    └── alerts.json
```

---

## 7. Security Considerations

### Security Layers

| Layer | Description |
|-------|-------------|
| **Input Validation** | All external inputs validated before processing |
| **Privilege Management** | Root/admin required, minimal privilege principle |
| **State Protection** | Critical changes require confirmation, rollback capability |
| **Secure Storage** | VPN credentials encrypted in OS keychain |
| **Network Security** | All communications encrypted, DNS leak prevention |

### Key Security Features

- **DNS Leak Prevention:** All DNS through encrypted tunnel, monitor non-VPN interfaces
- **Kill Switch:** Block all traffic if VPN drops, restore only on reconnect
- **Traffic Obfuscation:** Randomize timing, dummy traffic, TLS fingerprint rotation
- **Secure Defaults:** All security features enabled by default

---

## 8. Testing Strategy

### Testing Pyramid

| Level | Coverage | Description |
|-------|----------|-------------|
| **Unit Tests** | 70% | Core logic with platform stubs |
| **Integration Tests** | 25% | Module interactions, cross-platform |
| **E2E Tests** | 5% | Tauri + real system critical flows |

### Test Configuration

```toml
[[test]]
name = "unit"
path = "tests/unit"

[[test]]
name = "integration"
path = "tests/integration"

[[test]]
name = "e2e"
path = "tests/e2e"
```

### Security Testing

- Input validation tests (malicious MAC, hostname buffer overflow, SQL injection)
- Privilege escalation tests
- Rollback mechanism tests
- VPN credential security tests

---

## 9. Open Questions

| # | Question | Impact | Status |
|---|----------|--------|--------|
| 1 | WireGuard: boringtun vs wireguard-go FFI? | VPN stability | TBD |
| 2 | Frontend framework: React, Vue, or Svelte? | UI development | TBD |
| 3 | Logging: env_logger vs tracing? | Observability | TBD |
| 4 | Config format: TOML vs YAML? | User experience | TBD |
| 5 | Update mechanism: auto-update or manual? | Distribution | TBD |

---

## 10. Non-Goals

- Application-layer security (antivirus, EDR)
- Physical security (USB, camera)
- Mobile platforms (iOS, Android)
- Browser extension integration
- Cloud sync or remote management
