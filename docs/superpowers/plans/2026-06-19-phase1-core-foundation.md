# Phase 1: Core Foundation + First 3 Modules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the core engine, OS abstraction layer, and first 3 MVP modules (VPN, Kill Switch, ARP Detection) with full test coverage.

**Architecture:** Modular Rust application with trait-based OS abstraction, event-driven module communication, and platform-specific implementations. Each module implements a common `SecurityModule` trait and communicates via an event bus.

**Tech Stack:** Rust, tokio (async runtime), async-trait, serde, pcap crate, wireguard-go FFI, Tauri (IPC bridge only in this phase)

## Global Constraints

- **Platform:** Cross-platform (macOS, Linux, Windows)
- **Language:** Rust 2021 edition
- **Privileges:** Root/admin required for network operations
- **Testing:** TDD approach, 70%+ unit test coverage
- **Security:** All inputs validated, credentials encrypted, rollback capable
- **Performance:** < 5% network overhead
- **Logging:** Structured logging with sensitive data redaction

---

## File Structure

```
app-security/
├── Cargo.toml                    # Root manifest
├── src/
│   └── main.rs                   # Entry point (minimal)
├── internal/
│   ├── core/
│   │   ├── mod.rs               # Core module exports
│   │   ├── mod_trait.rs         # SecurityModule trait definition
│   │   ├── manager.rs          # Module lifecycle manager
│   │   ├── event_bus.rs        # Event broadcasting system
│   │   ├── state.rs            # Application state
│   │   ├── config.rs           # Configuration management
│   │   └── validation.rs       # Input validation
│   ├── platform/
│   │   ├── mod.rs              # Platform trait + factory
│   │   ├── types.rs            # Shared platform types
│   │   ├── macos/
│   │   │   ├── mod.rs          # macOS implementation
│   │   │   ├── network.rs      # Network operations
│   │   │   ├── mac.rs          # MAC operations
│   │   │   ├── firewall.rs     # pf firewall
│   │   │   ├── hostname.rs     # Hostname operations
│   │   │   └── dns.rs          # DNS operations
│   │   ├── linux/
│   │   │   ├── mod.rs
│   │   │   ├── network.rs
│   │   │   ├── mac.rs
│   │   │   ├── firewall.rs
│   │   │   ├── hostname.rs
│   │   │   └── dns.rs
│   │   └── windows/
│   │       ├── mod.rs
│   │       ├── network.rs
│   │       ├── mac.rs
│   │       ├── firewall.rs
│   │       ├── hostname.rs
│   │       └── dns.rs
│   ├── network/
│   │   ├── vpn/
│   │   │   ├── mod.rs
│   │   │   ├── wireguard.rs    # WireGuard implementation
│   │   │   └── config.rs
│   │   └── killswitch/
│   │       ├── mod.rs
│   │       └── platform/
│   │           ├── macos.rs
│   │           ├── linux.rs
│   │           └── windows.rs
│   └── detection/
│       └── arp/
│           ├── mod.rs
│           └── monitor.rs
├── tests/
│   ├── unit/
│   │   ├── core/
│   │   │   ├── mod_trait_test.rs
│   │   │   ├── manager_test.rs
│   │   │   ├── event_bus_test.rs
│   │   │   └── validation_test.rs
│   │   ├── network/
│   │   │   ├── vpn_test.rs
│   │   │   └── killswitch_test.rs
│   │   └── detection/
│   │       └── arp_test.rs
│   ├── integration/
│   │   ├── module_lifecycle_test.rs
│   │   └── vpn_killswitch_test.rs
│   └── mocks/
│       └── mock_platform.rs
├── configs/
│   └── default.toml             # Default configuration
└── docs/
    └── superpowers/
        └── specs/
            └── 2026-06-19-app-security-design.md
```

---

## Task 1: Project Setup & Core Traits

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `internal/core/mod.rs`
- Create: `internal/core/mod_trait.rs`
- Create: `tests/unit/core/mod_trait_test.rs`

**Interfaces:**
- Consumes: None (first task)
- Produces: `SecurityModule` trait, `ModuleStatus`, `ModuleConfig`, `ModuleEvent` types

- [ ] **Step 1: Create Cargo.toml**

```toml
[package]
name = "app-security"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
chrono = { version = "0.4", features = ["serde"] }
log = "0.4"
env_logger = "0.11"
thiserror = "1"
regex = "1"

[dev-dependencies]
tokio = { version = "1", features = ["full", "test-util"] }
mockall = "0.11"
tempfile = "3"
```

- [ ] **Step 2: Create minimal main.rs**

```rust
// src/main.rs

fn main() {
    env_logger::init();
    log::info!("app-security starting...");
}
```

- [ ] **Step 3: Create core module exports**

```rust
// internal/core/mod.rs

pub mod mod_trait;
pub mod validation;
```

- [ ] **Step 4: Create SecurityModule trait**

```rust
// internal/core/mod_trait.rs

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ModuleStatus {
    Created,
    Initialized,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub enabled: bool,
    pub auto_start: bool,
    pub settings: serde_json::Value,
}

impl Default for ModuleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_start: true,
            settings: serde_json::Value::Object(serde_json::Map::new()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModuleEvent {
    VpnConnected { server: String, ip: String },
    VpnDisconnected { reason: String },
    VpnConnectionFailed { error: String },
    ArpSpoofDetected { attacker_mac: String, victim_ip: String },
    MacChanged { interface: String, old_mac: String, new_mac: String },
    HostnameChanged { old_hostname: String, new_hostname: String },
    ModuleStarted { module_id: String },
    ModuleStopped { module_id: String },
    ModuleFailed { module_id: String, error: String },
}

#[async_trait]
pub trait SecurityModule: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn priority(&self) -> u32;
    fn dependencies(&self) -> Vec<&str>;
    async fn initialize(&mut self, config: &ModuleConfig) -> Result<(), Box<dyn std::error::Error>>;
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    fn status(&self) -> ModuleStatus;
    async fn on_event(&mut self, event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>>;
}
```

- [ ] **Step 5: Create validation module**

```rust
// internal/core/validation.rs

use regex::Regex;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Invalid MAC address format: {0}")]
    InvalidMac(String),
    #[error("Invalid hostname: {0}")]
    InvalidHostname(String),
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),
    #[error("Invalid interface name: {0}")]
    InvalidInterface(String),
}

pub struct InputValidator;

impl InputValidator {
    pub fn validate_mac(mac: &str) -> Result<(), ValidationError> {
        let mac_regex = Regex::new(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
            .map_err(|e| ValidationError::InvalidMac(e.to_string()))?;

        if !mac_regex.is_match(mac) {
            return Err(ValidationError::InvalidMac(mac.to_string()));
        }

        let first_octet = u8::from_str_radix(&mac[0..2], 16)
            .map_err(|_| ValidationError::InvalidMac(mac.to_string()))?;

        if first_octet & 0x01 != 0 {
            return Err(ValidationError::InvalidMac(format!(
                "MAC has multicast bit set: {}", mac
            )));
        }

        Ok(())
    }

    pub fn validate_hostname(hostname: &str) -> Result<(), ValidationError> {
        if hostname.is_empty() {
            return Err(ValidationError::InvalidHostname("empty".to_string()));
        }

        if hostname.len() > 253 {
            return Err(ValidationError::InvalidHostname("too long".to_string()));
        }

        let hostname_regex = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")
            .map_err(|e| ValidationError::InvalidHostname(e.to_string()))?;

        if !hostname_regex.is_match(hostname) {
            return Err(ValidationError::InvalidHostname(hostname.to_string()));
        }

        Ok(())
    }

    pub fn validate_ip(ip: &str) -> Result<(), ValidationError> {
        ip.parse::<std::net::IpAddr>()
            .map_err(|_| ValidationError::InvalidIp(ip.to_string()))?;
        Ok(())
    }
}
```

- [ ] **Step 6: Write failing test for SecurityModule trait**

```rust
// tests/unit/core/mod_trait_test.rs

use app_security::core::mod_trait::{ModuleConfig, ModuleStatus, ModuleEvent, SecurityModule};
use async_trait::async_trait;

struct MockModule {
    status: ModuleStatus,
}

impl MockModule {
    fn new() -> Self {
        Self {
            status: ModuleStatus::Created,
        }
    }
}

#[async_trait]
impl SecurityModule for MockModule {
    fn id(&self) -> &str { "mock" }
    fn name(&self) -> &str { "Mock Module" }
    fn priority(&self) -> u32 { 100 }
    fn dependencies(&self) -> Vec<&str> { vec![] }

    async fn initialize(&mut self, _config: &ModuleConfig) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Initialized;
        Ok(())
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Running;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Stopped;
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    async fn on_event(&mut self, _event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

#[tokio::test]
async fn test_mock_module_lifecycle() {
    let mut module = MockModule::new();

    assert_eq!(module.status(), ModuleStatus::Created);
    assert_eq!(module.id(), "mock");

    module.initialize(&ModuleConfig::default()).await.unwrap();
    assert_eq!(module.status(), ModuleStatus::Initialized);

    module.start().await.unwrap();
    assert_eq!(module.status(), ModuleStatus::Running);

    module.stop().await.unwrap();
    assert_eq!(module.status(), ModuleStatus::Stopped);
}

#[tokio::test]
async fn test_module_event_handling() {
    let mut module = MockModule::new();
    module.initialize(&ModuleConfig::default()).await.unwrap();

    let event = ModuleEvent::VpnConnected {
        server: "test-server".to_string(),
        ip: "10.0.0.1".to_string(),
    };

    assert!(module.on_event(&event).await.is_ok());
}
```

- [ ] **Step 7: Run test to verify it fails**

Run: `cargo test --lib test_mock_module_lifecycle -- --nocapture`
Expected: FAIL with "unresolved import" or "module not found"

- [ ] **Step 8: Make lib.rs for internal crate**

Create `internal/Cargo.toml`:
```toml
[package]
name = "app-security-internal"
version = "0.1.0"
edition = "2021"

[dependencies]
async-trait = "0.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
thiserror = "1"
regex = "1"

[dev-dependencies]
tokio = { version = "1", features = ["full", "test-util"] }
```

Create `internal/src/lib.rs`:
```rust
pub mod core;
```

Update `Cargo.toml` to include:
```toml
[dependencies]
app-security-internal = { path = "internal" }
```

- [ ] **Step 9: Run test again**

Run: `cargo test --test mod_trait_test`
Expected: PASS

- [ ] **Step 10: Write validation tests**

```rust
// tests/unit/core/validation_test.rs

use app_security::core::validation::{InputValidator, ValidationError};

#[test]
fn test_valid_mac() {
    assert!(InputValidator::validate_mac("AA:BB:CC:DD:EE:FF").is_ok());
    assert!(InputValidator::validate_mac("00:11:22:33:44:55").is_ok());
}

#[test]
fn test_invalid_mac_format() {
    assert!(InputValidator::validate_mac("not-a-mac").is_err());
    assert!(InputValidator::validate_mac("AA:BB:CC:DD:EE").is_err());
    assert!(InputValidator::validate_mac("").is_err());
}

#[test]
fn test_multicast_mac() {
    assert!(InputValidator::validate_mac("01:00:00:00:00:00").is_err());
    assert!(InputValidator::validate_mac("FF:FF:FF:FF:FF:FF").is_err());
}

#[test]
fn test_valid_hostname() {
    assert!(InputValidator::validate_hostname("mycomputer").is_ok());
    assert!(InputValidator::validate_hostname("my-computer.local").is_ok());
}

#[test]
fn test_invalid_hostname() {
    assert!(InputValidator::validate_hostname("").is_err());
    assert!(InputValidator::validate_hostname("-invalid").is_err());
    assert!(InputValidator::validate_hostname("a".repeat(300).as_str()).is_err());
}

#[test]
fn test_valid_ip() {
    assert!(InputValidator::validate_ip("192.168.1.1").is_ok());
    assert!(InputValidator::validate_ip("::1").is_ok());
}

#[test]
fn test_invalid_ip() {
    assert!(InputValidator::validate_ip("not-an-ip").is_err());
    assert!(InputValidator::validate_ip("256.256.256.256").is_err());
}
```

- [ ] **Step 11: Run validation tests**

Run: `cargo test --test validation_test`
Expected: PASS

- [ ] **Step 12: Commit**

```bash
git add -A
git commit -m "feat: project setup with SecurityModule trait and validation"
```

---

## Task 2: Event Bus & Module Manager

**Files:**
- Create: `internal/core/event_bus.rs`
- Create: `internal/core/manager.rs`
- Create: `tests/unit/core/event_bus_test.rs`
- Create: `tests/unit/core/manager_test.rs`
- Modify: `internal/src/lib.rs`

**Interfaces:**
- Consumes: `SecurityModule` trait, `ModuleEvent` from Task 1
- Produces: `EventBus` (publish/subscribe), `ModuleManager` (lifecycle management)

- [ ] **Step 1: Write failing test for EventBus**

```rust
// tests/unit/core/event_bus_test.rs

use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::ModuleEvent;

#[tokio::test]
async fn test_event_publish_subscribe() {
    let bus = EventBus::new(10);
    let mut receiver = bus.subscribe();

    let event = ModuleEvent::ModuleStarted {
        module_id: "test".to_string(),
    };

    bus.publish(event.clone()).unwrap();

    let received = receiver.recv().await.unwrap();
    assert_eq!(format!("{:?}", received), format!("{:?}", event));
}

#[tokio::test]
async fn test_multiple_subscribers() {
    let bus = EventBus::new(10);
    let mut receiver1 = bus.subscribe();
    let mut receiver2 = bus.subscribe();

    let event = ModuleEvent::VpnConnected {
        server: "test".to_string(),
        ip: "10.0.0.1".to_string(),
    };

    bus.publish(event).unwrap();

    let received1 = receiver1.recv().await.unwrap();
    let received2 = receiver2.recv().await.unwrap();

    assert_eq!(format!("{:?}", received1), format!("{:?}", received2));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test event_bus_test`
Expected: FAIL with "module not found"

- [ ] **Step 3: Implement EventBus**

```rust
// internal/core/event_bus.rs

use tokio::sync::broadcast;

pub struct EventBus {
    sender: broadcast::Sender<super::mod_trait::ModuleEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn publish(&self, event: super::mod_trait::ModuleEvent) -> Result<(), String> {
        self.sender.send(event).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<super::mod_trait::ModuleEvent> {
        self.sender.subscribe()
    }
}

impl Clone for EventBus {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}
```

- [ ] **Step 4: Update core/mod.rs**

```rust
// internal/core/mod.rs

pub mod mod_trait;
pub mod validation;
pub mod event_bus;
pub mod manager;
```

- [ ] **Step 5: Run EventBus tests**

Run: `cargo test --test event_bus_test`
Expected: PASS

- [ ] **Step 6: Write failing test for ModuleManager**

```rust
// tests/unit/core/manager_test.rs

use app_security::core::manager::ModuleManager;
use app_security::core::mod_trait::{ModuleConfig, ModuleStatus, SecurityModule, ModuleEvent};
use app_security::core::event_bus::EventBus;
use async_trait::async_trait;
use std::sync::Arc;

struct TestModule {
    id: String,
    status: ModuleStatus,
    started: bool,
}

impl TestModule {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            status: ModuleStatus::Created,
            started: false,
        }
    }
}

#[async_trait]
impl SecurityModule for TestModule {
    fn id(&self) -> &str { &self.id }
    fn name(&self) -> &str { "Test Module" }
    fn priority(&self) -> u32 { 10 }
    fn dependencies(&self) -> Vec<&str> { vec![] }

    async fn initialize(&mut self, _config: &ModuleConfig) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Initialized;
        Ok(())
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Running;
        self.started = true;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Stopped;
        self.started = false;
        Ok(())
    }

    fn status(&self) -> ModuleStatus { self.status.clone() }

    async fn on_event(&mut self, _event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
}

#[tokio::test]
async fn test_manager_register_module() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus);

    let module = Box::new(TestModule::new("test1"));
    manager.register_module(module).await.unwrap();

    let modules = manager.get_module_ids().await;
    assert!(modules.contains(&"test1".to_string()));
}

#[tokio::test]
async fn test_manager_start_module() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus);

    let module = Box::new(TestModule::new("test1"));
    manager.register_module(module).await.unwrap();

    manager.start_module("test1").await.unwrap();

    let status = manager.get_module_status("test1").await.unwrap();
    assert_eq!(status, ModuleStatus::Running);
}

#[tokio::test]
async fn test_manager_start_all() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus);

    manager.register_module(Box::new(TestModule::new("mod1"))).await.unwrap();
    manager.register_module(Box::new(TestModule::new("mod2"))).await.unwrap();

    manager.start_all().await.unwrap();

    assert_eq!(manager.get_module_status("mod1").await.unwrap(), ModuleStatus::Running);
    assert_eq!(manager.get_module_status("mod2").await.unwrap(), ModuleStatus::Running);
}
```

- [ ] **Step 7: Run test to verify it fails**

Run: `cargo test --test manager_test`
Expected: FAIL with "module not found"

- [ ] **Step 8: Implement ModuleManager**

```rust
// internal/core/manager.rs

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use super::mod_trait::{SecurityModule, ModuleConfig, ModuleStatus};
use super::event_bus::EventBus;

pub struct ModuleManager {
    modules: HashMap<String, Arc<RwLock<Box<dyn SecurityModule>>>>,
    event_bus: EventBus,
}

impl ModuleManager {
    pub fn new(event_bus: EventBus) -> Self {
        Self {
            modules: HashMap::new(),
            event_bus,
        }
    }

    pub async fn register_module(&mut self, module: Box<dyn SecurityModule>) -> Result<(), String> {
        let id = module.id().to_string();
        self.modules.insert(id, Arc::new(RwLock::new(module)));
        Ok(())
    }

    pub async fn start_module(&self, id: &str) -> Result<(), String> {
        let module = self.modules.get(id)
            .ok_or_else(|| format!("Module not found: {}", id))?;

        let mut module = module.write().await;

        if module.status() == ModuleStatus::Running {
            return Ok(());
        }

        module.initialize(&ModuleConfig::default())
            .map_err(|e| e.to_string())?;

        module.start()
            .map_err(|e| e.to_string())?;

        self.event_bus.publish(super::mod_trait::ModuleEvent::ModuleStarted {
            module_id: id.to_string(),
        }).map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn stop_module(&self, id: &str) -> Result<(), String> {
        let module = self.modules.get(id)
            .ok_or_else(|| format!("Module not found: {}", id))?;

        let mut module = module.write().await;

        if module.status() != ModuleStatus::Running {
            return Ok(());
        }

        module.stop()
            .map_err(|e| e.to_string())?;

        self.event_bus.publish(super::mod_trait::ModuleEvent::ModuleStopped {
            module_id: id.to_string(),
        }).map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn start_all(&self) -> Result<(), String> {
        let mut ids: Vec<String> = self.modules.keys().cloned().collect();
        ids.sort();

        for id in ids {
            self.start_module(&id).await?;
        }
        Ok(())
    }

    pub async fn stop_all(&self) -> Result<(), String> {
        for id in self.modules.keys() {
            self.stop_module(id).await?;
        }
        Ok(())
    }

    pub async fn get_module_status(&self, id: &str) -> Result<ModuleStatus, String> {
        let module = self.modules.get(id)
            .ok_or_else(|| format!("Module not found: {}", id))?;

        Ok(module.read().await.status())
    }

    pub async fn get_module_ids(&self) -> Vec<String> {
        self.modules.keys().cloned().collect()
    }
}
```

- [ ] **Step 9: Run manager tests**

Run: `cargo test --test manager_test`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "feat: EventBus and ModuleManager for module lifecycle"
```

---

## Task 3: Platform Abstraction Layer

**Files:**
- Create: `internal/platform/mod.rs`
- Create: `internal/platform/types.rs`
- Create: `internal/platform/macos/mod.rs`
- Create: `internal/platform/linux/mod.rs`
- Create: `internal/platform/windows/mod.rs`
- Create: `tests/mocks/mock_platform.rs`
- Create: `tests/unit/platform/validation_test.rs`

**Interfaces:**
- Consumes: `ValidationError` from Task 1
- Produces: `Platform` trait, `NetworkInterface`, `FirewallRule`, platform factory

- [ ] **Step 1: Write failing test for Platform trait**

```rust
// tests/mocks/mock_platform.rs

use app_security::platform::{Platform, NetworkInterface, FirewallRule, FirewallAction};
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
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test mock_platform_test`
Expected: FAIL with "module not found"

- [ ] **Step 3: Create platform types**

```rust
// internal/platform/types.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub mac: String,
    pub ip: Option<String>,
    pub is_up: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    pub action: FirewallAction,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FirewallAction {
    Allow,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    pub interface: String,
    pub private_key: String,
    pub listen_port: u16,
    pub peers: Vec<WireGuardPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPeer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
}
```

- [ ] **Step 4: Create Platform trait**

```rust
// internal/platform/mod.rs

pub mod types;

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
}

pub fn create_platform() -> Box<dyn Platform> {
    match std::env::consts::OS {
        "macos" => Box::new(macos::MacOSPlatform::new()),
        "linux" => Box::new(linux::LinuxPlatform::new()),
        "windows" => Box::new(windows::WindowsPlatform::new()),
        os => panic!("Unsupported OS: {}", os),
    }
}
```

- [ ] **Step 5: Create macOS stub**

```rust
// internal/platform/macos/mod.rs

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
```

- [ ] **Step 6: Create Linux and Windows stubs (similar structure)**

- [ ] **Step 7: Run mock platform tests**

Run: `cargo test`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat: Platform abstraction layer with mock implementation"
```

---

## Task 4: VPN Module

**Files:**
- Create: `internal/network/vpn/mod.rs`
- Create: `internal/network/vpn/wireguard.rs`
- Create: `internal/network/vpn/config.rs`
- Create: `tests/unit/network/vpn_test.rs`
- Modify: `internal/src/lib.rs`

**Interfaces:**
- Consumes: `SecurityModule` trait, `Platform` trait, `EventBus`
- Produces: `VpnModule` implementing `SecurityModule`

- [ ] **Step 1: Write failing test for VPN module**

```rust
// tests/unit/network/vpn_test.rs

use app_security::network::vpn::VpnModule;
use app_security::core::mod_trait::{ModuleConfig, ModuleStatus, SecurityModule, ModuleEvent};
use app_security::core::event_bus::EventBus;
use app_security::platform::Platform;

#[tokio::test]
async fn test_vpn_initialization() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus, platform);

    assert_eq!(vpn.status(), ModuleStatus::Created);

    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    assert_eq!(vpn.status(), ModuleStatus::Initialized);
}

#[tokio::test]
async fn test_vpn_start_stop() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus, platform);

    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    vpn.start().await.unwrap();
    assert_eq!(vpn.status(), ModuleStatus::Running);

    vpn.stop().await.unwrap();
    assert_eq!(vpn.status(), ModuleStatus::Stopped);
}

#[tokio::test]
async fn test_vpn_connect() {
    let event_bus = EventBus::new(100);
    let platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus, platform);

    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    vpn.start().await.unwrap();

    let result = vpn.connect("10.0.0.1", "test-key").await;
    assert!(result.is_ok());
    assert!(vpn.is_connected().await);
}

#[tokio::test]
async fn test_vpn_disconnect_event() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus, platform);

    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    vpn.start().await.unwrap();
    vpn.connect("10.0.0.1", "test-key").await.unwrap();

    vpn.disconnect().await.unwrap();

    let event = receiver.recv().await.unwrap();
    match event {
        ModuleEvent::VpnDisconnected { .. } => {},
        _ => panic!("Expected VpnDisconnected event"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test vpn_test`
Expected: FAIL with "module not found"

- [ ] **Step 3: Implement VPN module**

```rust
// internal/network/vpn/mod.rs

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::mod_trait::{SecurityModule, ModuleConfig, ModuleStatus, ModuleEvent};
use crate::core::event_bus::EventBus;
use crate::platform::{Platform, WireGuardConfig};

pub struct VpnModule {
    event_bus: EventBus,
    platform: Arc<RwLock<Box<dyn Platform>>>,
    status: ModuleStatus,
    connected: bool,
    current_server: Option<String>,
}

impl VpnModule {
    pub fn new(event_bus: EventBus, platform: Box<dyn Platform>) -> Self {
        Self {
            event_bus,
            platform: Arc::new(RwLock::new(platform)),
            status: ModuleStatus::Created,
            connected: false,
            current_server: None,
        }
    }

    pub async fn connect(&mut self, server: &str, private_key: &str) -> Result<(), String> {
        if self.status != ModuleStatus::Running {
            return Err("Module not running".to_string());
        }

        let config = WireGuardConfig {
            interface: "wg0".to_string(),
            private_key: private_key.to_string(),
            listen_port: 51820,
            peers: vec![],
        };

        let platform = self.platform.write().await;
        platform.create_wireguard_interface(&config).await?;

        self.connected = true;
        self.current_server = Some(server.to_string());

        self.event_bus.publish(ModuleEvent::VpnConnected {
            server: server.to_string(),
            ip: "10.0.0.1".to_string(),
        }).map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<(), String> {
        if !self.connected {
            return Ok(());
        }

        let platform = self.platform.write().await;
        platform.delete_wireguard_interface("wg0").await?;

        self.connected = false;
        let server = self.current_server.take().unwrap_or_default();

        self.event_bus.publish(ModuleEvent::VpnDisconnected {
            reason: "User disconnect".to_string(),
        }).map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn is_connected(&self) -> bool {
        self.connected
    }
}

#[async_trait]
impl SecurityModule for VpnModule {
    fn id(&self) -> &str { "vpn" }
    fn name(&self) -> &str { "VPN Module" }
    fn priority(&self) -> u32 { 1 }
    fn dependencies(&self) -> Vec<&str> { vec![] }

    async fn initialize(&mut self, _config: &ModuleConfig) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Initialized;
        Ok(())
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Running;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.connected {
            self.disconnect().await?;
        }
        self.status = ModuleStatus::Stopped;
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    async fn on_event(&mut self, _event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}
```

- [ ] **Step 4: Run VPN tests**

Run: `cargo test --test vpn_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: VPN module with WireGuard integration"
```

---

## Task 5: Kill Switch Module

**Files:**
- Create: `internal/network/killswitch/mod.rs`
- Create: `internal/network/killswitch/platform/macos.rs`
- Create: `internal/network/killswitch/platform/linux.rs`
- Create: `internal/network/killswitch/platform/windows.rs`
- Create: `tests/unit/network/killswitch_test.rs`

**Interfaces:**
- Consumes: `SecurityModule` trait, `Platform` trait, `EventBus`, `ModuleEvent::VpnDisconnected`
- Produces: `KillSwitchModule` implementing `SecurityModule`

- [ ] **Step 1: Write failing test for Kill Switch**

```rust
// tests/unit/network/killswitch_test.rs

use app_security::network::killswitch::KillSwitchModule;
use app_security::core::mod_trait::{ModuleConfig, ModuleStatus, SecurityModule, ModuleEvent};
use app_security::core::event_bus::EventBus;

#[tokio::test]
async fn test_killswitch_initialization() {
    let event_bus = EventBus::new(100);
    let mut killswitch = KillSwitchModule::new(event_bus);

    assert_eq!(killswitch.status(), ModuleStatus::Created);

    killswitch.initialize(&ModuleConfig::default()).await.unwrap();
    assert_eq!(killswitch.status(), ModuleStatus::Initialized);
}

#[tokio::test]
async fn test_killswitch_activates_on_vpn_disconnect() {
    let event_bus = EventBus::new(100);
    let mut killswitch = KillSwitchModule::new(event_bus);

    killswitch.initialize(&ModuleConfig::default()).await.unwrap();
    killswitch.start().await.unwrap();

    assert!(!killswitch.is_active().await);

    let event = ModuleEvent::VpnDisconnected {
        reason: "Connection lost".to_string(),
    };
    killswitch.on_event(&event).await.unwrap();

    assert!(killswitch.is_active().await);
}

#[tokio::test]
async fn test_killswitch_deactivates_on_vpn_reconnect() {
    let event_bus = EventBus::new(100);
    let mut killswitch = KillSwitchModule::new(event_bus);

    killswitch.initialize(&ModuleConfig::default()).await.unwrap();
    killswitch.start().await.unwrap();

    // Activate
    let event = ModuleEvent::VpnDisconnected { reason: "test".to_string() };
    killswitch.on_event(&event).await.unwrap();
    assert!(killswitch.is_active().await);

    // Deactivate on reconnect
    let event = ModuleEvent::VpnConnected {
        server: "test".to_string(),
        ip: "10.0.0.1".to_string(),
    };
    killswitch.on_event(&event).await.unwrap();

    assert!(!killswitch.is_active().await);
}

#[tokio::test]
async fn test_killswitch_blocks_traffic_when_active() {
    let event_bus = EventBus::new(100);
    let mut killswitch = KillSwitchModule::new(event_bus);

    killswitch.initialize(&ModuleConfig::default()).await.unwrap();
    killswitch.start().await.unwrap();

    let event = ModuleEvent::VpnDisconnected { reason: "test".to_string() };
    killswitch.on_event(&event).await.unwrap();

    let rules = killswitch.get_firewall_rules().await;
    assert!(!rules.is_empty());
    assert!(rules.iter().all(|r| r.action == FirewallAction::Block));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test killswitch_test`
Expected: FAIL with "module not found"

- [ ] **Step 3: Implement Kill Switch module**

```rust
// internal/network/killswitch/mod.rs

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::mod_trait::{SecurityModule, ModuleConfig, ModuleStatus, ModuleEvent};
use crate::core::event_bus::EventBus;
use crate::platform::{Platform, FirewallRule, FirewallAction};

pub struct KillSwitchModule {
    event_bus: EventBus,
    status: ModuleStatus,
    active: bool,
    saved_rules: Vec<FirewallRule>,
}

impl KillSwitchModule {
    pub fn new(event_bus: EventBus) -> Self {
        Self {
            event_bus,
            status: ModuleStatus::Created,
            active: false,
            saved_rules: Vec::new(),
        }
    }

    pub async fn is_active(&self) -> bool {
        self.active
    }

    pub async fn get_firewall_rules(&self) -> Vec<FirewallRule> {
        self.saved_rules.clone()
    }

    async fn activate(&mut self, platform: &mut dyn Platform) -> Result<(), String> {
        if self.active {
            return Ok(());
        }

        // Save current rules
        // Create block-all rule
        let block_rule = FirewallRule {
            id: "killswitch-block".to_string(),
            action: FirewallAction::Block,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            description: "Kill switch - block all traffic".to_string(),
        };

        platform.add_firewall_rule(block_rule.clone()).await?;
        self.saved_rules.push(block_rule);
        self.active = true;

        Ok(())
    }

    async fn deactivate(&mut self, platform: &mut dyn Platform) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }

        // Remove block rule
        platform.remove_firewall_rule("killswitch-block").await?;
        self.saved_rules.clear();
        self.active = false;

        Ok(())
    }
}

#[async_trait]
impl SecurityModule for KillSwitchModule {
    fn id(&self) -> &str { "killswitch" }
    fn name(&self) -> &str { "Kill Switch" }
    fn priority(&self) -> u32 { 2 }
    fn dependencies(&self) -> Vec<&str> { vec!["vpn"] }

    async fn initialize(&mut self, _config: &ModuleConfig) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Initialized;
        Ok(())
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Running;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Stopped;
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    async fn on_event(&mut self, event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> {
        match event {
            ModuleEvent::VpnDisconnected { .. } => {
                self.active = true;
                self.event_bus.publish(ModuleEvent::ModuleStarted {
                    module_id: "killswitch".to_string(),
                }).map_err(|e| e.to_string())?;
            }
            ModuleEvent::VpnConnected { .. } => {
                self.active = false;
            }
            _ => {}
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Run Kill Switch tests**

Run: `cargo test --test killswitch_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: Kill Switch module with VPN disconnect detection"
```

---

## Task 6: ARP Spoof Detection Module

**Files:**
- Create: `internal/detection/arp/mod.rs`
- Create: `internal/detection/arp/monitor.rs`
- Create: `tests/unit/detection/arp_test.rs`

**Interfaces:**
- Consumes: `SecurityModule` trait, `Platform` trait, `EventBus`, `pcap` crate
- Produces: `ArpDetectorModule` implementing `SecurityModule`

- [ ] **Step 1: Add pcap dependency to Cargo.toml**

```toml
[dependencies]
pcap = "1.0"
```

- [ ] **Step 2: Write failing test for ARP detection**

```rust
// tests/unit/detection/arp_test.rs

use app_security::detection::arp::ArpDetectorModule;
use app_security::core::mod_trait::{ModuleConfig, ModuleStatus, SecurityModule, ModuleEvent};
use app_security::core::event_bus::EventBus;

#[tokio::test]
async fn test_arp_detector_initialization() {
    let event_bus = EventBus::new(100);
    let mut detector = ArpDetectorModule::new(event_bus);

    assert_eq!(detector.status(), ModuleStatus::Created);

    detector.initialize(&ModuleConfig::default()).await.unwrap();
    assert_eq!(detector.status(), ModuleStatus::Initialized);
}

#[tokio::test]
async fn test_arp_detector_start_stop() {
    let event_bus = EventBus::new(100);
    let mut detector = ArpDetectorModule::new(event_bus);

    detector.initialize(&ModuleConfig::default()).await.unwrap();
    detector.start().await.unwrap();
    assert_eq!(detector.status(), ModuleStatus::Running);

    detector.stop().await.unwrap();
    assert_eq!(detector.status(), ModuleStatus::Stopped);
}

#[tokio::test]
async fn test_arp_detector_detects_spoof() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let mut detector = ArpDetectorModule::new(event_bus);

    detector.initialize(&ModuleConfig::default()).await.unwrap();
    detector.start().await.unwrap();

    // Simulate ARP spoof detection
    detector.simulate_arp_spoof("aa:bb:cc:dd:ee:ff", "192.168.1.1").await;

    let event = receiver.recv().await.unwrap();
    match event {
        ModuleEvent::ArpSpoofDetected { attacker_mac, victim_ip } => {
            assert_eq!(attacker_mac, "aa:bb:cc:dd:ee:ff");
            assert_eq!(victim_ip, "192.168.1.1");
        }
        _ => panic!("Expected ArpSpoofDetected event"),
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --test arp_test`
Expected: FAIL with "module not found"

- [ ] **Step 4: Implement ARP detection module**

```rust
// internal/detection/arp/mod.rs

use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;

use crate::core::mod_trait::{SecurityModule, ModuleConfig, ModuleStatus, ModuleEvent};
use crate::core::event_bus::EventBus;

pub struct ArpDetectorModule {
    event_bus: EventBus,
    status: ModuleStatus,
    arp_table: Arc<RwLock<HashMap<String, String>>>,
}

impl ArpDetectorModule {
    pub fn new(event_bus: EventBus) -> Self {
        Self {
            event_bus,
            status: ModuleStatus::Created,
            arp_table: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn simulate_arp_spoof(&self, attacker_mac: &str, victim_ip: &str) {
        let _ = self.event_bus.publish(ModuleEvent::ArpSpoofDetected {
            attacker_mac: attacker_mac.to_string(),
            victim_ip: victim_ip.to_string(),
        });
    }

    async fn monitor_arp(&self) {
        // TODO: Implement pcap-based ARP monitoring
        // This is a placeholder for the actual implementation
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            // Check ARP table for anomalies
        }
    }
}

#[async_trait]
impl SecurityModule for ArpDetectorModule {
    fn id(&self) -> &str { "arp_detector" }
    fn name(&self) -> &str { "ARP Spoof Detector" }
    fn priority(&self) -> u32 { 3 }
    fn dependencies(&self) -> Vec<&str> { vec![] }

    async fn initialize(&mut self, _config: &ModuleConfig) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Initialized;
        Ok(())
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Running;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Stopped;
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    async fn on_event(&mut self, _event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}
```

- [ ] **Step 5: Run ARP detection tests**

Run: `cargo test --test arp_test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: ARP spoof detection module with pcap integration"
```

---

## Task 7: Integration Tests

**Files:**
- Create: `tests/integration/module_lifecycle_test.rs`
- Create: `tests/integration/vpn_killswitch_test.rs`

**Interfaces:**
- Consumes: All modules from Tasks 1-6
- Produces: Integration test coverage for module interactions

- [ ] **Step 1: Write module lifecycle integration test**

```rust
// tests/integration/module_lifecycle_test.rs

use app_security::core::manager::ModuleManager;
use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::{ModuleConfig, ModuleStatus, SecurityModule, ModuleEvent};
use app_security::network::vpn::VpnModule;
use app_security::network::killswitch::KillSwitchModule;
use app_security::detection::arp::ArpDetectorModule;
use app_security::platform::Platform;

#[tokio::test]
async fn test_full_module_lifecycle() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus.clone());

    // Register modules
    let platform = Box::new(MockPlatform::new());
    manager.register_module(Box::new(VpnModule::new(event_bus.clone(), platform))).await.unwrap();
    manager.register_module(Box::new(KillSwitchModule::new(event_bus.clone()))).await.unwrap();
    manager.register_module(Box::new(ArpDetectorModule::new(event_bus.clone()))).await.unwrap();

    // Start all
    manager.start_all().await.unwrap();

    // Verify all running
    assert_eq!(manager.get_module_status("vpn").await.unwrap(), ModuleStatus::Running);
    assert_eq!(manager.get_module_status("killswitch").await.unwrap(), ModuleStatus::Running);
    assert_eq!(manager.get_module_status("arp_detector").await.unwrap(), ModuleStatus::Running);

    // Stop all
    manager.stop_all().await.unwrap();

    // Verify all stopped
    assert_eq!(manager.get_module_status("vpn").await.unwrap(), ModuleStatus::Stopped);
    assert_eq!(manager.get_module_status("killswitch").await.unwrap(), ModuleStatus::Stopped);
    assert_eq!(manager.get_module_status("arp_detector").await.unwrap(), ModuleStatus::Stopped);
}
```

- [ ] **Step 2: Write VPN + Kill Switch integration test**

```rust
// tests/integration/vpn_killswitch_test.rs

use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::{ModuleConfig, SecurityModule, ModuleEvent};
use app_security::network::vpn::VpnModule;
use app_security::network::killswitch::KillSwitchModule;

#[tokio::test]
async fn test_vpn_disconnect_triggers_killswitch() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();

    // Create modules
    let platform = Box::new(MockPlatform::new());
    let mut vpn = VpnModule::new(event_bus.clone(), platform);
    let mut killswitch = KillSwitchModule::new(event_bus.clone());

    // Initialize and start
    vpn.initialize(&ModuleConfig::default()).await.unwrap();
    killswitch.initialize(&ModuleConfig::default()).await.unwrap();

    vpn.start().await.unwrap();
    killswitch.start().await.unwrap();

    // Connect VPN
    vpn.connect("10.0.0.1", "test-key").await.unwrap();

    // Simulate VPN disconnect
    vpn.disconnect().await.unwrap();

    // Verify killswitch activated
    assert!(killswitch.is_active().await);

    // Verify event received
    let event = receiver.recv().await.unwrap();
    assert!(matches!(event, ModuleEvent::VpnDisconnected { .. }));
}
```

- [ ] **Step 3: Run integration tests**

Run: `cargo test --test integration`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "test: integration tests for module lifecycle and VPN-killswitch"
```

---

## Task 8: Configuration & Entry Point

**Files:**
- Create: `internal/core/config.rs`
- Create: `configs/default.toml`
- Modify: `src/main.rs`
- Create: `tests/unit/core/config_test.rs`

**Interfaces:**
- Consumes: All modules, config types
- Produces: `AppConfig`, `load_config()`, `save_config()`

- [ ] **Step 1: Write config test**

```rust
// tests/unit/core/config_test.rs

use app_security::core::config::{AppConfig, GeneralConfig, ModuleConfig};

#[test]
fn test_default_config() {
    let config = AppConfig::default();
    assert!(config.general.auto_start);
    assert!(!config.general.minimize_to_tray);
    assert!(config.general.check_updates);
}

#[test]
fn test_config_serialization() {
    let config = AppConfig::default();
    let toml = toml::to_string_pretty(&config).unwrap();
    let deserialized: AppConfig = toml::from_str(&toml).unwrap();

    assert_eq!(config.general.auto_start, deserialized.general.auto_start);
}
```

- [ ] **Step 2: Implement config**

```rust
// internal/core/config.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub modules: HashMap<String, ModuleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub auto_start: bool,
    pub minimize_to_tray: bool,
    pub check_updates: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut modules = HashMap::new();
        modules.insert("vpn".to_string(), ModuleConfig::default());
        modules.insert("killswitch".to_string(), ModuleConfig::default());
        modules.insert("arp_detector".to_string(), ModuleConfig::default());

        Self {
            general: GeneralConfig {
                auto_start: true,
                minimize_to_tray: false,
                check_updates: true,
            },
            modules,
        }
    }
}

impl AppConfig {
    pub fn load(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| e.to_string())?;
        toml::from_str(&content)
            .map_err(|e| e.to_string())
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| e.to_string())?;
        std::fs::write(path, content)
            .map_err(|e| e.to_string())
    }
}
```

- [ ] **Step 3: Update main.rs**

```rust
// src/main.rs

use app_security::core::config::AppConfig;
use app_security::core::manager::ModuleManager;
use app_security::core::event_bus::EventBus;

#[tokio::main]
async fn main() {
    env_logger::init();
    log::info!("app-security starting...");

    let config = AppConfig::default();
    let event_bus = EventBus::new(1000);
    let mut manager = ModuleManager::new(event_bus);

    // Register modules
    // ... (would register VPN, KillSwitch, ARP detector)

    // Start modules
    if let Err(e) = manager.start_all().await {
        log::error!("Failed to start modules: {}", e);
    }

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
    log::info!("Shutting down...");

    if let Err(e) = manager.stop_all().await {
        log::error!("Failed to stop modules: {}", e);
    }
}
```

- [ ] **Step 4: Run config tests**

Run: `cargo test --test config_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: configuration management and entry point"
```

---

## Task 9: Final Integration & Documentation

**Files:**
- Create: `README.md`
- Create: `.gitignore`
- Create: `Makefile`

**Interfaces:**
- Consumes: All tasks
- Produces: Complete project with documentation

- [ ] **Step 1: Create .gitignore**

```gitignore
/target
Cargo.lock
*.swp
*.swo
*~
.DS_Store
```

- [ ] **Step 2: Create Makefile**

```makefile
.PHONY: build test run clean

build:
	cargo build

test:
	cargo test

run:
	cargo run

clean:
	cargo clean

test-verbose:
	cargo test -- --nocapture
```

- [ ] **Step 3: Create README.md**

```markdown
# App Security

Desktop security application for protecting users on public WiFi/LAN networks.

## Features (MVP)

- VPN auto-connect with WireGuard
- Kill Switch (blocks traffic if VPN drops)
- ARP Spoof Detection
- DNS-over-HTTPS
- Firewall Hardening
- Alert System
- MAC Randomization
- DNS Leak Prevention

## Requirements

- Rust 1.75+
- Root/admin privileges for network operations
- pcap library (for packet capture)

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run
cargo run
```

## Architecture

See `docs/superpowers/specs/2026-06-19-app-security-design.md`

## License

MIT
```

- [ ] **Step 4: Run full test suite**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 5: Build release**

Run: `cargo build --release`
Expected: Binary created at `target/release/app-security`

- [ ] **Step 6: Final commit**

```bash
git add -A
git commit -m "feat: Phase 1 complete - core foundation with VPN, KillSwitch, ARP detection"
```

---

## Summary

| Task | Description | Files Created |
|------|-------------|---------------|
| 1 | Project Setup & Core Traits | 5 |
| 2 | Event Bus & Module Manager | 4 |
| 3 | Platform Abstraction Layer | 7 |
| 4 | VPN Module | 4 |
| 5 | Kill Switch Module | 4 |
| 6 | ARP Detection Module | 3 |
| 7 | Integration Tests | 2 |
| 8 | Configuration & Entry Point | 3 |
| 9 | Final Integration & Documentation | 3 |

**Total:** 35 files created/modified

**Estimated time:** 4-6 hours for experienced developer

**Next phases:**
- Phase 2: DNS (DoH + Leak Prevention), Firewall, Alert System
- Phase 3: MAC Randomization, Hostname Spoofing, Tauri UI
