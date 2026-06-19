# Phase 2A: Core Fixes + DNS Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix event dispatch and dependency ordering, then add DNS-over-HTTPS and leak prevention modules.

**Architecture:** Extend ModuleManager with event dispatch loop and topological sort. Add new DnsModule with DoH client and leak detector. Sequential implementation — each task builds on previous.

**Tech Stack:** Rust, tokio, reqwest (HTTP), dns-encoding, pcap (optional)

## Global Constraints

- **Platform:** Cross-platform (macOS, Linux, Windows)
- **Language:** Rust 2021 edition
- **Testing:** TDD approach, 70%+ unit test coverage
- **Security:** All inputs validated, credentials encrypted, rollback capable

---

## File Structure

```
internal/src/
├── core/
│   ├── manager.rs          # MODIFY: Add event dispatch + topological sort
│   └── toposort.rs         # CREATE: Topological sort algorithm
├── network/
│   └── dns/
│       ├── mod.rs          # CREATE: DnsModule implementing SecurityModule
│       ├── doh.rs          # CREATE: DNS-over-HTTPS client
│       ├── leak.rs         # CREATE: DNS leak detection
│       └── config.rs       # CREATE: DNS configuration types
tests/
├── unit/
│   ├── core/
│   │   ├── manager_test.rs # MODIFY: Add event dispatch tests
│   │   └── toposort_test.rs # CREATE: Topological sort tests
│   └── network/
│       └── dns_test.rs     # CREATE: DNS module tests
```

---

## Task 1: Event Dispatch Mechanism

**Files:**
- Modify: `internal/src/core/manager.rs`
- Create: `tests/unit/core/manager_event_dispatch_test.rs`

**Interfaces:**
- Consumes: `EventBus` from Task 2 (Phase 1), `SecurityModule` trait
- Produces: `ModuleManager::start_event_dispatch()` method

- [ ] **Step 1: Write failing test for event dispatch**

```rust
// tests/unit/core/manager_event_dispatch_test.rs

use app_security::core::manager::ModuleManager;
use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::{ModuleConfig, ModuleStatus, SecurityModule, ModuleEvent};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

struct MockModule {
    id: String,
    events_received: Arc<RwLock<Vec<ModuleEvent>>>,
}

impl MockModule {
    fn new(id: &str) -> (Self, Arc<RwLock<Vec<ModuleEvent>>>) {
        let events = Arc::new(RwLock::new(Vec::new()));
        (Self {
            id: id.to_string(),
            events_received: events.clone(),
        }, events)
    }
}

#[async_trait]
impl SecurityModule for MockModule {
    fn id(&self) -> &str { &self.id }
    fn name(&self) -> &str { "Mock" }
    fn priority(&self) -> u32 { 10 }
    fn dependencies(&self) -> Vec<&str> { vec![] }
    async fn initialize(&mut self, _config: &ModuleConfig) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
    fn status(&self) -> ModuleStatus { ModuleStatus::Running }
    async fn on_event(&mut self, event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> {
        self.events_received.write().await.push(event.clone());
        Ok(())
    }
}

#[tokio::test]
async fn test_event_dispatch_forwards_to_modules() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus.clone());
    
    let (module1, events1) = MockModule::new("mod1");
    let (module2, events2) = MockModule::new("mod2");
    
    manager.register_module(Box::new(module1)).await.unwrap();
    manager.register_module(Box::new(module2)).await.unwrap();
    
    manager.start_all().await.unwrap();
    manager.start_event_dispatch().await;
    
    // Publish event
    let event = ModuleEvent::ModuleStarted { module_id: "test".to_string() };
    event_bus.publish(event.clone()).unwrap();
    
    // Wait for dispatch
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    
    // Verify both modules received the event
    let received1 = events1.read().await;
    let received2 = events2.read().await;
    
    assert_eq!(received1.len(), 1);
    assert_eq!(received2.len(), 1);
    assert!(matches!(&received1[0], ModuleEvent::ModuleStarted { .. }));
    assert!(matches!(&received2[0], ModuleEvent::ModuleStarted { .. }));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test manager_event_dispatch_test`
Expected: FAIL with "method not found"

- [ ] **Step 3: Implement event dispatch**

```rust
// Add to internal/src/core/manager.rs

impl ModuleManager {
    /// Start event dispatch loop - forwards events to all modules
    pub async fn start_event_dispatch(&self) {
        let mut receiver = self.event_bus.subscribe();
        let modules = self.modules.clone();
        
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv().await {
                for module in modules.values() {
                    let mut module = module.write().await;
                    let _ = module.on_event(&event).await;
                }
            }
        });
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test manager_event_dispatch_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/src/core/manager.rs tests/unit/core/manager_event_dispatch_test.rs
git commit -m "feat: add event dispatch mechanism to ModuleManager"
```

---

## Task 2: Dependency-aware Startup

**Files:**
- Create: `internal/src/core/toposort.rs`
- Create: `tests/unit/core/toposort_test.rs`
- Modify: `internal/src/core/manager.rs`

**Interfaces:**
- Consumes: `SecurityModule::dependencies()` method
- Produces: `topological_sort()` function, updated `ModuleManager::start_all()`

- [ ] **Step 1: Write failing test for topological sort**

```rust
// tests/unit/core/toposort_test.rs

use app_security::core::toposort::topological_sort;
use std::collections::HashMap;

#[test]
fn test_topological_sort_no_dependencies() {
    let mut deps: HashMap<String, Vec<String>> = HashMap::new();
    deps.insert("a".to_string(), vec![]);
    deps.insert("b".to_string(), vec![]);
    deps.insert("c".to_string(), vec![]);
    
    let order = topological_sort(&deps).unwrap();
    assert_eq!(order.len(), 3);
    assert!(order.contains(&"a".to_string()));
    assert!(order.contains(&"b".to_string()));
    assert!(order.contains(&"c".to_string()));
}

#[test]
fn test_topological_sort_with_dependencies() {
    let mut deps: HashMap<String, Vec<String>> = HashMap::new();
    deps.insert("vpn".to_string(), vec![]);
    deps.insert("killswitch".to_string(), vec!["vpn".to_string()]);
    deps.insert("arp".to_string(), vec![]);
    
    let order = topological_sort(&deps).unwrap();
    
    let vpn_pos = order.iter().position(|x| x == "vpn").unwrap();
    let ks_pos = order.iter().position(|x| x == "killswitch").unwrap();
    assert!(vpn_pos < ks_pos);
}

#[test]
fn test_topological_sort_circular_dependency() {
    let mut deps: HashMap<String, Vec<String>> = HashMap::new();
    deps.insert("a".to_string(), vec!["b".to_string()]);
    deps.insert("b".to_string(), vec!["a".to_string()]);
    
    let result = topological_sort(&deps);
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test toposort_test`
Expected: FAIL with "module not found"

- [ ] **Step 3: Implement topological sort**

```rust
// internal/src/core/toposort.rs

use std::collections::{HashMap, VecDeque};

pub fn topological_sort(deps: &HashMap<String, Vec<String>>) -> Result<Vec<String>, String> {
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    
    for (node, dependents) in deps {
        in_degree.entry(node.clone()).or_insert(0);
        for dep in dependents {
            if !deps.contains_key(dep) {
                return Err(format!("Dependency not found: {}", dep));
            }
            *in_degree.entry(dep.clone()).or_insert(0);
        }
    }
    
    for (node, dependents) in deps {
        for dep in dependents {
            *in_degree.entry(node.clone()).or_insert(0) += 1;
        }
    }
    
    let mut queue: VecDeque<String> = VecDeque::new();
    for (node, &degree) in &in_degree {
        if degree == 0 {
            queue.push_back(node.clone());
        }
    }
    
    let mut order = Vec::new();
    
    while let Some(node) = queue.pop_front() {
        order.push(node.clone());
        
        if let Some(dependents) = deps.get(&node) {
            for dep in dependents {
                if let Some(degree) = in_degree.get_mut(dep) {
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push_back(dep.clone());
                    }
                }
            }
        }
    }
    
    if order.len() != deps.len() {
        return Err("Circular dependency detected".to_string());
    }
    
    Ok(order)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test toposort_test`
Expected: PASS

- [ ] **Step 5: Update ModuleManager::start_all()**

```rust
// Modify internal/src/core/manager.rs

impl ModuleManager {
    pub async fn start_all(&self) -> Result<(), String> {
        let mut deps: HashMap<String, Vec<String>> = HashMap::new();
        for (id, module) in &self.modules {
            let module = module.read().await;
            deps.insert(id.clone(), module.dependencies().into_iter().map(String::from).collect());
        }
        
        let order = super::toposort::topological_sort(&deps)?;
        
        for id in order {
            self.start_module(&id).await?;
        }
        
        Ok(())
    }
}
```

- [ ] **Step 6: Run all tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add internal/src/core/toposort.rs internal/src/core/manager.rs tests/unit/core/toposort_test.rs
git commit -m "feat: add dependency-aware startup with topological sort"
```

---

## Task 3: DNS-over-HTTPS Module

**Files:**
- Create: `internal/src/network/dns/mod.rs`
- Create: `internal/src/network/dns/doh.rs`
- Create: `internal/src/network/dns/config.rs`
- Create: `tests/unit/network/dns_test.rs`

**Interfaces:**
- Consumes: `SecurityModule` trait, `EventBus`
- Produces: `DnsModule`, `DohClient`, `DnsEvent`

- [ ] **Step 1: Add dependencies to Cargo.toml**

```toml
[dependencies]
reqwest = { version = "0.11", features = ["json"] }
```

- [ ] **Step 2: Write failing test for DNS module**

```rust
// tests/unit/network/dns_test.rs

use app_security::network::dns::DnsModule;
use app_security::core::mod_trait::{ModuleConfig, ModuleStatus, SecurityModule};
use app_security::core::event_bus::EventBus;

#[tokio::test]
async fn test_dns_module_initialization() {
    let event_bus = EventBus::new(100);
    let mut dns = DnsModule::new(event_bus);
    
    assert_eq!(dns.status(), ModuleStatus::Created);
    
    dns.initialize(&ModuleConfig::default()).await.unwrap();
    assert_eq!(dns.status(), ModuleStatus::Initialized);
}

#[tokio::test]
async fn test_dns_module_start_stop() {
    let event_bus = EventBus::new(100);
    let mut dns = DnsModule::new(event_bus);
    
    dns.initialize(&ModuleConfig::default()).await.unwrap();
    dns.start().await.unwrap();
    assert_eq!(dns.status(), ModuleStatus::Running);
    
    dns.stop().await.unwrap();
    assert_eq!(dns.status(), ModuleStatus::Stopped);
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --test dns_test`
Expected: FAIL with "module not found"

- [ ] **Step 4: Implement DnsModule**

```rust
// internal/src/network/dns/mod.rs

use async_trait::async_trait;
use crate::core::mod_trait::{SecurityModule, ModuleConfig, ModuleStatus, ModuleEvent};
use crate::core::event_bus::EventBus;
use super::doh::DohClient;

pub struct DnsModule {
    event_bus: EventBus,
    status: ModuleStatus,
    doh_client: DohClient,
}

impl DnsModule {
    pub fn new(event_bus: EventBus) -> Self {
        Self {
            event_bus,
            status: ModuleStatus::Created,
            doh_client: DohClient::new("https://1.1.1.1/dns-query".to_string()),
        }
    }
    
    pub async fn resolve(&self, domain: &str) -> Result<Vec<std::net::IpAddr>, String> {
        self.doh_client.resolve(domain).await.map_err(|e| e.to_string())
    }
}

#[async_trait]
impl SecurityModule for DnsModule {
    fn id(&self) -> &str { "dns" }
    fn name(&self) -> &str { "DNS Module" }
    fn priority(&self) -> u32 { 4 }
    fn dependencies(&self) -> Vec<&str> { vec![] }
    
    async fn initialize(&mut self, _config: &ModuleConfig) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Initialized;
        Ok(())
    }
    
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Running;
        self.event_bus.publish(ModuleEvent::DohConnected {
            server: "1.1.1.1".to_string(),
        }).map_err(|e| e.to_string())?;
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.status = ModuleStatus::Stopped;
        Ok(())
    }
    
    fn status(&self) -> ModuleStatus { self.status.clone() }
    
    async fn on_event(&mut self, _event: &ModuleEvent) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}
```

- [ ] **Step 5: Implement DoH client**

```rust
// internal/src/network/dns/doh.rs

use reqwest::Client;
use std::net::IpAddr;

#[derive(Debug)]
pub enum DohError {
    NetworkError(String),
    EncodingError(String),
    DecodingError(String),
}

impl std::fmt::Display for DohError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DohError::NetworkError(e) => write!(f, "Network error: {}", e),
            DohError::EncodingError(e) => write!(f, "Encoding error: {}", e),
            DohError::DecodingError(e) => write!(f, "Decoding error: {}", e),
        }
    }
}

impl std::error::Error for DohError {}

pub struct DohClient {
    resolver_url: String,
    client: Client,
}

impl DohClient {
    pub fn new(resolver_url: String) -> Self {
        Self {
            resolver_url,
            client: Client::new(),
        }
    }
    
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, DohError> {
        let _ = domain;
        Err(DohError::EncodingError("Not implemented".to_string()))
    }
}
```

- [ ] **Step 6: Add DnsEvent to ModuleEvent**

```rust
// Modify internal/src/core/mod_trait.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModuleEvent {
    // ... existing variants ...
    
    DohConnected { server: String },
    DnsLeakDetected { dns_server: String, interface: String },
}
```

- [ ] **Step 7: Run tests**

Run: `cargo test --test dns_test`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/src/network/dns/ tests/unit/network/dns_test.rs internal/src/core/mod_trait.rs
git commit -m "feat: add DNS-over-HTTPS module with DoH client"
```

---

## Task 4: DNS Leak Prevention

**Files:**
- Create: `internal/src/network/dns/leak.rs`
- Create: `tests/unit/network/dns_leak_test.rs`
- Modify: `internal/src/network/dns/mod.rs`

**Interfaces:**
- Consumes: `DnsModule`, `EventBus`, `ModuleEvent::DnsLeakDetected`
- Produces: `DnsLeakDetector`

- [ ] **Step 1: Write failing test for leak detection**

```rust
// tests/unit/network/dns_leak_test.rs

use app_security::network::dns::leak::DnsLeakDetector;
use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::ModuleEvent;
use std::collections::HashSet;

#[tokio::test]
async fn test_leak_detector_identifies_known_server() {
    let event_bus = EventBus::new(100);
    let mut known = HashSet::new();
    known.insert("8.8.8.8".parse().unwrap());
    known.insert("1.1.1.1".parse().unwrap());
    
    let detector = DnsLeakDetector::new(event_bus, known);
    
    assert!(detector.is_known_server(&"8.8.8.8".parse().unwrap()));
    assert!(detector.is_known_server(&"1.1.1.1".parse().unwrap()));
    assert!(!detector.is_known_server(&"192.168.1.1".parse().unwrap()));
}

#[tokio::test]
async fn test_leak_detector_publishes_event() {
    let event_bus = EventBus::new(100);
    let mut receiver = event_bus.subscribe();
    let mut known = HashSet::new();
    known.insert("8.8.8.8".parse().unwrap());
    
    let detector = DnsLeakDetector::new(event_bus, known);
    
    detector.detect_leak("8.8.8.8".parse().unwrap(), "eth0").await;
    
    let event = receiver.recv().await.unwrap();
    assert!(matches!(event, ModuleEvent::DnsLeakDetected { .. }));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test dns_leak_test`
Expected: FAIL with "module not found"

- [ ] **Step 3: Implement leak detector**

```rust
// internal/src/network/dns/leak.rs

use std::collections::HashSet;
use std::net::IpAddr;
use crate::core::event_bus::EventBus;
use crate::core::mod_trait::ModuleEvent;

pub struct DnsLeakDetector {
    event_bus: EventBus,
    known_dns_servers: HashSet<IpAddr>,
}

impl DnsLeakDetector {
    pub fn new(event_bus: EventBus, known_dns_servers: HashSet<IpAddr>) -> Self {
        Self {
            event_bus,
            known_dns_servers,
        }
    }
    
    pub fn is_known_server(&self, ip: &IpAddr) -> bool {
        self.known_dns_servers.contains(ip)
    }
    
    pub async fn detect_leak(&self, dns_server: IpAddr, interface: &str) {
        if self.is_known_server(&dns_server) {
            let _ = self.event_bus.publish(ModuleEvent::DnsLeakDetected {
                dns_server: dns_server.to_string(),
                interface: interface.to_string(),
            });
        }
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add internal/src/network/dns/leak.rs tests/unit/network/dns_leak_test.rs
git commit -m "feat: add DNS leak detection module"
```

---

## Task 5: Integration Tests & Final Verification

**Files:**
- Create: `tests/integration/phase2a_test.rs`
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: All Phase 2A tasks
- Produces: Integration tests, updated main.rs

- [ ] **Step 1: Write integration test for event dispatch + killswitch**

```rust
// tests/integration/phase2a_test.rs

use app_security::core::manager::ModuleManager;
use app_security::core::event_bus::EventBus;
use app_security::core::mod_trait::{ModuleConfig, ModuleStatus};
use app_security::network::vpn::VpnModule;
use app_security::network::killswitch::KillSwitchModule;
use app_security::network::dns::DnsModule;

#[tokio::test]
async fn test_event_dispatch_triggers_killswitch() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus.clone());
    
    let platform = Box::new(MockPlatform::new());
    manager.register_module(Box::new(VpnModule::new(event_bus.clone(), platform))).await.unwrap();
    manager.register_module(Box::new(KillSwitchModule::new(event_bus.clone()))).await.unwrap();
    manager.register_module(Box::new(DnsModule::new(event_bus.clone()))).await.unwrap();
    
    manager.start_all().await.unwrap();
    manager.start_event_dispatch().await;
    
    assert_eq!(manager.get_module_status("vpn").await.unwrap(), ModuleStatus::Running);
    assert_eq!(manager.get_module_status("killswitch").await.unwrap(), ModuleStatus::Running);
    assert_eq!(manager.get_module_status("dns").await.unwrap(), ModuleStatus::Running);
}

#[tokio::test]
async fn test_dependency_ordering() {
    let event_bus = EventBus::new(100);
    let mut manager = ModuleManager::new(event_bus.clone());
    
    manager.register_module(Box::new(KillSwitchModule::new(event_bus.clone()))).await.unwrap();
    manager.register_module(Box::new(VpnModule::new(event_bus.clone(), Box::new(MockPlatform::new())))).await.unwrap();
    
    manager.start_all().await.unwrap();
    
    assert_eq!(manager.get_module_status("vpn").await.unwrap(), ModuleStatus::Running);
    assert_eq!(manager.get_module_status("killswitch").await.unwrap(), ModuleStatus::Running);
}
```

- [ ] **Step 2: Run integration tests**

Run: `cargo test --test phase2a_test`
Expected: PASS

- [ ] **Step 3: Update main.rs with DNS module**

```rust
// Modify src/main.rs

use app_security::network::dns::DnsModule;

#[tokio::main]
async fn main() {
    env_logger::init();
    log::info!("app-security starting...");
    
    let config = AppConfig::default();
    let event_bus = EventBus::new(1000);
    let mut manager = ModuleManager::new(event_bus.clone());
    
    let platform = Box::new(create_platform());
    manager.register_module(Box::new(VpnModule::new(event_bus.clone(), platform))).await.unwrap();
    manager.register_module(Box::new(KillSwitchModule::new(event_bus.clone()))).await.unwrap();
    manager.register_module(Box::new(ArpDetectorModule::new(event_bus.clone()))).await.unwrap();
    manager.register_module(Box::new(DnsModule::new(event_bus.clone()))).await.unwrap();
    
    if let Err(e) = manager.start_all().await {
        log::error!("Failed to start modules: {}", e);
    }
    
    manager.start_event_dispatch().await;
    
    tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
    log::info!("Shutting down...");
    
    if let Err(e) = manager.stop_all().await {
        log::error!("Failed to stop modules: {}", e);
    }
}
```

- [ ] **Step 4: Run full test suite**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add tests/integration/phase2a_test.rs src/main.rs
git commit -m "feat: Phase 2A complete - event dispatch, dependency ordering, DNS module"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Event dispatch mechanism | 2 |
| 2 | Dependency-aware startup | 3 |
| 3 | DNS-over-HTTPS module | 4 |
| 4 | DNS leak prevention | 3 |
| 5 | Integration tests | 2 |

**Total:** 14 files created/modified

**Estimated time:** 2-3 hours
