# 5W1H Analysis: Public WiFi/LAN Security App

> Phân loại: **Hệ thống** (ứng dụng mới, đa module, cần kiến trúc)

---

## What — Cần làm gì?

**Deliverable**: Ứng dụng desktop bảo vệ người dùng khỏi các mối đe dọa mạng khi sử dụng WiFi/LAN công cộng, đồng thời ẩn danh hóa thông tin thiết bị.

**Scope cụ thể**:
- 8 tính năng bảo vệ mạng (VPN, kill switch, evil twin detection, ARP detection, DoH/DoT, trust scoring, firewall, alerts)
- 6 tính năng ẩn danh hóa (MAC random, hostname spoof, traffic obfuscation, multi-hop, fingerprint mask, DNS leak prevention)

**Không bao gồm (out of scope)**:
- Bảo vệ vật lý (USB, camera)
- Endpoint protection (antivirus, EDR)
- Bảo vệ application layer (sandboxing)

**❓ Câu hỏi cần làm rõ**:
- MVP gồm bao nhiêu tính năng? (đề xuất: 5-6 tính năng ưu tiên cao)
- App chạy background daemon hay chỉ khi user bật?

---

## Why — Tại sao?

**Business reason**:
- Người làm việc remote/hybrid ngày càng nhiều → nhu cầu bảo mật WiFi công cộng tăng
- Các giải pháp hiện tại (NordVPN, GlassWire) không tập trung vào detection + anonymization cùng lúc
- Niche: kết hợp **phòng thủ chủ động** (detect attack) + **ẩn danh** (hide identity) trong 1 app

**Giá trị cho người dùng**:
- Yên tâm làm việc ở bất kỳ đâu mà không lo bị nghe lén, tracking
- Không cần kiến thức bảo mật — app tự xử lý

**❓ Câu hỏi cần làm rõ**:
- Đây là sản phẩm thương mại hay open-source/cá nhân?
- Có kế hoạch monetization không? (ảnh hưởng đến quyết định VPN server)

---

## Who — Ai liên quan?

**Người dùng (End users)**:
- Freelancer, developer, nhân viên remote làm việc tại coworking/café
- Kỹ năng IT trung bình — cần UX đơn giản, tự động

**Hệ thống tương tác**:
- OS network stack (firewall, routing table, network interfaces)
- DHCP server (nhận IP, lộ hostname)
- Access Point/Router (nhận MAC, traffic)
- DNS resolver (upstream DNS server)
- VPN server (nếu self-host)

**Bị ảnh hưởng**:
- Network admin (có thể thấy MAC/hostname giả — hợp pháp nhưng cần lưu ý)
- ISP (không thấy traffic nếu VPN hoạt động)

**❓ Câu hỏi cần làm rõ**:
- App cần hoạt động khi user không có quyền admin? (hạn chế nhiều tính năng)
- Target persona chính: tech-savvy hay non-tech?

---

## When — Thứ tự & Dependency?

### Dependency graph

```
Phase 1 (Foundation)          Phase 2 (Core)              Phase 3 (Advanced)
─────────────────────         ──────────────              ──────────────────
├─ Project setup              ├─ VPN auto-connect [1]     ├─ Evil Twin detect [3]
├─ Network monitoring core    ├─ Kill switch [2]          ├─ Traffic obfuscation [11]
├─ OS permission handling     ├─ MAC randomization [9]    ├─ Multi-hop proxy [12]
└─ UI shell (system tray)     ├─ Firewall hardening [7]   ├─ Fingerprint masking [13]
                              ├─ DNS-over-HTTPS [5]       └─ Network trust scoring [6]
                              ├─ DNS leak prevention [14]
                              ├─ ARP spoof detection [4]
                              ├─ Hostname spoofing [10]
                              └─ Alert system [8]
```

### Prerequisite

| Tính năng | Phụ thuộc vào |
|-----------|---------------|
| Kill switch [2] | VPN module [1] phải có trước |
| DNS leak prevention [14] | VPN [1] + DoH [5] phải có trước |
| Alert system [8] | Detection modules [3,4] phải có trước |
| Trust scoring [6] | Cần data từ detection modules |

### Đề xuất MVP (Phase 1 + Phase 2 core)

**MVP = 8 tính năng**: #1, #2, #4, #5, #7, #8, #9, #14

Lý do: Cover đủ mối đe dọa phổ biến nhất, có cả bảo vệ lẫn ẩn danh cơ bản.

---

## Where — Ở đâu trong kiến trúc?

### Module layout

```
app-security/
├── cmd/                    # Entry points
│   └── app-security/      # Main binary
├── internal/
│   ├── core/              # Core engine, lifecycle management
│   ├── network/
│   │   ├── vpn/           # [1,2] VPN + Kill switch
│   │   ├── firewall/      # [7] Firewall rules
│   │   └── dns/           # [5,14] DoH/DoT + leak prevention
│   ├── detection/
│   │   ├── arp/           # [4] ARP spoof detection
│   │   ├── eviltwin/      # [3] Evil Twin detection
│   │   └── scoring/       # [6] Network trust scoring
│   ├── anonymity/
│   │   ├── mac/           # [9] MAC randomization
│   │   ├── hostname/      # [10] Hostname spoofing
│   │   ├── traffic/       # [11] Traffic padding
│   │   ├── proxy/         # [12] Multi-hop
│   │   └── fingerprint/   # [13] TLS/HTTP fingerprint
│   ├── alert/             # [8] Alert system
│   └── ui/                # System tray, dashboard
├── configs/               # Default configs
└── docs/                  # Documentation
```

### Layer mapping

| Layer | Modules | Quyền cần |
|-------|---------|-----------|
| Kernel/Driver | MAC spoof, packet capture, firewall | root/admin |
| Network stack | VPN tunnel, DNS resolver, routing | root/admin |
| Application | UI, alert, scoring, config | user |

---

## How — Cách implement?

### Lựa chọn A: Go + WireGuard + Tauri UI

| Aspect | Chi tiết |
|--------|----------|
| Core engine | Go — concurrency tốt, gopacket cho packet capture, wireguard-go |
| Packet capture | gopacket (wrapper libpcap) |
| VPN | wireguard-go (embedded, không cần cài riêng) |
| DNS | dnscrypt-proxy hoặc custom DoH client |
| UI | Tauri (Rust + Web frontend) — nhẹ, cross-platform |
| MAC/hostname | OS-specific syscalls |

**Ưu điểm**: Ecosystem Go mạnh cho networking, WireGuard nhẹ & nhanh, single binary dễ distribute.
**Nhược điểm**: Tauri + Go = 2 runtime (Rust + Go), phức tạp build pipeline.

### Lựa chọn B: Rust thuần + iced/egui UI

| Aspect | Chi tiết |
|--------|----------|
| Core engine | Rust — memory safe, system-level, performance |
| Packet capture | pnet hoặc pcap crate |
| VPN | boringtun (WireGuard in Rust) |
| DNS | trust-dns / hickory-dns |
| UI | iced hoặc egui (native Rust GUI) |
| MAC/hostname | nix crate (Unix) / windows-rs |

**Ưu điểm**: Single language, no GC, maximum performance, memory safety tuyệt đối.
**Nhược điểm**: Rust learning curve cao, GUI ecosystem chưa mature bằng.

### Lựa chọn C: Go core + Electron UI

| Aspect | Chi tiết |
|--------|----------|
| Core engine | Go (giống A) |
| UI | Electron — rich UI, nhiều library |

**Ưu điểm**: UI đẹp nhất, dev speed nhanh cho frontend.
**Nhược điểm**: Electron nặng (~150MB RAM), không phù hợp với app security (bề mặt tấn công lớn).

### Đề xuất: **Lựa chọn A (Go + WireGuard + Tauri)**

Lý do: Cân bằng giữa dev speed, performance, cross-platform. Go có ecosystem networking tốt nhất. Tauri nhẹ hơn Electron nhiều lần.

**❓ Câu hỏi cần làm rõ**:
- Bạn familiar với Go hay Rust hơn?
- Ưu tiên dev speed hay maximum performance?

---

## Constraints — Ràng buộc

| Ràng buộc | Chi tiết |
|-----------|----------|
| **Platform** | ❓ Chưa xác định — cần user confirm |
| **Privileges** | BẮT BUỘC cần root/admin cho hầu hết tính năng core |
| **Performance** | App phải lightweight, không gây lag network (< 5% overhead) |
| **Privacy** | App KHÔNG ĐƯỢC thu thập/gửi dữ liệu user ra ngoài |
| **Legality** | MAC spoofing hợp pháp ở hầu hết quốc gia, nhưng cần disclaimer |
| **VPN server** | Nếu self-host: cần infra. Nếu dùng provider: phụ thuộc bên thứ 3 |
| **Backward compat** | N/A (dự án mới) |

---

## Risk & Rollback

| # | Rủi ro | Impact | Mitigation |
|---|--------|--------|------------|
| 1 | OS update break network API | Cao | Abstract OS layer, CI test trên nhiều OS version |
| 2 | VPN server bị block/down | Cao | Multi-server, fallback mechanism |
| 3 | False positive detection (báo nhầm) | Trung bình | Tuning threshold, user whitelist |
| 4 | App conflict với VPN khác đã cài | Trung bình | Detect & warn, không force override |
| 5 | Legal issue với MAC spoofing ở 1 số nước | Thấp | Disclaimer, user opt-in |
| 6 | Performance overhead cao | Trung bình | Benchmark từng module, lazy loading |
| 7 | Packet capture bị antivirus block | Trung bình | Sign binary, whitelist guide |

**Rollback strategy**:
- Mỗi module hoạt động độc lập → disable từng module không ảnh hưởng app
- Network changes (firewall, MAC, hostname) phải lưu state cũ → revert khi tắt app
- Kill switch phải có failsafe: nếu app crash → restore network bình thường

---

## Tổng kết — Cần user confirm

| # | Câu hỏi | Ảnh hưởng đến |
|---|---------|---------------|
| 1 | Target platform? (Windows/macOS/Linux/all) | Tech stack, build system, testing |
| 2 | Go hay Rust? (hoặc ngôn ngữ khác?) | Toàn bộ implementation |
| 3 | Sản phẩm thương mại hay open-source? | Monetization, VPN server strategy |
| 4 | VPN server self-host hay dùng provider? | Infra cost, privacy guarantee |
| 5 | MVP bắt đầu với bao nhiêu tính năng? | Timeline phase 1 |
| 6 | App chạy daemon background hay on-demand? | Architecture, resource usage |
| 7 | Ưu tiên dev speed hay maximum security? | Quyết định nhiều tradeoff |
