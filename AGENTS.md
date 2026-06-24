# AGENTS.md — NetSentinel Project Intelligence

> This document is the canonical reference for any AI agent or human developer working on NetSentinel. It describes the project structure, architecture, data flow, conventions, and the multi-agent orchestration system.

---

## 1. Project Overview

**NetSentinel** is a cross-platform desktop application for network discovery, security auditing, and infrastructure monitoring. Built for Blue Team, Purple Team, and SOC analysts.

- **Language**: 100% Rust (backend + frontend, single binary)
- **GUI Framework**: [Iced 0.13](https://github.com/iced-rs/iced) (Elm Architecture, GPU-accelerated)
- **Async Runtime**: Tokio (full features)
- **Networking**: pnet (raw packets), socket2, tokio networking
- **Storage**: SQLite via rusqlite (baselines), JSON files (settings, history)
- **IPC**: gRPC via tonic + prost (Unix Domain Socket server for inter-tool communication)
- **Protocol**: Nexus Protocol (git submodule at `proto/`)
- **Build**: Cargo workspace with a build script (`build.rs`) for protobuf compilation and nmap probe parsing

---

## 2. Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| GUI | Iced 0.13 (features: `tokio`, `image`) | Native desktop UI with Elm Architecture |
| Backend Core | Rust + Tokio | Async network scanning engine |
| Raw Packets | pnet 0.35, pnet_packet 0.35 | ARP/ICMP/SYN scan packet crafting |
| Sockets | socket2 0.5 | Low-level socket operations |
| Database | rusqlite 0.31 (bundled) | Baseline snapshot persistence |
| Serialization | serde + serde_json | JSON for settings/history, bincode for probes |
| gRPC IPC | tonic 0.12 + prost 0.13 | Inter-tool communication via Unix sockets |
| TLS Analysis | tokio-native-tls, native-tls, x509-parser | Certificate inspection |
| HTTP Auditing | reqwest 0.13 (rustls) | Web security checks |
| Reporting | genpdf, printpdf, html-escape | PDF/HTML report generation |
| Logging | tracing + tracing-subscriber | Structured logging with env-filter |
| Error Handling | thiserror 2.0 | Custom `ScanError` enum |
| System Info | sysinfo 0.32 | Device/OS information |
| File Dialogs | rfd 0.14 | Native file save/open dialogs |
| Nmap Probes | nmap_parser (workspace crate) | Service probe detection database |

---

## 3. Directory Structure

```
NetSentinel/
├── AGENTS.md                    # THIS FILE — Project intelligence document
├── README.md                    # User-facing documentation
├── Cargo.toml                   # Workspace root + main package manifest
├── Cargo.lock                   # Dependency lockfile
├── build.rs                     # Build script: protobuf compilation + nmap probe parsing
├── dev-elevated.sh              # Shell script to run with root privileges (raw sockets)
├── LICENSE                      # MIT License
├── .gitmodules                  # Git submodule: proto/ -> nexus-protocol
│
├── assets/                      # Static assets bundled at compile time
│   ├── netSentinel-logo.png     # Application logo (displayed in header)
│   ├── cve-database.db          # SQLite CVE database for vulnerability matching
│   └── nmap-service-probes      # Nmap service fingerprint database (parsed by build.rs)
│
├── proto/                       # Git submodule: Nexus Protocol definitions
│   ├── nexus_ipc.proto          # gRPC service + message definitions for IPC
│   ├── README.md
│   └── LICENSE
│
├── tools/                       # Workspace member crates
│   └── nmap_parser/             # Custom crate: parses nmap-service-probes file
│       ├── Cargo.toml
│       └── src/
│
├── src/                         # Main application source
│   ├── main.rs                  # Entry point: spawns capture thread + launches Iced GUI
│   ├── lib.rs                   # Library root: re-exports all public modules
│   ├── error.rs                 # ScanError enum (project-wide error type)
│   ├── events.rs                # AppEvent + ScanEvent enums (backend -> UI event bridge)
│   ├── types.rs                 # Core data types: Device, Port, ScanType, etc.
│   ├── settings.rs              # Settings profiles (JSON persistence, async file I/O)
│   ├── history.rs               # Scan history (JSON persistence, capped at 100 entries)
│   ├── baseline.rs              # Baseline snapshots + diff computation (SQLite-backed)
│   ├── ipc.rs                   # gRPC IPC server (tonic, Unix Domain Socket)
│   │
│   ├── bin/
│   │   └── json_to_sqlite.rs    # Utility binary: JSON to SQLite migration tool
│   │
│   ├── state/                   # Shared mutable state management
│   │   ├── mod.rs               # Re-exports SharedScanState
│   │   └── scan_state.rs        # SharedScanState: atomic flags + tokio Mutex for scan data
│   │
│   ├── commands/                # Backend command functions (async, called by UI)
│   │   ├── mod.rs               # Re-exports + DeviceInfo/NetworkInfo structs
│   │   ├── scan.rs              # start_scan, stop_scan, pause_scan, resume_scan
│   │   ├── device.rs            # get_device_info (system info)
│   │   ├── network.rs           # get_network_info (IP, MAC, gateway)
│   │   ├── platform.rs          # get_platform_capabilities (OS-specific features)
│   │   ├── privilege.rs         # check_privilege_status (root/capability detection)
│   │   ├── settings.rs          # CRUD for settings profiles
│   │   ├── history.rs           # CRUD for scan history entries
│   │   ├── baseline.rs          # CRUD for baselines + comparison
│   │   └── export.rs            # CSV/JSON export of scan results
│   │
│   ├── network/                 # Core scanning engine modules
│   │   ├── mod.rs               # Module declarations (23 submodules)
│   │   ├── host_discovery.rs    # Orchestrates discovery methods
│   │   ├── cidr.rs              # CIDR notation parsing
│   │   ├── icmp.rs              # ICMP Echo Request implementation
│   │   ├── tcp_raw_scan.rs      # TCP SYN stealth scan (raw sockets)
│   │   ├── udp_scan.rs          # UDP port scan (ICMP unreachable)
│   │   ├── udp_raw_scan.rs      # Raw UDP scan implementation
│   │   ├── sctp_scan.rs         # SCTP INIT scan
│   │   ├── banner.rs            # Service banner grabbing (SSH, HTTP, SMTP, etc.)
│   │   ├── service_detection.rs # Nmap service probe matching
│   │   ├── tls.rs               # TLS/SSL certificate analysis
│   │   ├── cve.rs               # CVE database matching + update logic
│   │   ├── oui.rs               # MAC address OUI vendor lookup
│   │   ├── privileges.rs        # OS privilege/capability detection
│   │   ├── sanitize.rs          # Input sanitization utilities
│   │   ├── timing.rs            # Scan timing templates (T0-T5)
│   │   ├── active_checks.rs     # Active vulnerability checks
│   │   ├── web_audit.rs         # HTTP/HTTPS security auditing
│   │   ├── threats.rs           # Threat detection logic
│   │   ├── ipv6_discovery.rs    # IPv6 host discovery
│   │   ├── mdns_netbios.rs      # mDNS/NetBIOS name resolution
│   │   ├── capture.rs           # Background packet capture thread
│   │   ├── discovery/           # Host discovery methods
│   │   │   ├── mod.rs
│   │   │   ├── arp_sweep.rs     # Active ARP sweep (raw Ethernet, requires root)
│   │   │   ├── arp_table.rs     # Passive ARP table reading (no privileges)
│   │   │   └── tcp_probe.rs     # TCP connect probe discovery
│   │   └── platform/            # OS-specific network operations
│   │       ├── mod.rs
│   │       ├── linux.rs         # Linux: /proc/net/arp, /proc/net/route
│   │       ├── windows.rs       # Windows: arp -a, route print
│   │       └── macos.rs         # macOS: arp -a, route -n get default
│   │
│   ├── reporting/               # Report generation & compliance
│   │   ├── mod.rs
│   │   ├── export.rs            # HTML + PDF report generation
│   │   ├── scoring.rs           # CVSS scoring + EPSS integration
│   │   └── compliance.rs        # CIS, HIPAA, PCI DSS compliance checks
│   │
│   └── ui/                      # Iced GUI frontend
│       ├── mod.rs               # Application model, Message enum, update(), view(), subscription(), run()
│       ├── theme.rs             # Color palette + widget style functions (dark/light themes)
│       ├── views/               # Page-specific view rendering
│       │   ├── mod.rs
│       │   ├── dashboard.rs     # Dashboard: system info, network info, privilege status
│       │   ├── scan.rs          # Scan page: controls, device table, detail panel, logs
│       │   ├── settings.rs      # Settings: profile management, scan config, UI preferences
│       │   ├── history.rs       # History: past scans with expandable device details
│       │   └── baseline.rs      # Baseline: save/compare/delete network snapshots
│       └── widgets/             # Reusable UI components
│           └── mod.rs           # Shared widgets (privilege banner, etc.)
│
├── .agents/                     # AI agent skill definitions
│   └── skills/
│       ├── backend-standards/   # Backend coding standards skill
│       │   └── SKILL.md
│       └── frontend-standards/  # Frontend coding standards skill
│           └── SKILL.md
│
├── .opencode/                   # OpenCode agent configuration
│   ├── agents/
│   │   ├── netsentinel-general.md  # Chief Orchestrator agent definition
│   │   ├── planner.md              # Planner sub-agent (read-only, architecture)
│   │   ├── developer.md            # Developer sub-agent (implementation)
│   │   └── reviewer.md             # Reviewer sub-agent (read-only, audit)
│   ├── package.json
│   └── package-lock.json
│
└── target/                      # Cargo build output (gitignored)
```

---

## 4. Architecture Overview

### 4.1 High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         NetSentinel Binary                          │
│                                                                     │
│  ┌──────────────┐     ┌──────────────────┐     ┌────────────────┐  │
│  │   Iced GUI    │     │  Command Layer   │     │ Network Engine │  │
│  │  (ui/mod.rs)  │────>│ (commands/*.rs)  │────>│ (network/*.rs) │  │
│  │               │<────│                  │<────│                │  │
│  │  Model        │     │  Async functions │     │  Scanners      │  │
│  │  Message      │     │  operating on    │     │  Banner grab   │  │
│  │  update()     │     │  SharedScanState │     │  CVE matching  │  │
│  │  view()       │     │                  │     │  TLS analysis  │  │
│  │  subscription │     │                  │     │  OS fingerprint│  │
│  └──────┬───────┘     └────────┬─────────┘     └───────┬────────┘  │
│         │                      │                        │           │
│         │              ┌───────┴────────┐               │           │
│         │              │ Storage Layer  │               │           │
│         │              │ settings.rs    │               │           │
│         │              │ history.rs     │               │           │
│         │              │ baseline.rs    │               │           │
│         │              └────────────────┘               │           │
│         │                                               │           │
│  ┌──────┴───────────────────────────────────────────────┴────────┐  │
│  │              Event Bridge (channels)                          │  │
│  │  mpsc::UnboundedSender<AppEvent>  -->  Subscription stream    │  │
│  │  mpsc::Receiver<AppEvent> (IPC)   -->  Subscription stream    │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │              IPC Server (ipc.rs)                              │  │
│  │  gRPC over Unix Domain Socket (/tmp/nexus_central.sock)      │  │
│  │  Receives: HostDiscovered, SecurityAlert, CommandTrigger      │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 The Elm Architecture (Iced)

The UI follows the **Model-View-Update** pattern strictly:

| Component | Location | Responsibility |
|-----------|----------|----------------|
| **Model** | `ui/mod.rs` → `NetSentinelApp` struct | All application state |
| **Message** | `ui/mod.rs` → `Message` enum | All possible events (~70 variants) |
| **update()** | `ui/mod.rs` → `NetSentinelApp::update()` | State mutation + async `Task` dispatch |
| **view()** | `ui/mod.rs` → `NetSentinelApp::view()` | Pure rendering, delegates to `views/*.rs` |
| **subscription()** | `ui/mod.rs` → `NetSentinelApp::subscription()` | Streams backend events into Messages |

### 4.3 Page Navigation

The app has 5 pages controlled by the `Page` enum:

| Page | View Module | Description |
|------|-------------|-------------|
| `Dashboard` | `views/dashboard.rs` | System info, network info, privilege status, CVE alerts |
| `Scan` | `views/scan.rs` | Scan controls, device table, device detail panel, scan logs |
| `Settings` | `views/settings.rs` | Profile CRUD, scan config, UI preferences |
| `History` | `views/history.rs` | Past scan entries with expandable device details |
| `Baseline` | `views/baseline.rs` | Save/compare/delete network state snapshots |

### 4.4 Event Bridge System

Backend events flow to the UI through two channel-based subscriptions:

1. **Scanner Subscription** (`scan-events`): Active only during scans. Receives `AppEvent` variants from `mpsc::UnboundedReceiver<AppEvent>`. Batched at 200ms intervals.
2. **IPC Subscription** (`ipc-events`): Always running. Receives external tool events from `mpsc::Receiver<AppEvent>` via the gRPC server. Batched at 200ms intervals.

Both subscriptions use `tokio::select!` with a periodic tick to batch `DeviceFound` events into `DevicesDiscovered(Vec<Device>)` for efficiency.

### 4.5 Shared State Management

`SharedScanState` (in `state/scan_state.rs`) is the central mutable state for scan operations:

- **AtomicBool** (lock-free): `is_running`, `is_paused` — for fast flag checks
- **AtomicU32** (lock-free): `scanned_count`, `total_hosts` — for progress tracking
- **Arc<tokio::sync::Mutex<T>>** (async-safe): `devices` (HashMap), `cancel_tx`, `current_target` — for complex data

The state is wrapped in `Arc<SharedScanState>` and cloned into async tasks.

---

## 5. Key Data Types

### 5.1 Core Types (`types.rs`)

```rust
ScanType       — Connect | Syn | Fin | Xmas | Null | Udp | Sctp
DeviceStatus   — Online | Offline | Unknown
PortState      — Open | Closed | Filtered
Port           — { number: u16, protocol, service, state }
Device         — { ip, mac, hostname, vendor, os, status, ports, last_seen,
                   banner_results, active_checks, web_audits }
```

### 5.2 Error Type (`error.rs`)

```rust
ScanError — InvalidCidr | NetworkError | PermissionDenied | Cancelled |
            NotRunning | InvalidInput | InvalidPort | SettingsError |
            ProfileNotFound | IoError | HistoryError | Timeout |
            BaselineError | CveError | EventError
```

### 5.3 Event Types (`events.rs`)

```rust
AppEvent  — DeviceFound | ScanProgress | ScanComplete | ScanLog |
            BannerFound | CveAlert | PrivilegeStatus | IpcCommand | SecurityAlert

ScanEvent — DeviceFound | Progress(f32) | Log | BannerFound | CveAlert | Finished
```

### 5.4 Settings (`settings.rs`)

```rust
SettingsProfile — { id, name, is_default, scan_config, ui_preferences, created_at, updated_at }
ScanConfig      — { default_cidr, timeout_ms, max_concurrent_hosts, max_concurrent_ports,
                    scan_ports_enabled, selected_ports, discovery_methods, retry_count }
UiPreferences   — { refresh_rate_ms, auto_refresh, show_advanced_options, confirm_before_scan }
```

### 5.5 Persistence Types

```rust
ScanHistoryEntry — { id, scan_id, cidr, device_count, duration_ms, status, devices, timestamp }
Baseline         — { id, name, description, devices, scan_cidr, created_at }
BaselineDiff     — { baseline_id, baseline_name, new_hosts, removed_hosts,
                     changed_ports, new_services, scan_timestamp }
```

---

## 6. Storage Architecture

| Data | Format | Location | Module |
|------|--------|----------|--------|
| Settings profiles | JSON | `{config_dir}/profiles.json` | `settings.rs` |
| Current settings | JSON | `{config_dir}/current_settings.json` | `settings.rs` |
| Scan history | JSON (capped at 100) | `{config_dir}/scan_history.json` | `history.rs` |
| Baselines | SQLite | `{config_dir}/baselines.db` | `baseline.rs` |
| CVE database | SQLite | `assets/cve-database.db` | `network/cve.rs` |
| Nmap probes | Bincode (compiled) | `OUT_DIR/nmap_probes.bin` | `build.rs` |

The `config_dir` is determined by the `dirs` crate (platform-specific application data directory).

---

## 7. IPC System (Nexus Protocol)

NetSentinel includes a gRPC server for inter-tool communication within the Nexus ecosystem:

- **Transport**: Unix Domain Socket at `/tmp/nexus_central.sock`
- **Protocol**: Defined in `proto/nexus_ipc.proto` (git submodule from `nexus-protocol` repo)
- **Service**: `NexusIntercom` with bidirectional streaming (`StreamEvents`) and unary (`TriggerAction`)
- **Messages**: `NetworkHost`, `SecurityAlert`, `CommandTrigger` wrapped in `IPCMessage` oneof
- **Tools**: NET_SENTINEL, SHADOW_DECOY, VENOM_WEAVER, AEGIS_FUZZ, SLEUTH_HOUND
- **Integration**: Events are forwarded into the UI via `mpsc::Sender<AppEvent>`

---

## 8. Build System

### 8.1 Build Script (`build.rs`)

The build script performs two operations:

1. **Protobuf compilation**: Uses `tonic-build` + `protoc-bin-vendored` to compile `proto/nexus_ipc.proto` into Rust gRPC code.
2. **Nmap probe parsing**: Parses `assets/nmap-service-probes` using the `nmap_parser` workspace crate and serializes the probe database into `OUT_DIR/nmap_probes.bin` using bincode.

### 8.2 Workspace

```toml
[workspace]
members = ["tools/nmap_parser"]
```

The `nmap_parser` crate is a standalone library that defines `Probe`, `Match`, and `ProbeDatabase` structs for parsing nmap service fingerprint files.

### 8.3 Build & Run Commands

```bash
cargo build              # Standard debug build
cargo build --release    # Optimized release build
cargo run                # Run in debug mode
cargo test               # Run all tests
./dev-elevated.sh        # Build + run with root privileges (for raw socket scans)
```

---

## 9. Privilege Model

| Scan Type | Privilege Required | Fallback |
|-----------|-------------------|----------|
| TCP Connect | None | N/A |
| TCP SYN Stealth | root / CAP_NET_RAW | None (graceful error) |
| ICMP Ping Sweep | root / CAP_NET_RAW | TCP Probe fallback |
| ARP Sweep (active) | root / CAP_NET_RAW | ARP Table (passive) |
| UDP Scan | root (raw socket) | Basic UDP connect |
| Banner Grabbing | None | N/A |
| TLS Analysis | None | N/A |

The application detects privileges at startup via `commands/privilege.rs` and `network/privileges.rs`, displaying a warning banner if elevated features are unavailable.

---

## 10. Concurrency & Performance Constraints

| Resource | Limit | Mechanism |
|----------|-------|-----------|
| TCP concurrent connections | 1000 max | `tokio::sync::Semaphore` |
| ARP packet rate | 50 packets/second | Rate limiter |
| Scan history entries | 100 max | Eviction of oldest entries |
| Scan log buffer (UI) | 200 entries | Ring buffer (remove oldest) |
| Event channel batch interval | 200ms | `tokio::time::interval` in subscriptions |
| IPC channel buffer | 1024 messages | `mpsc::channel(1024)` |

---

## 11. Theme System (`ui/theme.rs`)

All colors are defined as module-level constants. No hardcoded colors should appear in view code.

| Token | Usage | RGB |
|-------|-------|-----|
| `BG` | Main window background | (17, 24, 39) |
| `SURFACE` | Cards, elevated panels | (31, 41, 55) |
| `PRIMARY` | Primary actions (blue) | (59, 130, 246) |
| `SUCCESS` | Online/active (green) | (16, 185, 129) |
| `DANGER` | Errors/CVE critical (red) | (239, 68, 68) |
| `WARNING` | Caution (amber) | (245, 158, 11) |
| `INFO` | Neutral accent (cyan) | (6, 182, 212) |
| `TEXT` | Primary text | (243, 244, 246) |
| `TEXT_MUTED` | Secondary text | (156, 163, 175) |
| `BORDER_COLOR` | Borders | (55, 65, 81) |
| `HEADER_BG` | Header/nav bar | (24, 32, 48) |
| `HOVER` | Hover state | (75, 85, 99) |
| `DISABLED` | Disabled elements | (107, 114, 128) |

Style functions: `card_style`, `header_style`, `app_background`, `primary_button`, `danger_button`, `secondary_button`, `success_button`, `tab_button`, `active_tab_button`, `toolbar_style`, `table_container_style`, `cve_banner_style`, `terminal_style`, `empty_state_style`.

---

## 12. Multi-Agent Orchestration System

### 12.1 Agent Hierarchy

```
NetSentinel General (Chief Orchestrator)
├── Planner    — Senior Rust & GUI Architect (read-only, no edit permission)
├── Developer  — Senior Systems & Iced Developer (full edit permission)
└── Reviewer   — Expert Security & GUI Code Auditor (read-only, no edit permission)
```

### 12.2 Agent Definitions (`.opencode/agents/`)

| Agent | File | Model | Temperature | Permissions |
|-------|------|-------|-------------|-------------|
| NetSentinel General | `netsentinel-general.md` | (default) | 0.3 | Full |
| Planner | `planner.md` | `opencode-go/deepseek-v4-pro` | 0.1 | `edit: deny` |
| Developer | `developer.md` | `opencode-go/kimi-k2.7-code` | 0.4 | Full |
| Reviewer | `reviewer.md` | `opencode-go/kimi-k2.7-code` | 0.2 | `edit: deny` |

### 12.3 Orchestration Pipeline

```
Request → [General: Decompose] → [Planner: Blueprint] → [Developer: Implement] → [Reviewer: Audit]
                                                                              ↑              │
                                                                              └── Fix loop ──┘
                                                                              (if CRITICAL/HIGH)
```

1. **General** receives the request, decomposes into backend/frontend tasks, formulates a feature brief.
2. **Planner** produces a complete architecture blueprint (structs, enums, async signatures, message variants, view hierarchy, styling guidelines). Never writes implementation code.
3. **Developer** implements the blueprint. Produces complete, compiling `.rs` files.
4. **Reviewer** audits in 5 passes: (1) Concurrency & Main-Thread Safety, (2) Panic Prevention, (3) Elm Architecture & View Purity, (4) Network Concurrency & Permissions, (5) Layout & Styling.
5. If CRITICAL or HIGH issues are found, code returns to Developer for fixes.

### 12.4 Skills (`.agents/skills/`)

| Skill | File | Scope |
|-------|------|-------|
| Backend Standards | `backend-standards/SKILL.md` | Rust safety, Tokio async, concurrency, SQLite, error handling, network scanning patterns |
| Frontend Standards | `frontend-standards/SKILL.md` | Elm Architecture, Iced layout, async GUI, themes, performance checklist |

---

## 13. Coding Conventions

### 13.1 Non-Negotiable Rules

1. **No panics in production**: Never use `.unwrap()`, `.expect()`, or `panic!()`. Use `?` operator and `Result<T, ScanError>`.
2. **No blocking I/O on GUI thread**: All network, file, and database operations must be async (Tokio) or wrapped in `tokio::task::spawn_blocking`.
3. **No lock poisoning across awaits**: Never hold `std::sync::MutexGuard` or `std::sync::RwLockGuard` across `.await` points. Use `tokio::sync::Mutex/RwLock` for async contexts.
4. **Pure view functions**: The `view()` function must not mutate state, clone large vectors, or perform sorting/filtering. All computation happens in `update()`.
5. **Theme consistency**: Never hardcode color values in view code. Use constants from `ui/theme.rs`.
6. **Resource control**: Use semaphores and concurrency limits for all network operations.

### 13.2 Error Handling Pattern

```rust
// All fallible functions return Result<T, ScanError>
async fn some_operation() -> Result<SomeType, ScanError> {
    let result = fallible_call()
        .await
        .map_err(|e| ScanError::NetworkError(format!("Context: {}", e)))?;
    Ok(result)
}
```

### 13.3 Async Command Pattern (UI -> Backend)

```rust
// In update(), dispatch async work via Task::perform
Message::SomeAction => {
    let state = self.shared_state.clone();
    Task::perform(
        async move {
            crate::commands::some_command(state).await
                .map_err(|e| e.to_string())
        },
        Message::SomeActionCompleted,  // wraps Result<T, String>
    )
}
```

### 13.4 Subscription Pattern (Backend -> UI)

```rust
// In subscription(), stream events via iced::stream::channel
Subscription::run_with_id(
    "unique-id",
    iced::stream::channel(100, move |mut output| async move {
        // Receive from channel, batch, send as Messages
    }),
)
```

---

## 14. Platform Support

| Platform | Discovery | Gateway Detection | Notes |
|----------|-----------|-------------------|-------|
| Linux | `/proc/net/arp`, raw sockets via pnet | `/proc/net/route` | Full raw socket support with CAP_NET_RAW |
| Windows | `arp -a` command | `route print` | Requires admin for raw sockets |
| macOS | `arp -a` command | `route -n get default` | Full raw socket support |

---

## 15. Testing

Tests are embedded in-module using `#[cfg(test)]` blocks. Key test coverage:

- `types.rs` — TTL estimation, service name mapping, serialization
- `settings.rs` — Profile creation, serialization roundtrips, defaults
- `history.rs` — CRUD operations, 100-entry cap, sort order, camelCase serialization
- `baseline.rs` — Diff computation (new/removed hosts, port changes), SQLite roundtrip

Run tests with:
```bash
cargo test
```

---

## 16. Key File Quick Reference

| Need to modify... | Start here |
|-------------------|-----------|
| Add a new UI page | `ui/mod.rs` (Page enum + view match) → `ui/views/new_page.rs` |
| Add a new Message variant | `ui/mod.rs` (Message enum + update match arm) |
| Add a new scan type | `types.rs` (ScanType enum) → `commands/scan.rs` → `network/` |
| Add a new network scanner | `network/mod.rs` → `network/new_scanner.rs` → `commands/scan.rs` |
| Modify theme/colors | `ui/theme.rs` |
| Add a new settings field | `settings.rs` (struct) → `ui/views/settings.rs` (UI) → `ui/mod.rs` (messages) |
| Add a new IPC message | `proto/nexus_ipc.proto` → `build.rs` → `ipc.rs` |
| Modify error types | `error.rs` (ScanError enum) |
| Add a new event type | `events.rs` (AppEvent/ScanEvent) → `ui/mod.rs` (subscription + message) |
| Modify baseline logic | `baseline.rs` (store + diff) → `commands/baseline.rs` |
| Add a new export format | `reporting/export.rs` → `ui/mod.rs` (export messages) |

---

*Last updated: 2026-06-23 — NetSentinel v0.1.0*
