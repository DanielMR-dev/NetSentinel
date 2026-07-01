# NetSentinel

NetSentinel is a cross-platform desktop application for network discovery, security auditing, and infrastructure monitoring. Built for Blue Team, Purple Team, and SOC analysts, it combines a high-performance Rust scanning engine with a modern native Rust GUI (Iced) to deliver real-time network intelligence without leaving your desktop.


## Features

Features are grouped by maturity. Items in **Experimental** have initial implementations and may work in common scenarios but are not yet fully validated across all supported platforms. Items in **Planned** are on the roadmap but not yet available.

### Implemented

- **TCP Connect Scan** — Full TCP handshake scanning (no privileges required)
- **ARP Table Discovery** — Passive discovery from the system ARP cache (no privileges needed)
- **Device & Network Information** — Local system and network interface summary
- **Settings Profiles** — Persistent scan configurations with CRUD management
- **Scan History** — Persistent log of past scans with device details (capped at 100 entries)
- **Baseline Snapshots** — Save network state as SQLite-backed baselines and diff against future scans
- **Dark Theme** — Built-in dark theme with a comprehensive color token system
- **Real-time Progress** — Live progress bar, device count, and auto-scrolling scan logs
- **gRPC IPC Server** — Unix Domain Socket server for the Nexus ecosystem protocol

### Experimental

These modules are implemented and wired into the UI/scan pipeline but may be incomplete, platform-specific, or awaiting comprehensive test coverage.

- **ARP Sweep** — Layer 2 discovery via raw Ethernet frames (requires elevated privileges)
- **ICMP Ping Sweep** — Raw socket ICMP Echo Request scanning with privilege-aware fallback
- **TCP SYN Stealth Scan** — Half-open scanning via raw packet injection (requires root/CAP_NET_RAW)
- **TCP FIN/XMAS/NULL Scans** — Advanced stealth scanning techniques for firewall evasion
- **UDP Scan** — ICMP Port Unreachable-based UDP port discovery on critical services
- **SCTP INIT Scan** — Stream Control Transmission Protocol discovery
- **IPv6 Discovery** — Host discovery for IPv6 networks
- **mDNS/NetBIOS** — Name resolution via multicast DNS and NetBIOS protocols
- **Banner Grabbing** — Protocol-aware probes for SSH, HTTP, SMTP, FTP, MySQL, PostgreSQL, RDP, and more
- **Nmap Service Detection** — Fingerprint matching against the nmap-service-probes database
- **TLS/SSL Analysis** — Certificate inspection including version, cipher suite, issuer, expiry, self-signed detection, and SAN domain enumeration
- **OS Fingerprinting** — TTL-based OS estimation from response packets
- **OUI Vendor Lookup** — MAC address manufacturer identified from an IEEE OUI database
- **CVE Matching** — Known CVE entries matched against discovered service banners using a local SQLite database
- **Active Vulnerability Checks** — Targeted probes for known critical vulnerabilities on discovered services
- **Web Security Auditing** — HTTP/HTTPS security header analysis and misconfiguration detection
- **Threat Detection** — Identification of suspicious services, open proxies, and potential attack vectors
- **HTML/PDF Reports** — Audit report generation with device details, vulnerabilities, and recommendations
- **CSV/JSON Export** — Raw data export for integration with other tools
- **CVSS Scoring** — Common Vulnerability Scoring System integration
- **Compliance Checks** — Automated assessment against CIS, HIPAA, and PCI DSS benchmarks
- **Topology View** — Network topology visualization page

### Planned

- **Light Theme** — Alternative light color scheme
- **Keyboard Shortcuts** — Full keyboard navigation for efficient usage
- **Advanced Search & Filter** — Real-time device filtering by IP, MAC, hostname, vendor, and status
- **Sortable Tables** — Click-to-sort device tables by IP, MAC, vendor, hostname, open ports, and last seen
- **EPSS Integration** — Exploit Prediction Scoring System probability data
- **Scheduled Scans** — Recurring scan jobs and alerting
- **SIEM Export** — Native export to common SIEM formats
- **Cloud Asset Discovery** — Discovery of cloud-managed endpoints and APIs
- **Multi-User Collaboration** — Shared baselines and scan results across teams
- **REST API Server** — HTTP API for external integrations

## Tech Stack

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

## Architecture

The project follows a unified architecture within a single Rust binary, eliminating IPC overhead and the need for a web runtime.

### High-Level Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                         NetSentinel Binary                          │
│                                                                     │
│  ┌──────────────┐     ┌──────────────────┐     ┌────────────────┐   │
│  │   Iced GUI   │     │  Command Layer   │     │ Network Engine │   │
│  │  (ui/mod.rs) │────>│ (commands/*.rs)  │────>│ (network/*.rs) │   │
│  │              │<────│                  │<────│                │   │
│  │  Model       │     │  Async functions │     │  Scanners      │   │
│  │  Message     │     │  operating on    │     │  Banner grab   │   │
│  │  update()    │     │  SharedScanState │     │  CVE matching  │   │
│  │  view()      │     │                  │     │  TLS analysis  │   │
│  │  subscription│     │                  │     │  OS fingerprint│   │
│  └──────┬───────┘     └────────┬─────────┘     └────────┬───────┘   │
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
│  │  gRPC over Unix Domain Socket (/tmp/nexus_central.sock)       │  │
│  │  Receives: HostDiscovered, SecurityAlert, CommandTrigger      │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Architectural Patterns

- **Elm Architecture (Model-View-Update)**: Strict separation of UI state (`NetSentinelApp`), message handlers (`update()`), and pure rendering (`view()`)
- **Event Bridge System**: Backend events flow to the UI through two channel-based subscriptions (scanner events + IPC events), batched at 200ms intervals
- **Shared State Management**: `SharedScanState` uses `AtomicBool`/`AtomicU32` for lock-free flags and `Arc<tokio::sync::Mutex<T>>` for complex data
- **Async Command Pattern**: UI dispatches async work via `Task::perform`, backend operations return `Result<T, ScanError>`
- **Subscription Streaming**: Long-running tasks stream progress via `iced::stream::channel` with `tokio::select!` batching

### Storage Architecture

| Data | Format | Location |
|------|--------|----------|
| Settings profiles | JSON | `{config_dir}/profiles.json` |
| Current settings | JSON | `{config_dir}/current_settings.json` |
| Scan history | JSON (capped at 100) | `{config_dir}/scan_history.json` |
| Baselines | SQLite | `{config_dir}/baselines.db` |
| CVE database | SQLite | `assets/cve-database.db` |
| Nmap probes | Bincode (compiled) | `OUT_DIR/nmap_probes.bin` |

## Build from Source

### Prerequisites

| Dependency | Version | Purpose |
|------------|---------|---------|
| Rust | >= 1.77.2 | Main language runtime |
| GCC/Clang | Recent | C compiler for native crates |

**Ubuntu/Debian:**
```bash
sudo apt install build-essential pkg-config libx11-dev libasound2-dev libudev-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install dbus-devel pkgconf-pkg-config libX11-devel alsa-lib-devel systemd-devel
```

### Installation

The `proto/` directory is a **required Git submodule** registered in `.gitmodules`. It contains the Nexus Protocol definitions used by the gRPC IPC server. Make sure to clone recursively, or initialize the submodule after cloning:

```bash
git clone --recursive https://github.com/DanielMR-dev/NetSentinel.git
cd NetSentinel

# If you already cloned without --recursive, initialize the submodule:
git submodule update --init --recursive

cargo build --release
```

### Development

```bash
# Standard development mode
cargo run

# With elevated privileges (for SYN scan, ICMP, ARP sweep)
sudo -E ./dev-elevated.sh
```

### Testing

```bash
cargo test
```

## Privilege Levels

| Scan Type | Privilege Required | Fallback |
|-----------|-------------------|----------|
| TCP Connect | None | N/A |
| TCP SYN Stealth | root / CAP_NET_RAW | None (graceful error) |
| TCP FIN/XMAS/NULL | root / CAP_NET_RAW | None (graceful error) |
| ICMP Ping Sweep | root / CAP_NET_RAW | TCP Probe fallback |
| ARP Sweep (active) | root / CAP_NET_RAW | ARP Table (passive) |
| UDP Scan | root (raw socket) | Basic UDP connect |
| Banner Grabbing | None | N/A |
| TLS Analysis | None | N/A |
| Service Detection | None | N/A |

The application detects privileges at startup and displays a warning banner if elevated features are unavailable. Features requiring elevated privileges automatically fall back to unprivileged alternatives where possible.

## Requires Elevated Privileges

The following features require root/administrator access or `CAP_NET_RAW` on Linux. They will not function without elevation unless a fallback is available:

- **ARP Sweep** — sends raw Ethernet frames
- **ICMP Ping Sweep** — opens raw sockets for ICMP
- **TCP SYN Stealth Scan** — crafts raw TCP packets
- **TCP FIN/XMAS/NULL Scans** — crafts raw TCP packets with custom flag combinations
- **UDP Scan** — uses raw sockets to read ICMP unreachable responses

## Supported Platforms

| Platform | Discovery | Gateway Detection | Notes |
|----------|-----------|-------------------|-------|
| Linux | `/proc/net/arp`, raw sockets via pnet | `/proc/net/route` | Full raw socket support with CAP_NET_RAW |
| Windows | `arp -a` command | `route print` | Requires admin for raw sockets |
| macOS | `arp -a` command | `route -n get default` | Full raw socket support |

## Build System

The project uses a Cargo workspace with a custom build script (`build.rs`) that performs two operations:

1. **Protobuf compilation**: Uses `tonic-build` + `protoc-bin-vendored` to compile `proto/nexus_ipc.proto` into Rust gRPC code
2. **Nmap probe parsing**: Parses `assets/nmap-service-probes` using the `nmap_parser` workspace crate and serializes the probe database into `OUT_DIR/nmap_probes.bin` using bincode

### Workspace Structure

```toml
[workspace]
members = ["tools/nmap_parser"]
```

The `nmap_parser` crate is a standalone library that defines `Probe`, `Match`, and `ProbeDatabase` structs for parsing nmap service fingerprint files.

## Concurrency & Performance

| Resource | Limit | Mechanism |
|----------|-------|-----------|
| TCP concurrent connections | 1000 max | `tokio::sync::Semaphore` |
| ARP packet rate | 50 packets/second | Rate limiter |
| Scan history entries | 100 max | Eviction of oldest entries |
| Scan log buffer (UI) | 200 entries | Ring buffer (remove oldest) |
| Event channel batch interval | 200ms | `tokio::time::interval` in subscriptions |
| IPC channel buffer | 1024 messages | `mpsc::channel(1024)` |

## Screenshots

Screenshots will be added to `docs/images/` as the UI stabilizes. See [`docs/images/README.md`](docs/images/README.md) for the screenshot manifest and placeholder list.

## Theme System

All colors are defined as module-level constants in `ui/theme.rs`. No hardcoded colors appear in view code.

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

## License

This project is licensed under the MIT License — see the repository for the full license text.

---

**For developers and AI agents**: See `AGENTS.md` for comprehensive project intelligence including detailed architecture, data flow, coding conventions, and the multi-agent orchestration system.
