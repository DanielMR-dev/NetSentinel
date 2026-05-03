# Backend Implementation Plan

## 1. Cargo.toml Changes
Add `pnet` for ARP packet construction:
```toml
pnet = "0.35"
```

## 2. Types (types.rs)
Add:
```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum DeviceType {
    Unknown,
    Mobile,     // iOS/Android
    Desktop,    // Windows/Mac/Linux
    Router,
    IoT,
}

#[derive(Serialize, Clone)]
pub struct ScanLogEvent {
    pub level: String,
    pub message: String,
    pub timestamp: i64,
    pub target: Option<String>,
    pub device_found: Option<bool>,
}
```

Update `Device` struct to include `device_type: DeviceType`.

## 3. Host Discovery (network/host_discovery.rs)
- Add `send_arp_probe()` using pnet for ARP who-has requests
- Add `detect_device_type()` from MAC OUI lookup
- Add `emit_log()` helper for structured logging
- Replace `found_devices.lock().unwrap()` with proper error handling
- Increase concurrency to 100 parallel checks
- Add ARP discovery phase before TCP probing

## 4. Scan State (state/scan_state.rs)
- Add `logs: Arc<Mutex<Vec<ScanLogEvent>>>` for storing scan logs
- Add `add_log()` method
- Add `get_logs()` method for frontend retrieval

## 5. Events to Emit
- `scan_log` - Structured log messages for frontend display
- `device_found` - Device discovered (existing)
- `scan_progress` - Progress updates (existing)
- `scan_complete` - Scan finished (existing)

## 6. Mobile Detection Strategy
1. Send ARP who-has to each IP (broadcast)
2. Devices that respond are alive regardless of open TCP ports
3. Parse MAC address from ARP response
4. Use OUI database (embedded) to guess device vendor/type
5. Mobile devices often don't have SSH/RDP/ SMB open but DO respond to ARP

## 7. Performance Optimizations
- Batch ARP requests (10 at a time with 100ms delays to avoid flooding)
- Parallel TCP probes for devices not found via ARP
- Early termination when response received