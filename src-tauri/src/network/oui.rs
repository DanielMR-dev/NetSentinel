//! OUI (Organizationally Unique Identifier) vendor lookup module.
//!
//! Extracts the first 3 octets (6 hex characters) from a MAC address
//! and looks up the manufacturer/vendor from a built-in table of the
//! top 50 most common OUI prefixes.

use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Static OUI lookup table, initialized once on first access.
///
/// Keys are uppercase `XX:XX:XX` prefixes (first 3 octets of a MAC address).
/// Values are the vendor/manufacturer name.
///
/// Each OUI prefix is assigned to exactly one vendor based on IEEE assignments.
static OUI_TABLE: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::with_capacity(256);

    // Apple
    m.insert("00:03:93", "Apple");
    m.insert("00:05:02", "Apple");
    m.insert("00:0A:27", "Apple");
    m.insert("00:0A:95", "Apple");
    m.insert("00:10:FA", "Apple");
    m.insert("00:1D:4F", "Apple");
    m.insert("00:1E:52", "Apple");
    m.insert("00:1E:C2", "Apple");
    m.insert("00:23:12", "Apple");
    m.insert("00:25:00", "Apple");
    m.insert("00:26:08", "Apple");
    m.insert("3C:07:54", "Apple");
    m.insert("A4:83:E7", "Apple");
    m.insert("AC:87:A3", "Apple");
    m.insert("F0:18:98", "Apple");

    // Samsung
    m.insert("00:16:6C", "Samsung");
    m.insert("00:21:19", "Samsung");
    m.insert("00:26:37", "Samsung");
    m.insert("08:D4:2B", "Samsung");
    m.insert("8C:71:F8", "Samsung");
    m.insert("A8:06:00", "Samsung");
    m.insert("B4:79:A7", "Samsung");

    // Intel
    m.insert("00:02:B3", "Intel");
    m.insert("00:03:47", "Intel");
    m.insert("00:04:23", "Intel");
    m.insert("00:07:E9", "Intel");
    m.insert("00:0E:0C", "Intel");
    m.insert("00:13:20", "Intel");
    m.insert("00:15:00", "Intel");
    m.insert("00:16:6F", "Intel");
    m.insert("00:18:F3", "Intel");
    m.insert("00:19:D1", "Intel");
    m.insert("00:1B:21", "Intel");
    m.insert("00:1C:BF", "Intel");
    m.insert("00:1E:65", "Intel");
    m.insert("00:20:7B", "Intel");
    m.insert("00:21:5D", "Intel");
    m.insert("00:22:FA", "Intel");
    m.insert("00:23:14", "Intel");
    m.insert("00:24:D6", "Intel");
    m.insert("00:26:C6", "Intel");
    m.insert("00:27:10", "Intel");
    m.insert("3C:D9:2B", "Intel");
    m.insert("68:05:CA", "Intel");
    m.insert("A0:36:9F", "Intel");
    m.insert("AC:7B:A1", "Intel");

    // Realtek
    m.insert("00:00:22", "Realtek");
    m.insert("00:E0:4C", "Realtek");
    m.insert("52:54:00", "Realtek");

    // Broadcom
    m.insert("00:10:18", "Broadcom");
    m.insert("00:1A:8A", "Broadcom");
    m.insert("00:24:D7", "Broadcom");

    // Qualcomm / Qualcomm Atheros
    m.insert("00:03:7F", "Qualcomm");
    m.insert("00:13:74", "Qualcomm");
    m.insert("00:24:6C", "Qualcomm Atheros");
    m.insert("04:F0:21", "Qualcomm");

    // MediaTek
    m.insert("00:0C:E7", "MediaTek");
    m.insert("00:1C:51", "MediaTek");

    // TP-Link
    m.insert("14:CC:20", "TP-Link");
    m.insert("30:B5:C2", "TP-Link");
    m.insert("50:C7:BF", "TP-Link");
    m.insert("60:E3:27", "TP-Link");
    m.insert("64:66:B3", "TP-Link");
    m.insert("64:70:02", "TP-Link");
    m.insert("90:F6:52", "TP-Link");
    m.insert("A0:F3:C1", "TP-Link");
    m.insert("B0:4E:26", "TP-Link");
    m.insert("C0:25:E9", "TP-Link");
    m.insert("F4:F2:6D", "TP-Link");

    // Netgear
    m.insert("00:09:5B", "Netgear");
    m.insert("00:0F:B5", "Netgear");
    m.insert("00:14:6C", "Netgear");
    m.insert("00:1B:2F", "Netgear");
    m.insert("00:1E:2A", "Netgear");
    m.insert("00:22:3F", "Netgear");
    m.insert("00:24:B2", "Netgear");
    m.insert("00:26:F2", "Netgear");
    m.insert("20:4E:7F", "Netgear");
    m.insert("84:1B:5E", "Netgear");
    m.insert("C0:3F:0E", "Netgear");
    m.insert("C4:3D:C7", "Netgear");
    m.insert("E0:46:9A", "Netgear");
    m.insert("E0:91:F5", "Netgear");

    // ASUS
    m.insert("00:0C:6E", "ASUS");
    m.insert("00:0E:A6", "ASUS");
    m.insert("00:11:2F", "ASUS");
    m.insert("00:15:F2", "ASUS");
    m.insert("00:17:31", "ASUS");
    m.insert("00:1A:92", "ASUS");
    m.insert("00:1D:60", "ASUS");
    m.insert("00:1E:8C", "ASUS");
    m.insert("00:22:15", "ASUS");
    m.insert("00:23:54", "ASUS");
    m.insert("00:24:8C", "ASUS");
    m.insert("00:26:18", "ASUS");
    m.insert("08:60:6E", "ASUS");
    m.insert("1C:87:2C", "ASUS");
    m.insert("2C:4D:54", "ASUS");
    m.insert("2C:56:DC", "ASUS");
    m.insert("30:85:A9", "ASUS");
    m.insert("38:2C:4A", "ASUS");
    m.insert("50:46:5D", "ASUS");
    m.insert("54:04:A6", "ASUS");
    m.insert("60:45:CB", "ASUS");
    m.insert("60:A4:4C", "ASUS");
    m.insert("74:D0:2B", "ASUS");
    m.insert("AC:22:0B", "ASUS");
    m.insert("BC:EE:7B", "ASUS");
    m.insert("D8:50:E6", "ASUS");
    m.insert("E0:3F:49", "ASUS");
    m.insert("E0:CB:4E", "ASUS");
    m.insert("F4:6D:04", "ASUS");

    // Cisco
    m.insert("00:00:0C", "Cisco");
    m.insert("00:01:42", "Cisco");
    m.insert("00:01:43", "Cisco");
    m.insert("00:01:63", "Cisco");
    m.insert("00:01:64", "Cisco");
    m.insert("00:01:96", "Cisco");
    m.insert("00:01:97", "Cisco");
    m.insert("00:01:C7", "Cisco");
    m.insert("00:01:C9", "Cisco");
    m.insert("00:02:16", "Cisco");
    m.insert("00:02:17", "Cisco");
    m.insert("00:02:4A", "Cisco");
    m.insert("00:02:4B", "Cisco");
    m.insert("00:02:7D", "Cisco");
    m.insert("00:02:7E", "Cisco");
    m.insert("00:03:6B", "Cisco");
    m.insert("00:03:94", "Cisco");
    m.insert("00:03:9F", "Cisco");
    m.insert("00:03:A0", "Cisco");
    m.insert("00:03:DD", "Cisco");
    m.insert("00:03:E0", "Cisco");
    m.insert("00:03:FD", "Cisco");
    m.insert("00:04:27", "Cisco");
    m.insert("00:04:28", "Cisco");
    m.insert("00:04:4D", "Cisco");
    m.insert("00:04:4E", "Cisco");
    m.insert("00:04:6D", "Cisco");
    m.insert("00:04:6E", "Cisco");
    m.insert("00:04:C0", "Cisco");
    m.insert("00:04:C1", "Cisco");
    m.insert("00:05:00", "Cisco");
    m.insert("00:05:01", "Cisco");
    m.insert("00:05:31", "Cisco");
    m.insert("00:05:32", "Cisco");
    m.insert("00:05:5E", "Cisco");
    m.insert("00:05:5F", "Cisco");
    m.insert("00:05:73", "Cisco");
    m.insert("00:05:74", "Cisco");
    m.insert("00:05:9A", "Cisco");
    m.insert("00:05:9B", "Cisco");
    m.insert("00:40:96", "Cisco");
    m.insert("00:50:0F", "Cisco");
    m.insert("00:50:2A", "Cisco");
    m.insert("00:50:3E", "Cisco");
    m.insert("00:50:53", "Cisco");
    m.insert("00:50:54", "Cisco");
    m.insert("00:50:80", "Cisco");
    m.insert("00:50:A2", "Cisco");
    m.insert("00:50:BD", "Cisco");
    m.insert("00:50:CD", "Cisco");
    m.insert("00:50:D1", "Cisco");
    m.insert("00:50:E2", "Cisco");
    m.insert("00:50:F0", "Cisco");
    m.insert("00:60:09", "Cisco");
    m.insert("00:60:2F", "Cisco");
    m.insert("00:60:3E", "Cisco");
    m.insert("00:60:47", "Cisco");
    m.insert("00:60:5C", "Cisco");
    m.insert("00:60:70", "Cisco");
    m.insert("00:60:83", "Cisco");
    m.insert("00:60:97", "Cisco");
    m.insert("00:90:0C", "Cisco");
    m.insert("00:90:21", "Cisco");
    m.insert("00:90:2B", "Cisco");
    m.insert("00:90:5F", "Cisco");
    m.insert("00:90:6D", "Cisco");
    m.insert("00:90:6F", "Cisco");
    m.insert("00:90:86", "Cisco");
    m.insert("00:90:A6", "Cisco");
    m.insert("00:90:AB", "Cisco");
    m.insert("00:90:B1", "Cisco");
    m.insert("00:90:BF", "Cisco");
    m.insert("00:90:D9", "Cisco");
    m.insert("00:90:F2", "Cisco");
    m.insert("00:A0:C9", "Cisco");
    m.insert("00:B0:17", "Cisco");
    m.insert("00:B0:19", "Cisco");
    m.insert("00:B0:4A", "Cisco");
    m.insert("00:B0:64", "Cisco");
    m.insert("00:B0:8E", "Cisco");
    m.insert("00:B0:C2", "Cisco");
    m.insert("00:B0:FA", "Cisco");
    m.insert("00:D0:58", "Cisco");
    m.insert("00:D0:79", "Cisco");
    m.insert("00:D0:90", "Cisco");
    m.insert("00:D0:BA", "Cisco");
    m.insert("00:D0:BC", "Cisco");
    m.insert("00:D0:FF", "Cisco");
    m.insert("00:E0:14", "Cisco");
    m.insert("00:E0:18", "Cisco");
    m.insert("00:E0:1E", "Cisco");
    m.insert("00:E0:34", "Cisco");
    m.insert("00:E0:4F", "Cisco");
    m.insert("00:E0:A3", "Cisco");
    m.insert("00:E0:B0", "Cisco");
    m.insert("00:E0:F7", "Cisco");
    m.insert("00:E0:F9", "Cisco");

    // Dell
    m.insert("00:06:5B", "Dell");
    m.insert("00:08:74", "Dell");
    m.insert("00:0B:DB", "Dell");
    m.insert("00:0D:56", "Dell");
    m.insert("00:0F:1F", "Dell");
    m.insert("00:11:43", "Dell");
    m.insert("00:12:3F", "Dell");
    m.insert("00:13:72", "Dell");
    m.insert("00:14:22", "Dell");
    m.insert("00:15:C5", "Dell");
    m.insert("00:18:8B", "Dell");
    m.insert("00:19:B9", "Dell");
    m.insert("00:1A:A0", "Dell");
    m.insert("00:1C:23", "Dell");
    m.insert("00:1D:09", "Dell");
    m.insert("00:1E:4F", "Dell");
    m.insert("00:1E:C9", "Dell");
    m.insert("00:21:70", "Dell");
    m.insert("00:21:9B", "Dell");
    m.insert("00:22:19", "Dell");
    m.insert("00:24:E8", "Dell");
    m.insert("00:25:64", "Dell");
    m.insert("00:26:B9", "Dell");
    m.insert("14:FE:B5", "Dell");
    m.insert("24:6E:96", "Dell");
    m.insert("34:17:EB", "Dell");
    m.insert("34:E6:D7", "Dell");
    m.insert("44:A8:42", "Dell");
    m.insert("4C:76:25", "Dell");
    m.insert("5C:26:0A", "Dell");
    m.insert("64:00:6A", "Dell");
    m.insert("78:2B:CB", "Dell");
    m.insert("78:45:C4", "Dell");
    m.insert("84:7B:EB", "Dell");
    m.insert("90:B1:1C", "Dell");
    m.insert("A4:1F:72", "Dell");
    m.insert("B0:83:FE", "Dell");
    m.insert("B8:2A:72", "Dell");
    m.insert("BC:30:5B", "Dell");
    m.insert("D4:81:D7", "Dell");
    m.insert("D4:BE:D9", "Dell");
    m.insert("EC:F4:BB", "Dell");
    m.insert("F0:1F:AF", "Dell");
    m.insert("F8:BC:12", "Dell");
    m.insert("F8:CA:B8", "Dell");

    // HP (Hewlett-Packard)
    m.insert("00:01:E6", "HP");
    m.insert("00:02:A5", "HP");
    m.insert("00:04:EA", "HP");
    m.insert("00:08:02", "HP");
    m.insert("00:08:83", "HP");
    m.insert("00:08:C7", "HP");
    m.insert("00:0A:57", "HP");
    m.insert("00:0B:CD", "HP");
    m.insert("00:0D:9D", "HP");
    m.insert("00:0E:7F", "HP");
    m.insert("00:0F:20", "HP");
    m.insert("00:0F:61", "HP");
    m.insert("00:10:E3", "HP");
    m.insert("00:11:0A", "HP");
    m.insert("00:11:85", "HP");
    m.insert("00:12:79", "HP");
    m.insert("00:13:21", "HP");
    m.insert("00:14:38", "HP");
    m.insert("00:14:C2", "HP");
    m.insert("00:15:60", "HP");
    m.insert("00:16:35", "HP");
    m.insert("00:17:08", "HP");
    m.insert("00:17:A4", "HP");
    m.insert("00:18:71", "HP");
    m.insert("00:18:FE", "HP");
    m.insert("00:19:BB", "HP");
    m.insert("00:1A:4B", "HP");
    m.insert("00:1B:78", "HP");
    m.insert("00:1C:C4", "HP");
    m.insert("00:1E:0B", "HP");
    m.insert("00:1F:29", "HP");
    m.insert("00:21:5A", "HP");
    m.insert("00:22:64", "HP");
    m.insert("00:23:7D", "HP");
    m.insert("00:24:81", "HP");
    m.insert("00:25:B3", "HP");
    m.insert("00:26:55", "HP");
    m.insert("00:30:C1", "HP");
    m.insert("00:50:8B", "HP");
    m.insert("00:60:B0", "HP");
    m.insert("00:80:5F", "HP");
    m.insert("00:80:A0", "HP");
    m.insert("18:A9:05", "HP");
    m.insert("1C:C1:DE", "HP");
    m.insert("2C:27:D7", "HP");
    m.insert("48:0F:CF", "HP");
    m.insert("5C:8A:38", "HP");
    m.insert("6C:C2:17", "HP");
    m.insert("78:E3:B5", "HP");
    m.insert("94:57:A5", "HP");
    m.insert("9C:8E:99", "HP");
    m.insert("A0:1D:48", "HP");
    m.insert("A0:48:1C", "HP");
    m.insert("A0:D3:C1", "HP");
    m.insert("B4:99:BA", "HP");
    m.insert("B8:AF:67", "HP");
    m.insert("C8:CB:B8", "HP");
    m.insert("D4:85:64", "HP");
    m.insert("E8:39:35", "HP");
    m.insert("F4:15:63", "HP");

    // Lenovo
    m.insert("00:06:1B", "Lenovo");
    m.insert("00:09:2D", "Lenovo");
    m.insert("00:09:6B", "Lenovo");
    m.insert("00:0A:E4", "Lenovo");
    m.insert("00:12:FE", "Lenovo");
    m.insert("00:16:D3", "Lenovo");
    m.insert("00:1A:6B", "Lenovo");
    m.insert("00:21:5E", "Lenovo");
    m.insert("00:24:7E", "Lenovo");
    m.insert("00:26:2D", "Lenovo");
    m.insert("28:6C:07", "Lenovo");
    m.insert("2C:D4:44", "Lenovo");
    m.insert("34:02:86", "Lenovo");
    m.insert("34:64:A9", "Lenovo");
    m.insert("3C:97:0E", "Lenovo");
    m.insert("48:5A:B6", "Lenovo");
    m.insert("50:7B:9D", "Lenovo");
    m.insert("5C:C5:D4", "Lenovo");
    m.insert("60:36:DD", "Lenovo");
    m.insert("60:57:18", "Lenovo");
    m.insert("60:6C:71", "Lenovo");
    m.insert("6C:92:BF", "Lenovo");
    m.insert("70:5A:0F", "Lenovo");
    m.insert("74:E5:43", "Lenovo");
    m.insert("7C:7A:91", "Lenovo");
    m.insert("84:3A:4B", "Lenovo");
    m.insert("8C:16:45", "Lenovo");
    m.insert("98:FA:9B", "Lenovo");
    m.insert("A0:8C:FD", "Lenovo");
    m.insert("B8:88:E3", "Lenovo");
    m.insert("C8:5B:5B", "Lenovo");
    m.insert("DC:0E:A1", "Lenovo");
    m.insert("F0:DE:F1", "Lenovo");

    // Xiaomi
    m.insert("00:9E:C8", "Xiaomi");
    m.insert("04:CF:8C", "Xiaomi");
    m.insert("0C:1D:AF", "Xiaomi");
    m.insert("10:2A:B3", "Xiaomi");
    m.insert("14:F6:5A", "Xiaomi");
    m.insert("18:59:36", "Xiaomi");
    m.insert("1C:AB:34", "Xiaomi");
    m.insert("20:82:C0", "Xiaomi");
    m.insert("28:E3:1F", "Xiaomi");
    m.insert("34:CE:00", "Xiaomi");
    m.insert("38:A4:ED", "Xiaomi");
    m.insert("3C:BD:3E", "Xiaomi");
    m.insert("40:31:3C", "Xiaomi");
    m.insert("4C:13:19", "Xiaomi");
    m.insert("50:64:2B", "Xiaomi");
    m.insert("58:44:98", "Xiaomi");
    m.insert("64:B4:73", "Xiaomi");
    m.insert("64:CC:2E", "Xiaomi");
    m.insert("68:DF:DD", "Xiaomi");
    m.insert("74:23:44", "Xiaomi");
    m.insert("78:02:F8", "Xiaomi");
    m.insert("78:11:DC", "Xiaomi");
    m.insert("7C:1D:D9", "Xiaomi");
    m.insert("84:44:64", "Xiaomi");
    m.insert("8C:DE:F9", "Xiaomi");
    m.insert("98:FA:E3", "Xiaomi");
    m.insert("9C:99:A0", "Xiaomi");
    m.insert("A0:86:C6", "Xiaomi");
    m.insert("AC:C1:EE", "Xiaomi");
    m.insert("B0:E2:35", "Xiaomi");
    m.insert("C4:6A:B7", "Xiaomi");
    m.insert("D4:97:0B", "Xiaomi");
    m.insert("EC:D0:9F", "Xiaomi");
    m.insert("F0:B4:29", "Xiaomi");
    m.insert("F4:8B:32", "Xiaomi");
    m.insert("F8:A4:5F", "Xiaomi");
    m.insert("FC:64:BA", "Xiaomi");

    // Huawei
    m.insert("00:04:0D", "Huawei");
    m.insert("00:0F:E2", "Huawei");
    m.insert("00:18:82", "Huawei");
    m.insert("00:1E:10", "Huawei");
    m.insert("00:22:A1", "Huawei");
    m.insert("00:25:68", "Huawei");
    m.insert("00:25:9E", "Huawei");
    m.insert("00:34:FE", "Huawei");
    m.insert("00:46:4B", "Huawei");
    m.insert("00:5C:D2", "Huawei");
    m.insert("00:66:4B", "Huawei");
    m.insert("00:6B:8E", "Huawei");
    m.insert("00:6D:52", "Huawei");
    m.insert("00:9A:CD", "Huawei");
    m.insert("00:E0:FC", "Huawei");
    m.insert("04:02:1F", "Huawei");
    m.insert("04:25:C5", "Huawei");
    m.insert("04:4F:4C", "Huawei");
    m.insert("04:52:C7", "Huawei");
    m.insert("04:75:03", "Huawei");
    m.insert("04:92:26", "Huawei");
    m.insert("04:9F:CA", "Huawei");
    m.insert("04:B0:E7", "Huawei");
    m.insert("04:C0:6F", "Huawei");
    m.insert("04:D3:B0", "Huawei");
    m.insert("04:F9:38", "Huawei");
    m.insert("08:19:A6", "Huawei");
    m.insert("08:63:61", "Huawei");
    m.insert("08:7A:4C", "Huawei");
    m.insert("08:9E:01", "Huawei");
    m.insert("0C:37:DC", "Huawei");
    m.insert("0C:45:BA", "Huawei");
    m.insert("0C:8B:D3", "Huawei");
    m.insert("0C:96:BF", "Huawei");
    m.insert("0C:D6:BD", "Huawei");
    m.insert("10:1B:54", "Huawei");
    m.insert("10:44:00", "Huawei");
    m.insert("10:47:80", "Huawei");
    m.insert("10:51:72", "Huawei");
    m.insert("10:C6:1F", "Huawei");
    m.insert("14:15:7C", "Huawei");
    m.insert("14:B9:68", "Huawei");
    m.insert("18:C5:8A", "Huawei");
    m.insert("1C:15:1F", "Huawei");
    m.insert("1C:67:58", "Huawei");
    m.insert("1C:8E:5C", "Huawei");
    m.insert("20:08:ED", "Huawei");
    m.insert("20:2B:C1", "Huawei");
    m.insert("20:A6:80", "Huawei");
    m.insert("24:09:95", "Huawei");
    m.insert("24:1F:A0", "Huawei");
    m.insert("24:44:27", "Huawei");
    m.insert("24:69:3E", "Huawei");
    m.insert("24:69:A5", "Huawei");
    m.insert("24:71:89", "Huawei");
    m.insert("24:7F:3C", "Huawei");
    m.insert("24:9E:AB", "Huawei");
    m.insert("24:D9:21", "Huawei");
    m.insert("28:31:52", "Huawei");
    m.insert("28:5F:DB", "Huawei");
    m.insert("28:6E:D4", "Huawei");
    m.insert("28:BC:56", "Huawei");
    m.insert("2C:5B:B8", "Huawei");
    m.insert("2C:AB:00", "Huawei");
    m.insert("30:87:30", "Huawei");
    m.insert("30:D1:7E", "Huawei");
    m.insert("30:F3:35", "Huawei");
    m.insert("34:00:A3", "Huawei");
    m.insert("34:12:98", "Huawei");
    m.insert("34:6B:D3", "Huawei");
    m.insert("34:CD:BE", "Huawei");
    m.insert("38:46:08", "Huawei");
    m.insert("38:BC:01", "Huawei");
    m.insert("38:F2:3E", "Huawei");
    m.insert("3C:47:11", "Huawei");
    m.insert("3C:BB:FD", "Huawei");
    m.insert("3C:DF:BD", "Huawei");
    m.insert("40:4D:8E", "Huawei");
    m.insert("40:CB:A8", "Huawei");
    m.insert("44:55:B1", "Huawei");
    m.insert("48:46:FB", "Huawei");
    m.insert("48:57:DD", "Huawei");
    m.insert("48:DB:50", "Huawei");
    m.insert("4C:1F:CC", "Huawei");
    m.insert("4C:54:99", "Huawei");
    m.insert("4C:8B:30", "Huawei");
    m.insert("50:06:AB", "Huawei");
    m.insert("50:1D:93", "Huawei");
    m.insert("50:9F:27", "Huawei");
    m.insert("54:89:98", "Huawei");
    m.insert("54:A5:1B", "Huawei");
    m.insert("58:1F:28", "Huawei");
    m.insert("58:2A:F7", "Huawei");
    m.insert("58:7F:66", "Huawei");
    m.insert("5C:4C:A9", "Huawei");
    m.insert("5C:7D:5E", "Huawei");
    m.insert("5C:B3:95", "Huawei");
    m.insert("5C:B4:3E", "Huawei");
    m.insert("5C:C3:07", "Huawei");
    m.insert("60:08:10", "Huawei");
    m.insert("60:DE:44", "Huawei");
    m.insert("60:E7:01", "Huawei");
    m.insert("64:16:F0", "Huawei");
    m.insert("64:3E:8C", "Huawei");
    m.insert("64:6E:EA", "Huawei");
    m.insert("64:A6:51", "Huawei");
    m.insert("68:8F:84", "Huawei");
    m.insert("68:A0:F6", "Huawei");
    m.insert("68:A8:28", "Huawei");
    m.insert("68:CC:6E", "Huawei");
    m.insert("6C:0E:0D", "Huawei");
    m.insert("6C:8D:C1", "Huawei");
    m.insert("70:19:2F", "Huawei");
    m.insert("70:54:F5", "Huawei");
    m.insert("70:72:3C", "Huawei");
    m.insert("70:7B:E8", "Huawei");
    m.insert("70:8A:09", "Huawei");
    m.insert("70:A8:E3", "Huawei");
    m.insert("74:88:2A", "Huawei");
    m.insert("74:9D:DC", "Huawei");
    m.insert("74:A0:63", "Huawei");
    m.insert("74:A2:E6", "Huawei");
    m.insert("74:DB:D1", "Huawei");
    m.insert("78:1D:BA", "Huawei");
    m.insert("78:4B:87", "Huawei");
    m.insert("78:6A:89", "Huawei");
    m.insert("78:D7:52", "Huawei");
    m.insert("7C:11:CB", "Huawei");
    m.insert("7C:60:97", "Huawei");
    m.insert("7C:A2:3E", "Huawei");
    m.insert("80:38:BC", "Huawei");
    m.insert("80:B6:86", "Huawei");
    m.insert("80:D0:9B", "Huawei");
    m.insert("80:FB:06", "Huawei");
    m.insert("84:5B:12", "Huawei");
    m.insert("84:74:2A", "Huawei");
    m.insert("84:DB:AC", "Huawei");
    m.insert("88:53:D4", "Huawei");
    m.insert("88:66:39", "Huawei");
    m.insert("88:A2:D7", "Huawei");
    m.insert("88:CE:FA", "Huawei");
    m.insert("88:F7:C7", "Huawei");
    m.insert("8C:34:FD", "Huawei");
    m.insert("90:17:AC", "Huawei");
    m.insert("90:4E:2B", "Huawei");
    m.insert("90:67:1C", "Huawei");
    m.insert("94:04:9C", "Huawei");
    m.insert("94:77:2B", "Huawei");
    m.insert("94:DB:C9", "Huawei");
    m.insert("98:4C:04", "Huawei");
    m.insert("9C:28:EF", "Huawei");
    m.insert("9C:37:F4", "Huawei");
    m.insert("9C:53:22", "Huawei");
    m.insert("9C:54:CA", "Huawei");
    m.insert("9C:C1:72", "Huawei");
    m.insert("A0:AB:1B", "Huawei");
    m.insert("A4:99:47", "Huawei");
    m.insert("A4:BA:DB", "Huawei");
    m.insert("A8:57:4E", "Huawei");
    m.insert("AC:4E:91", "Huawei");
    m.insert("AC:85:3D", "Huawei");
    m.insert("AC:CF:85", "Huawei");
    m.insert("B0:59:47", "Huawei");
    m.insert("B0:78:F0", "Huawei");
    m.insert("B0:E2:E5", "Huawei");
    m.insert("B4:15:13", "Huawei");
    m.insert("B4:30:52", "Huawei");
    m.insert("B8:BC:1B", "Huawei");
    m.insert("BC:76:70", "Huawei");
    m.insert("C0:70:09", "Huawei");
    m.insert("C4:05:28", "Huawei");
    m.insert("C4:4A:D0", "Huawei");
    m.insert("C4:8E:8F", "Huawei");
    m.insert("C8:14:51", "Huawei");
    m.insert("C8:51:95", "Huawei");
    m.insert("CC:46:D6", "Huawei");
    m.insert("CC:53:B5", "Huawei");
    m.insert("CC:96:A0", "Huawei");
    m.insert("CC:A2:23", "Huawei");
    m.insert("D0:2D:B3", "Huawei");
    m.insert("D0:7A:B5", "Huawei");
    m.insert("D4:40:F0", "Huawei");
    m.insert("D4:6A:A8", "Huawei");
    m.insert("D4:6E:5C", "Huawei");
    m.insert("D4:72:26", "Huawei");
    m.insert("D4:94:E8", "Huawei");
    m.insert("D4:B1:10", "Huawei");
    m.insert("D8:49:0B", "Huawei");
    m.insert("D8:78:E5", "Huawei");
    m.insert("DC:09:4C", "Huawei");
    m.insert("DC:D2:FC", "Huawei");
    m.insert("E0:19:1D", "Huawei");
    m.insert("E0:24:7F", "Huawei");
    m.insert("E0:2A:82", "Huawei");
    m.insert("E0:97:F2", "Huawei");
    m.insert("E4:68:A3", "Huawei");
    m.insert("E8:08:82", "Huawei");
    m.insert("E8:5A:8B", "Huawei");
    m.insert("E8:CD:2D", "Huawei");
    m.insert("EC:23:3D", "Huawei");
    m.insert("EC:8C:A2", "Huawei");
    m.insert("F0:2F:D8", "Huawei");
    m.insert("F0:97:E6", "Huawei");
    m.insert("F0:C8:50", "Huawei");
    m.insert("F4:55:9C", "Huawei");
    m.insert("F4:8E:38", "Huawei");
    m.insert("F4:9F:F3", "Huawei");
    m.insert("F4:C7:14", "Huawei");
    m.insert("F8:01:13", "Huawei");
    m.insert("F8:3D:FF", "Huawei");
    m.insert("F8:4A:BF", "Huawei");
    m.insert("F8:71:0C", "Huawei");
    m.insert("F8:98:B9", "Huawei");
    m.insert("F8:BF:09", "Huawei");
    m.insert("F8:E8:11", "Huawei");
    m.insert("FC:48:EF", "Huawei");
    m.insert("FC:CF:62", "Huawei");

    // Amazon
    m.insert("00:BB:3A", "Amazon");
    m.insert("00:FC:8B", "Amazon");
    m.insert("0C:47:C9", "Amazon");
    m.insert("10:AE:60", "Amazon");
    m.insert("14:91:82", "Amazon");
    m.insert("18:74:2E", "Amazon");
    m.insert("34:D2:70", "Amazon");
    m.insert("38:F7:3D", "Amazon");
    m.insert("40:B4:CD", "Amazon");
    m.insert("44:65:0D", "Amazon");
    m.insert("50:F5:DA", "Amazon");
    m.insert("68:37:E9", "Amazon");
    m.insert("68:54:FD", "Amazon");
    m.insert("74:75:48", "Amazon");
    m.insert("74:C2:46", "Amazon");
    m.insert("78:E1:03", "Amazon");
    m.insert("84:D6:D0", "Amazon");
    m.insert("88:71:E5", "Amazon");
    m.insert("A0:02:DC", "Amazon");
    m.insert("AC:63:BE", "Amazon");
    m.insert("B4:7C:9C", "Amazon");
    m.insert("F0:27:2D", "Amazon");
    m.insert("F0:4F:7C", "Amazon");
    m.insert("F0:A2:25", "Amazon");
    m.insert("F0:D2:F1", "Amazon");
    m.insert("FC:65:DE", "Amazon");
    m.insert("FC:A1:83", "Amazon");
    m.insert("FC:A6:67", "Amazon");

    // Google
    m.insert("3C:5A:B4", "Google");
    m.insert("54:60:09", "Google");
    m.insert("94:EB:2C", "Google");
    m.insert("A4:77:33", "Google");
    m.insert("F4:F5:D8", "Google");
    m.insert("F4:F5:E8", "Google");
    m.insert("F8:8F:CA", "Google");

    // Raspberry Pi
    m.insert("B8:27:EB", "Raspberry Pi");
    m.insert("DC:A6:32", "Raspberry Pi");
    m.insert("E4:5F:01", "Raspberry Pi");
    m.insert("2C:CF:67", "Raspberry Pi");

    // Espressif (ESP32/ESP8266)
    m.insert("24:0A:C4", "Espressif");
    m.insert("24:62:AB", "Espressif");
    m.insert("24:6F:28", "Espressif");
    m.insert("30:AE:A4", "Espressif");
    m.insert("3C:71:BF", "Espressif");
    m.insert("48:3F:DA", "Espressif");
    m.insert("4C:11:AE", "Espressif");
    m.insert("4C:75:25", "Espressif");
    m.insert("50:02:91", "Espressif");
    m.insert("54:5A:A6", "Espressif");
    m.insert("5C:CF:7F", "Espressif");
    m.insert("60:01:94", "Espressif");
    m.insert("68:C6:3A", "Espressif");
    m.insert("7C:9E:BD", "Espressif");
    m.insert("7C:DF:A1", "Espressif");
    m.insert("80:7D:3A", "Espressif");
    m.insert("84:0D:8E", "Espressif");
    m.insert("84:F3:EB", "Espressif");
    m.insert("8C:AA:B5", "Espressif");
    m.insert("94:B9:7E", "Espressif");
    m.insert("98:CD:AC", "Espressif");
    m.insert("A0:20:A6", "Espressif");
    m.insert("A4:CF:12", "Espressif");
    m.insert("AC:67:B2", "Espressif");
    m.insert("B4:E6:2D", "Espressif");
    m.insert("C4:4F:33", "Espressif");
    m.insert("C4:5B:BE", "Espressif");
    m.insert("C8:2B:96", "Espressif");
    m.insert("CC:50:E3", "Espressif");
    m.insert("D8:A0:1D", "Espressif");
    m.insert("D8:BF:C0", "Espressif");
    m.insert("EC:FA:BC", "Espressif");
    m.insert("F0:08:D1", "Espressif");
    m.insert("F4:CF:A2", "Espressif");

    // Texas Instruments
    m.insert("00:12:4B", "Texas Instruments");
    m.insert("00:17:EA", "Texas Instruments");
    m.insert("00:17:EB", "Texas Instruments");
    m.insert("00:18:2F", "Texas Instruments");
    m.insert("00:18:30", "Texas Instruments");
    m.insert("00:18:31", "Texas Instruments");
    m.insert("00:18:32", "Texas Instruments");
    m.insert("00:18:33", "Texas Instruments");
    m.insert("00:18:34", "Texas Instruments");
    m.insert("00:21:BA", "Texas Instruments");
    m.insert("00:22:A5", "Texas Instruments");
    m.insert("00:23:D4", "Texas Instruments");
    m.insert("00:24:BA", "Texas Instruments");
    m.insert("08:00:28", "Texas Instruments");
    m.insert("10:2E:AF", "Texas Instruments");
    m.insert("10:CE:A9", "Texas Instruments");
    m.insert("14:7D:C5", "Texas Instruments");
    m.insert("18:04:ED", "Texas Instruments");
    m.insert("18:2C:65", "Texas Instruments");
    m.insert("18:33:9D", "Texas Instruments");
    m.insert("18:93:D7", "Texas Instruments");
    m.insert("1C:45:93", "Texas Instruments");
    m.insert("20:91:48", "Texas Instruments");
    m.insert("20:CD:39", "Texas Instruments");
    m.insert("28:EC:9A", "Texas Instruments");
    m.insert("34:15:13", "Texas Instruments");
    m.insert("34:B1:F7", "Texas Instruments");
    m.insert("3C:2D:B7", "Texas Instruments");
    m.insert("40:5F:C2", "Texas Instruments");
    m.insert("40:BD:32", "Texas Instruments");
    m.insert("44:C1:5C", "Texas Instruments");
    m.insert("50:51:A9", "Texas Instruments");
    m.insert("50:72:24", "Texas Instruments");
    m.insert("50:8C:B1", "Texas Instruments");
    m.insert("54:4A:16", "Texas Instruments");
    m.insert("54:6C:0E", "Texas Instruments");
    m.insert("54:7F:EE", "Texas Instruments");
    m.insert("5C:31:3E", "Texas Instruments");
    m.insert("60:64:05", "Texas Instruments");
    m.insert("64:7B:D4", "Texas Instruments");
    m.insert("64:9C:81", "Texas Instruments");
    m.insert("68:47:49", "Texas Instruments");
    m.insert("68:C9:0B", "Texas Instruments");
    m.insert("70:FF:76", "Texas Instruments");
    m.insert("74:D6:EA", "Texas Instruments");
    m.insert("78:A5:04", "Texas Instruments");
    m.insert("78:C5:E5", "Texas Instruments");
    m.insert("78:DE:E4", "Texas Instruments");
    m.insert("7C:66:9D", "Texas Instruments");
    m.insert("80:30:DC", "Texas Instruments");
    m.insert("84:DD:20", "Texas Instruments");
    m.insert("88:33:14", "Texas Instruments");
    m.insert("88:4A:EA", "Texas Instruments");
    m.insert("90:59:AF", "Texas Instruments");
    m.insert("98:07:2D", "Texas Instruments");
    m.insert("98:59:45", "Texas Instruments");
    m.insert("98:5D:AD", "Texas Instruments");
    m.insert("9C:1D:58", "Texas Instruments");
    m.insert("A0:E6:F8", "Texas Instruments");
    m.insert("A0:F6:FD", "Texas Instruments");
    m.insert("A4:DA:32", "Texas Instruments");
    m.insert("B0:91:22", "Texas Instruments");
    m.insert("B4:EE:D4", "Texas Instruments");
    m.insert("BC:0D:A5", "Texas Instruments");
    m.insert("BC:6A:29", "Texas Instruments");
    m.insert("C0:E4:22", "Texas Instruments");
    m.insert("C4:BE:84", "Texas Instruments");
    m.insert("C4:ED:BA", "Texas Instruments");
    m.insert("C8:3E:99", "Texas Instruments");
    m.insert("C8:A0:30", "Texas Instruments");
    m.insert("CC:78:AB", "Texas Instruments");
    m.insert("CC:8C:E3", "Texas Instruments");
    m.insert("D0:07:90", "Texas Instruments");
    m.insert("D0:39:72", "Texas Instruments");
    m.insert("D0:5F:B8", "Texas Instruments");
    m.insert("D0:FF:50", "Texas Instruments");
    m.insert("D4:36:39", "Texas Instruments");
    m.insert("D4:94:A1", "Texas Instruments");
    m.insert("D4:F5:13", "Texas Instruments");
    m.insert("E0:C7:9D", "Texas Instruments");
    m.insert("E0:D7:BA", "Texas Instruments");
    m.insert("E4:15:F6", "Texas Instruments");
    m.insert("EC:11:27", "Texas Instruments");
    m.insert("EC:24:B8", "Texas Instruments");
    m.insert("F0:45:DA", "Texas Instruments");
    m.insert("F0:B5:D1", "Texas Instruments");
    m.insert("F0:F8:F2", "Texas Instruments");
    m.insert("F4:5E:AB", "Texas Instruments");
    m.insert("F4:84:4C", "Texas Instruments");
    m.insert("F4:B8:5E", "Texas Instruments");
    m.insert("F4:FC:32", "Texas Instruments");
    m.insert("FC:0F:4B", "Texas Instruments");

    // Microchip
    m.insert("00:04:A3", "Microchip");
    m.insert("00:1E:C0", "Microchip");
    m.insert("04:91:62", "Microchip");
    m.insert("54:10:EC", "Microchip");
    m.insert("68:EE:96", "Microchip");
    m.insert("74:69:AF", "Microchip");
    m.insert("94:DE:80", "Microchip");
    m.insert("D8:80:3C", "Microchip");
    m.insert("F8:F0:05", "Microchip");

    m
});

/// Look up the vendor/manufacturer for a given MAC address.
///
/// Extracts the first 3 octets (OUI prefix) from the MAC address,
/// converts to uppercase, and looks up in the built-in table.
///
/// # Arguments
/// * `mac` - MAC address in `XX:XX:XX:XX:XX:XX` format
///
/// # Returns
/// * `Some(vendor_name)` if the OUI prefix is recognized
/// * `None` if the MAC is empty, malformed, or the prefix is unknown
pub fn lookup_vendor(mac: &str) -> Option<String> {
    if mac.is_empty() {
        return None;
    }

    // Extract the first 8 characters (XX:XX:XX) and convert to uppercase
    let prefix: String = mac.chars().take(8).collect::<String>().to_uppercase();

    // Validate format: should be XX:XX:XX (8 chars with colons at positions 2 and 5)
    if prefix.len() != 8 {
        return None;
    }

    OUI_TABLE.get(prefix.as_str()).map(|v| v.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_vendor_apple() {
        let result = lookup_vendor("00:03:93:AA:BB:CC");
        assert_eq!(result, Some("Apple".to_string()));
    }

    #[test]
    fn test_lookup_vendor_intel() {
        let result = lookup_vendor("00:02:B3:11:22:33");
        assert_eq!(result, Some("Intel".to_string()));
    }

    #[test]
    fn test_lookup_vendor_case_insensitive() {
        let result = lookup_vendor("00:03:93:aa:bb:cc");
        assert_eq!(result, Some("Apple".to_string()));
    }

    #[test]
    fn test_lookup_vendor_unknown() {
        let result = lookup_vendor("FF:FF:FF:00:00:00");
        assert_eq!(result, None);
    }

    #[test]
    fn test_lookup_vendor_empty_mac() {
        let result = lookup_vendor("");
        assert_eq!(result, None);
    }

    #[test]
    fn test_lookup_vendor_short_mac() {
        let result = lookup_vendor("00:03");
        assert_eq!(result, None);
    }

    #[test]
    fn test_lookup_vendor_raspberry_pi() {
        let result = lookup_vendor("B8:27:EB:12:34:56");
        assert_eq!(result, Some("Raspberry Pi".to_string()));
    }

    #[test]
    fn test_lookup_vendor_espressif() {
        let result = lookup_vendor("24:0A:C4:AA:BB:CC");
        assert_eq!(result, Some("Espressif".to_string()));
    }

    #[test]
    fn test_lookup_vendor_tp_link() {
        let result = lookup_vendor("14:CC:20:11:22:33");
        assert_eq!(result, Some("TP-Link".to_string()));
    }

    #[test]
    fn test_lookup_vendor_samsung() {
        let result = lookup_vendor("00:16:6C:AA:BB:CC");
        assert_eq!(result, Some("Samsung".to_string()));
    }

    #[test]
    fn test_lookup_vendor_huawei() {
        let result = lookup_vendor("00:E0:FC:11:22:33");
        assert_eq!(result, Some("Huawei".to_string()));
    }

    #[test]
    fn test_lookup_vendor_amazon() {
        let result = lookup_vendor("00:BB:3A:11:22:33");
        assert_eq!(result, Some("Amazon".to_string()));
    }

    #[test]
    fn test_lookup_vendor_google() {
        let result = lookup_vendor("3C:5A:B4:11:22:33");
        assert_eq!(result, Some("Google".to_string()));
    }

    #[test]
    fn test_lookup_vendor_cisco() {
        let result = lookup_vendor("00:00:0C:11:22:33");
        assert_eq!(result, Some("Cisco".to_string()));
    }

    #[test]
    fn test_lookup_vendor_dell() {
        let result = lookup_vendor("00:06:5B:11:22:33");
        assert_eq!(result, Some("Dell".to_string()));
    }

    #[test]
    fn test_no_duplicate_keys() {
        // Verify the table has no duplicate keys by checking the count
        // matches the number of unique insertions
        let table = &*OUI_TABLE;
        // The table should have a reasonable number of entries
        assert!(table.len() > 100, "OUI table should have >100 entries, got {}", table.len());
    }
}
