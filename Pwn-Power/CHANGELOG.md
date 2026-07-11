# PwnPower Changelog

## v2.1

### Added
- Relay GPIO state is now persisted in NVS and restored on boot, so the smart plug returns to its last state after power cycle or reboot.

### Fixed
- Removed blocking delay from the Wi-Fi disconnect event callback by deferring reconnect attempts to a timer.
- Fixed a webhook payload memory leak by ensuring JSON payload buffers are freed on all send paths.
- Replaced shared static handshake/general-capture task arguments with per-request heap arguments and task-owned cleanup.
- Reduced promiscuous deauth log spam by rate-limiting and aggregating deauth logging in background scans.
- Potentially fixed issue where device access point wouldn't come up after a promiscuous scan.
- Fixed heap corruption in the general-capture handler (`/capture`) where a static task argument was passed to a task that frees it; arguments are now heap-allocated per request and freed on task-creation failure.
- Corrected swapped `sightings`/`last_seen_epoch`/`epoch_valid` fields in the device-presence JSON response so clients receive accurate presence metadata.
- Fixed peer-discovery AP-timeout constant being defined in seconds while compared against millisecond timestamps, which caused followers to revert to leader after ~300 ms instead of 5 minutes.
- Treat `ESP_ERR_INVALID_STATE` from `esp_wifi_init()` as already-initialized so `/wifi/connect` succeeds on the normal boot path where Wi-Fi is initialized by `pwnpower.c`.
- Enforced a 1-hour maximum on handshake and general capture durations to prevent unbounded captures from removing AP access.
- Grew `known_ap_channels[]` from 64 to 100 entries to match `known_ap_bssids[]` and avoid out-of-bounds reads once more than 64 APs are learned.
- Added a minimum 2-byte length check at the top of the promiscuous sniffer to prevent out-of-bounds Frame Control reads on truncated frames.
- Account for the extra Address 4 field in four-address (WDS/mesh) data frames so EAPOL detection uses the correct LLC/EAPOL offset.
- Added CSV cell encoding in report exports to neutralize spreadsheet formula injection from SSID/vendor values.
- Fixed NVS key mismatch between `pwnpower.c` and `web_server.c` that prevented deferred background tasks (peer discovery, webhooks, background scan, idle scanner, device tracking) from starting after a reboot.
- Fixed the in-UI firmware upload form (`#ota-form`) being non-functional by implementing the missing `initOtaForm()` handler.
- Fixed setup wizard silently skipping on network error; `checkWizardStatus()` now correctly treats fetch failures as incomplete.
- Fixed blank page after completing setup wizard when a login password was set, by making `showLogin()` redirect to `/login`.
- Fixed login 401 response missing `Content-Type: application/json` header.
- Fixed deauth attack requests silently returning success when all 5 attack slots are full; now returns 503 with a clear error message.
- Fixed login page silently swallowing connection errors; now shows "Unable to connect to device" on fetch failure.
- Added confirmation dialog before forgetting a saved Wi-Fi network.
- Fixed WiFi connect failure during setup wizard being silently ignored; wizard now stops and shows the error instead of claiming success.
- Fixed `toggleBottleneckDetails()` relying on an implicit `event` global, which broke in Firefox and Safari.
- Fixed duplicate `Set-Cookie` header on login and added `SameSite=Strict` to the auth cookie.
- Fixed wizard state not being reset when re-entering the wizard, which could leave it on a stale step.

### Changed
- Grew OTA partitions from 0x190000 to 0x1A0000 each (scandata shrunk from 0xC0000 to 0xA0000) to accommodate the larger ESP-IDF v6.0 binary on 4MB flash.
- Reduced static JSON buffer allocations by ~14KB RAM (report_json, intelligence_json, device_presence_buf, unified_buf).
- Reduced background scan temp_stations buffer from 128 to 64 entries (~900 bytes saved).
- `showToast()` now accepts an optional type parameter (`'error'`, `'warning'`, `'success'`) with a colored left border to distinguish severity.
- Removed verbose `console.log`/`console.trace` debug statements from production scan code.
- Migrated build system to ESP-IDF v6.0.

## v2.0

### Added
- Secure login flow with token-based API protection for the web UI
- Privacy mode toggle to censor PII (MACs, SSIDs, vendors) for demos and content creation
- Configuration of onboard WiFi AP
- Option to connect device to home network with access over mDNS (pwnpower.local)
- Device will automatically perform deep scans and capture handshakes when device is not being used
- Added automatic OUI lookup for AP and STA vendor information
- Added automatic SNTP sync when connecting to a network for timestamping
- Added a network intelligence section with:
  - Deauths seen
  - Rouge APs detected
  - Persistent device tracking
  - Network bottleneck analysis
- Added a Network History section with:
  - AP and STA history
  - Channel congestion history
- Added ability to send configurable alerts to a webhook
- Enabled HTTPS with on-device self-signed cert
- Added mDNS support for pwnpower.local on PwnPower AP
- Added a first time boot setup wizard
- Added support for the ESP32-C5
- Added a recovery system to clear NVS and Storage partition on 5 rapid power cycles
- Added peer discovery to switch between multiple devices on a home network from one interface
- Added limiting so you can't select clients on different channels

### Changed
- Merged WiFi Recon and Attack sections into a single section
- Changed to use custom partition table for extra flash storage
- Separated web interface into seperate js, css and html files
- Revised web interface styling
- Changed SoftAP IP to 192.168.66.1 to prevent conflicts with STA connection

## v1.0

### Added

- Web UI
- Deauthentication and disassociation attack
- Passive handshake capture (EAPOL detection) and general 802.11 capture with in-memory PCAP export (handshake.pcap)
- OTA Firmware upload
- Simple smart-plug GPIO control endpoints
