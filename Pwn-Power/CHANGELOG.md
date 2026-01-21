# PwnPower Changelog

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

### Changed
- Merged WiFi Recon and Attack sections into a single section
- Changed to use custom partition table for extra flash storage
- Separated web interface into seperate js, css and html files
- Revised web interface styling
- Increased AP storage limit from 16 to 32 networks per scan


## v1.0

### Added

- Web UI
- Deauthentication and disassociation attack
- Passive handshake capture (EAPOL detection) and general 802.11 capture with in-memory PCAP export (handshake.pcap)
- OTA Firmware upload
- Simple smart-plug GPIO control endpoints
