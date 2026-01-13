# PwnPower Changelog

## v2.0

### Added
- AP Configuration via Web Interface
- Background Scan capabilities
- Changed to use custom partition table for extra flash storage
- Option to connect device to home network with access over mDNS (pwnpower.local)
- Smart idle detection to automatically perform deep scans and capture handshakes when device is not being used
- Added automatic OUI lookup for AP and STA vendor information
- Added automatic SNTP sync when connecting to a network for timestamping
- Added deauth detection and hidden SSID detection for background scan reports
- Added a network intelligence section to the web interface


### Changed
- Separated web interface into seperate js, css and html files
- Revised web interface styling
- Automatically populate WiFi Recon and Attack tables in the background
