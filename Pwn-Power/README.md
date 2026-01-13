# PwnPower

ESP32-C3 WiFi security audit tool with scanning, deauth attacks, handshake capture, and passive monitoring.
All controlled via a modern web interface.

## Features

### Scanning & Recon
- WiFi network scanning with vendor identification
- Station/client detection via promiscuous mode
- Hidden SSID detection and revelation
- Deauth frame detection and channel analysis
- Device tracking with timestamps

### Attacks & Capture
- Targeted deauthentication attacks
- Handshake capture with PCAP download
- Auto handshake capture (smart targeting)
- Vulnerable network scoring

### Connectivity
- Configurable AP with WPA2/WPA3 support
- Station mode with auto-reconnect
- mDNS support (`pwnpower.local`)
- NTP time sync

### Other
- Background scanning with flash storage
- CSV report generation
- Smart plug GPIO control
- OTA firmware updates
- Modern responsive web UI

## Requirements 
- ESP-IDF v5.5 or newer
- ESP32-C3

## Build and Flash
```bash
idf.py set-target esp32c3
idf.py build
idf.py flash
```

If you experience issues, try `idf.py fullclean` first.

## Usage

### Direct AP Connection
1. Connect to the `PwnPower` WiFi network (default password: `password`)
2. Open `192.168.4.1` in your browser

### Home Network Connection (mDNS)
1. Connect to PwnPower AP and open the web UI
2. Go to **Network Connection** section
3. Enter your home WiFi credentials and click Connect
4. Once connected, access via `http://pwnpower.local` from any device on your network

### Changing AP Settings
The AP SSID and password can be changed from the web UI under **AP Settings**. Changes persist across reboots.

## Web Interface
The interface is split into separate files for easier development:
- `interface/index_new.html` - HTML structure
- `interface/styles.css` - CSS styling
- `interface/app.js` - JavaScript functionality

Run `python interface/convert_multi.py` to regenerate the C arrays after modifying the UI. 


## NOTICE 

This firmware was written purely as an example, use at your own risk and responsibility, there is no guarantee for support. 

