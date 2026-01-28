# PwnPower

ESP32-C3/C5 WiFi security audit tool with scanning, deauth attacks, handshake capture, and passive monitoring.
All controlled via a modern web interface.

## Features

### Scanning & Recon
- WiFi network scanning with vendor identification
- Station/client detection via promiscuous mode
- Hidden SSID detection and revelation
- Deauth frame detection during manual and background scanning
- Device tracking with timestamps
- **Probe request fingerprinting** for advanced device identification

### Attacks & Capture
- Targeted deauthentication attacks
- Handshake capture with PCAP download
- Auto handshake capture (smart targeting)
- Vulnerable network scoring

### Connectivity
- Configurable AP with WPA2/WPA3 support
- Station mode with auto-reconnect
- mDNS support (`pwnpower.local`)
- **Automatic NTP time sync** when connected to internet

### Analytics & Monitoring
- Background scanning with flash storage
- CSV report generation and download
- Network intelligence with device presence tracking and security overview
- Network history with activity charts and analytics (7-day trends)
- Webhook alerts for device lifecycle events (arrival/departure/new devices)

### Hardware Control
- Smart plug GPIO control
- OTA firmware updates

### Web Interface
- Modern responsive web UI with collapsible sections

## Requirements
- ESP-IDF v5.5 or newer
- ESP32-C3 or ESP32-C5

## Build and Flash

### For ESP32-C3:
```bash
copy configs\sdkconfig.esp32c3 sdkconfig
copy configs\sdkconfig.esp32c3 sdkconfig.defaults
idf.py build
idf.py flash
```

### For ESP32-C5:
```bash
copy configs\sdkconfig.esp32c5 sdkconfig
copy configs\sdkconfig.esp32c5 sdkconfig.defaults
idf.py build
idf.py flash
```

#### Flashing Firmware
PwnPower uses OTA partition layouts. Use these offsets when flashing:

- Application: firmware.bin at **0x20000**
- Bootloader: bootloader.bin at **0x0** 
- Partition Table: partitions.bin at **0x8000**
- Flash Size: 4MB (ESP32-C3) or 8MB (ESP32-C5)


**Note:** ESP32-C5 supports 5GHz WiFi bands in addition to 2.4GHz, but has a smaller handshake capture buffer (16KB vs 32KB on C3).

If you experience issues, try `idf.py fullclean` first.

## Usage

### Direct AP Connection
1. Connect to the `PwnPower` WiFi network (default password: `password`)
2. Open `192.168.66.1` in your browser

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

