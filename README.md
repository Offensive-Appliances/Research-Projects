# Research-Projects

Research projects conducted by the Offensive Appliances team exploring hardware vulnerabilities, network security, and IoT device exploitation.

## Projects

### [PwnPower](./Pwn-Power)
A compact WiFi security auditing tool built on ESP32-C3 and ESP32-C5.
Connect to the PwnPower access point and access the web interface at https://pwnpower.local.

#### Quick Start
1. Power on the device
2. Connect to WiFi: PwnPower (password: password)
3. Open browser: https://pwnpower.local
4. Complete the one-time setup wizard

#### Core Features
- **Network Scanning** - Discover nearby WiFi networks and connected clients
- **Security Testing** - Deauthentication attacks and WPA handshake capture
- **Device Tracking** - Monitor device presence with automatic trust scoring
- **Webhook Alerts** - Discord/Slack notifications for device events
- **Background Operation** - Continuous autonomous scanning and tracking
- **Smart Plug Control** - GPIO-based relay control for hardware integration

#### How It Works
PwnPower runs as a WiFi access point you connect to directly. Once connected, the web interface gives you full control over scanning, attacks, and monitoring. The device operates autonomously in the background—scanning networks, tracking devices, and sending alerts—even when you're not using the interface.

When connected to your home network, access PwnPower from any device via https://pwnpower.local. Documentation available at https://docs.hnl.cc/pwnpower/

**Requirements:** ESP-IDF v5.5+, ESP32-C3 or ESP32-C5

---

### [Hackers-Night-Light](./Hackers-Night-Light)
**LEGACY FIRMWARE:** This repository contains the original open-source firmware for Hackers Nightlight. Current production units and dev-kits use different closed-source firmware. This legacy code is provided for educational purposes and is not compatible with the latest hardware versions.

Covert penetration testing tool disguised as a smart light bulb. Demonstrates vulnerabilities in WiFi-enabled smart home devices by implanting custom firmware on ESP32-C3 microcontrollers found in commercial smart lights.

**Supported Devices:**
- Vont Smart Light Pro (SLB01, SLB02, SLB04)
- Wyze Bulb Color (WLPA19CV2)
- RAZER (coming soon)

**Capabilities:**
- PMKID capture
- Deauthentication attacks
- WPA/WPA2 handshake capture
- Packet sniffing

---

## Getting Started

Each project has its own README with detailed setup and usage instructions. Start with the project folder of interest.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on how to contribute to this repository.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md).

## License

Each project maintains its own license. See the LICENSE file in each project directory.

## Disclaimer

These projects are provided for educational and authorized security research purposes only. Unauthorized access to computer networks is illegal. Users are responsible for ensuring their use complies with all applicable laws and regulations.
