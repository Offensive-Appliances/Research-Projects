# Research-Projects

Research projects conducted by the Offensive Appliances team exploring hardware vulnerabilities, network security, and IoT device exploitation.

## Projects

### [PwnPower](./Pwn-Power)
ESP32-C3 WiFi security audit tool with scanning, deauth attacks, handshake capture, and passive monitoring. Features a modern web interface for network penetration testing and reconnaissance.

**Key Features:**
- WiFi network scanning with vendor identification
- Deauthentication attacks and handshake capture
- Passive monitoring and device tracking
- Web-based control interface
- OTA firmware updates

**Requirements:** ESP-IDF v5.5+, ESP32-C3

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
