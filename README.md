# 📡 LAN Watch: Advanced Network & Bluetooth Scanner

**LAN Watch** is a dual-interface network discovery tool designed to bridge the gap between theoretical networking and practical application. It lists nearby Wi-Fi networks (SSIDs), uses low-level **ARP packet crafting** to find devices on the connected LAN, and performs asynchronous **Bluetooth Low Energy (BLE)** scanning.


## 🚀 Key Features
* **📶 Nearby Wi-Fi Discovery:** Lists nearby wireless networks (SSIDs) using the Windows WLAN service.
* **🖥️ LAN Device Discovery:** Uses raw **ARP (Address Resolution Protocol)** packets to identify active devices on the connected Wi-Fi subnet (IP & MAC addresses).
* **🔵 Bluetooth Scanning:** Integrated **Bleak** library to asynchronously detect nearby BLE peripherals (Headphones, IoT, Wearables).
* **🏷️ Smart Hostname Resolution:** Automatically performs **Reverse DNS lookups** to resolve IP addresses to human-readable device names (e.g., "Desktop-PC", "iPhone").
* **🖥️ Dual-Mode Interface:**
    * **Dashboard Mode:** A modern, reactive GUI built with **Streamlit**.
    * **CLI Mode:** A lightweight, text-based scanner for quick terminal checks.
* **⚡ Zero-Configuration:** Automatically detects the host's network range (Subnet) without manual input.

## 🛠️ Tech Stack
| Component | Technology | Description |
| :--- | :--- | :--- |
| **Core Logic** | Python 3.x | Main programming language. |
| **Network Layer** | **Scapy** | For crafting and sending raw ARP broadcast packets. |
| **Bluetooth** | **Bleak** | For asynchronous Bluetooth Low Energy (BLE) scanning. |
| **Frontend** | **Streamlit** | For the interactive web-based dashboard. |
| **Data Handling** | Pandas | For structuring scan results into sortable tables. |

## 📸 Usage

### Option 1: The Dashboard (GUI)
Launch the interactive web interface to visualize and sort network data.
```bash
streamlit run lan_watch_dashboard.py

```

### Option 2: Command Line Scanner

Run the standalone script for a fast, text-only scan.
*Note: Requires Administrator/Root privileges to send raw packets.*

```bash
python lan_watch_scanner.py

```

## 🔧 Installation

**1. Clone the Repository**

```bash
git clone https://github.com/Kronos237/LAN-Watch-project.git
cd LAN-Watch-project

```

**2. Install Dependencies**

```bash
pip install -r requirements.txt

```

> **Windows Users:** You must install [Npcap](https://npcap.com/) (select "Install with WinPcap API-compatible Mode") for Scapy to work correctly.

## 🧠 How It Works

1. **Range Detection:** The script executes system commands (e.g., `ipconfig`) to parse the active IPv4 address and Subnet Mask.
2. **Wi-Fi Radio Scan:** On Windows, it runs `netsh wlan show networks mode=bssid` to list nearby SSIDs.
3. **ARP Broadcasting:** It constructs a custom ARP Request packet ("Who has this IP?") and broadcasts it to the connected subnet (`ff:ff:ff:ff:ff:ff`). Active devices reply with their MAC address.
4. **Bluetooth Sniffing:** The `BleakScanner` listens for BLE advertisement packets to find nearby wireless peripherals.
5. **Enrichment:** The system queries the local DNS resolver to find the Hostname associated with each discovered IP.

## 🔮 Future Roadmap

* **Vendor Identification:** Integrate OUI (Organizationally Unique Identifier) lookup to identify device manufacturers (e.g., Apple, Samsung).
* **OS Fingerprinting:** Analyze packet TTL and window sizes to guess the operating system.
* **Continuous Monitoring:** Add a background mode to alert users when a new, unknown device joins the network.


---
