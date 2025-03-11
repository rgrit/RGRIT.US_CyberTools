# 🔓 Wireless Security Toolkit  

This repository provides **WiFi security and network monitoring tools**, enabling security researchers and penetration testers to **conduct WiFi-based security assessments, detect network anomalies, and analyze packet captures**.

---

## 📡 WiFi Attack Tools  

Facilitates **WiFi deauthentication, beacon flooding, and network jamming** for security testing and penetration assessments.

| 🛠️ **Script** | 📌 **Description** |
|--------------|-----------------|
| `wifi_deauth.py` | 🚀 Sends deauthentication packets to disconnect clients from a target access point. |
| `wifi_jam.py` | 📡 Floods the channel with fake beacons using random SSIDs for network disruption. |

### **🔹 Key Features**  
✅ **Deauthentication Attacks** – Disconnects clients from a WiFi AP to test resilience.  
✅ **Beacon Flooding** – Overwhelms networks with fake SSIDs, simulating rogue AP attacks.  
✅ **Automated Execution** – Requires only a wireless adapter in **monitor mode**.  

#### **Usage Guide**  

1. **Deauthentication Attack:**  
   ```bash
   sudo python3 wifi_deauth.py --ap <AP_MAC> --target <CLIENT_MAC> --iface <INTERFACE>
   ```
   - Use `ff:ff:ff:ff:ff:ff` as `--target` to disconnect all clients.

2. **Beacon Flooding Attack:**  
   ```bash
   sudo python3 wifi_jam.py --iface <INTERFACE> --count 200
   ```
   - This floods the WiFi space with **random SSIDs** to disrupt clients.

---

## 🔍 WiFi Discovery Tools  

Helps **identify nearby networks, scan for WiFi signals, and sniff packets** for security research.

| 🛠️ **Script** | 📌 **Description** |
|--------------|-----------------|
| `wifi_signal_discovery.py` | 📊 Scans WiFi networks and generates a signal strength heatmap. |
| `wifi_packet_sniff.py` | 🕵️ Captures WiFi packets and generates a structured security report. |

### **🔹 Key Features**  
✅ **WiFi Network Discovery** – Lists nearby SSIDs, signal strength, and encryption methods.  
✅ **Packet Sniffing & Analysis** – Captures 802.11 packets for in-depth security monitoring.  
✅ **Report Generation** – Automatically produces markdown reports from packet captures.  

#### **Usage Guide**  

1. **WiFi Signal Discovery & Visualization:**  
   ```bash
   sudo python3 wifi_signal_discovery.py
   ```
   - Outputs **a markdown report & a WiFi heatmap image**.

2. **WiFi Packet Sniffing (Requires Monitor Mode):**  
   ```bash
   sudo python3 wifi_packet_sniff.py --iface <INTERFACE>
   ```
   - Captures packets for **analysis of SSIDs, BSSIDs, encryption types, and active clients**.

---

## 🛡️ Network Monitoring & Packet Sniffing  

Provides **real-time traffic monitoring, anomaly detection, and PCAP analysis** for network security assessments.

| 🛠️ **Script** | 📌 **Description** |
|--------------|-----------------|
| `sniffer.py` | 📡 Monitors network packets, detects anomalies, and saves captures for forensic analysis. |

### **🔹 Key Features**  
✅ **Packet Capture** – Captures and logs network traffic for security analysis.  
✅ **Protocol Analysis** – Identifies TCP, UDP, ICMP, DNS, HTTP traffic, and encryption usage.  
✅ **Intrusion Detection** – Alerts on SYN floods, DNS attacks, and unusual network behavior.  

#### **Usage Guide**  

1. **Run network packet sniffer:**  
   ```bash
   sudo python3 sniffer.py --interface <INTERFACE> --time 60 --output network.pcap
   ```
   - Captures packets for **60 seconds** and logs security-relevant traffic.  

2. **Detect suspicious activity:**  
   ```bash
   sudo python3 sniffer.py --interface <INTERFACE> --threshold 100
   ```
   - Generates alerts if **excessive SYN, ARP, or UDP traffic** is detected.  

---

## 🚀 **Why This Toolkit Matters**  

With modern **wireless security challenges**, security teams need **automated tools** to detect threats, simulate attacks, and analyze network behavior effectively.  

This toolkit provides:  

- 🔓 **WiFi Attack Simulation** – Deauthentication, beacon flooding, and network jamming.  
- 📡 **Wireless Network Discovery** – Scanning, signal strength visualization, and reporting.  
- 🕵️ **Advanced Network Monitoring** – Captures network packets and identifies anomalies.  

---

## 🚀 **Future Enhancements**  

🔹 **Automated MITM Attacks** – Integrate packet injection for rogue AP testing.  
🔹 **AI-based Traffic Anomaly Detection** – Detect unusual network behavior with ML models.  
🔹 **Integration with SIEMs** – Enable real-time threat monitoring for enterprise security teams.  

Stay ahead of **WiFi threats** with this **wireless security and network monitoring toolkit!** 📡🔥