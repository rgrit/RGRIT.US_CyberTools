# 🚀 RGRIT CyberTools 🔥


# 🚨 Disclaimer

**Educational & Research Purposes Only**  
All content provided in this repository is strictly for educational and research purposes. Users must adhere to ethical and legal guidelines when utilizing any scripts, tools, or resources contained herein.

**Ethical and Legal Responsibility**  
You are solely responsible for ensuring that your use of these materials complies with all applicable laws and ethical standards. Unauthorized or malicious use is strictly prohibited and may result in legal action.

**No Warranty**  
All scripts, tools, and documentation are provided "as-is" without any warranty. The authors and contributors assume no responsibility for any consequences arising from the use or misuse of these resources.

By using this repository, you acknowledge and agree to these terms.


## Recent Updates (2025-03-15)

- 🆕 **Added** `Flipper_Zero/flipper_rf_lock.py`
- 🆕 **Added** `Flipper_Zero/rf_auto_scan_decode.py`
- 🆕 **Added** `Flipper_Zero/flipper_log_rf.py`
- 🆕 **Added** `Flipper_Zero/flipper_rf_scan_log.py`
- 🆕 **Added** `wigle_wifi_android/plot_groups_of_devices.py`
- 🆕 **Added** `wigle_wifi_android/frequency_plot.py`
- 🆕 **Added** `wigle_wifi_android/11_meter_grouping.py`
- 🆕 **Added** `wigle_wifi_android/signal_strength_heatmap.py`
- 🆕 **Added** `wigle_wifi_android/new_thing.py`
- 🆕 **Added** `wigle_wifi_android/weak_auth.py`
- 🆕 **Added** `wigle_wifi_android/authmode_wildcard_drilldown.py`
- 🆕 **Added** `wigle_wifi_android/data_pre-processing.py`
- 🆕 **Added** `wigle_wifi_android/geospatial_mapping.py`
- 🆕 **Added** `RTL-SDRv4/discover_stuff.py`
- 🆕 **Added** `RTL-SDRv4/detect_analyze_broad_spectrum.py`

## Repository Overview

### 📁 `11_meter_grouping.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `wigle_wifi_android/11_meter_grouping.py` | **WiFi SSID analysis script** | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/wigle_wifi_android/11_meter_grouping.py) |

### 📁 `CTI_and_Detection` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `OSINT_Scripts/CTI_and_Detection/rss_feed_mgmt_csv_to_OPML.py` | Converts CSV to OPML, mapping blog names and RSS links. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_mgmt_csv_to_OPML.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/analysis/text_analysis.py` | Summarizes articles with cyber threat intelligence and detection engineering insights. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/analysis/text_analysis.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/analysis/threat_analysis.py` | The provided code appears to be a collection of functions related to cybersecurity threat detection and analysis. Here is a high-level de... | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/analysis/threat_analysis.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/config.py` | Config file for RSS and API settings, with time handling and file paths. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/config.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/heatmap_generator.py` | Extracts MITRE codes from markdown files and generates a heatmap JSON file. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/heatmap_generator.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/main.py` | Fetches RSS feed, analyzes articles for threats, extracts IoCs, and generates reports. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/main.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/reporting/report_generator.py` | **Threat Intelligence Report Generator**
======================================

This script generates a Markdown report for a single thr... | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/reporting/report_generator.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/api_utils.py` | Queries LLaMA API with retries, handling timeouts and exceptions. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/api_utils.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/file_utils.py` | Loads/saves article IDs from/to a JSON file. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/file_utils.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/rss_utils.py` | Fetches and parses an RSS feed from a given URL, handling exceptions. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/rss_utils.py) |

### 📁 `Email` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Blue_Team_Scripts/Email/email_generate_sigma.py` | Extracts IoCs from email reports & generates Sigma rules. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Blue_Team_Scripts/Email/email_generate_sigma.py) |
| `Blue_Team_Scripts/Email/email_grab_attachments.py` | Extracts email attachments from Thunderbird IMAP storage, saving them locally and generating a Markdown report with metadata. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Blue_Team_Scripts/Email/email_grab_attachments.py) |
| `Blue_Team_Scripts/Email/email_list_senders.py` | Extracts email sender addresses from Thunderbird IMAP mailboxes. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Blue_Team_Scripts/Email/email_list_senders.py) |
| `Blue_Team_Scripts/Email/email_overview.py` | Analyzes Thunderbird emails for immediate action requirements using LLMs. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Blue_Team_Scripts/Email/email_overview.py) |
| `Blue_Team_Scripts/Email/email_security_report.py` | Analyzes email metadata for security threats using Ollama Python module. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Blue_Team_Scripts/Email/email_security_report.py) |

### 📁 `Purple_Team_Lab_Infra_As_Code` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Ansible/Purple_Team_Lab_Infra_As_Code/deploy_vms.yml` | Creates VMs on Proxmox with specified resources and ISOs. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Ansible/Purple_Team_Lab_Infra_As_Code/deploy_vms.yml) |
| `Ansible/Purple_Team_Lab_Infra_As_Code/download-proxmox-isos.yml` | Downloads specified ISOs to Proxmox ISO storage. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Ansible/Purple_Team_Lab_Infra_As_Code/download-proxmox-isos.yml) |
| `Ansible/Purple_Team_Lab_Infra_As_Code/hosts.yml` | Defines Ansible host config for Proxmox server, specifying connection and API details. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Ansible/Purple_Team_Lab_Infra_As_Code/hosts.yml) |
| `Ansible/Purple_Team_Lab_Infra_As_Code/proxmox-initial-setup.yml` | "Sets up Proxmox server, removes enterprise repos, enables non-enterprise repo, installs packages, and configures NIC passthrough." | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Ansible/Purple_Team_Lab_Infra_As_Code/proxmox-initial-setup.yml) |

### 📁 `Secure_Code_Review` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Blue_Team_Scripts/Secure_Code_Review/scan_for_credentials.py` | Analyzes Python files for security vulnerabilities using Ollama LLM. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Blue_Team_Scripts/Secure_Code_Review/scan_for_credentials.py) |

### 📁 `authmode_wildcard_drilldown.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `wigle_wifi_android/authmode_wildcard_drilldown.py` | **Generates a deep dive report from CSV data based on wildcard AuthMode search.** | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/wigle_wifi_android/authmode_wildcard_drilldown.py) |

### 📁 `check_cluster_healthy.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Elastic/check_cluster_healthy.py` | Connects to Elasticsearch cluster, checks health and prints result or error. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Elastic/check_cluster_healthy.py) |

### 📁 `convert_to_ducky.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Ducky_Scripts/convert_to_ducky.py` | Encodes Ducky Scripts (.txt) to binary payloads (.bin) using java-based duckencoder. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Ducky_Scripts/convert_to_ducky.py) |

### 📁 `correlation_lnx_syslog_flipper_badusb_repeated_enumeration.yml` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Custom_Sigma_Rules/correlation_lnx_syslog_flipper_badusb_repeated_enumeration.yml` | Detects potential BadUSB attacks using Flipper Zero via repeated USB insertion events. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Custom_Sigma_Rules/correlation_lnx_syslog_flipper_badusb_repeated_enumeration.yml) |

### 📁 `data_pre-processing.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `wigle_wifi_android/data_pre-processing.py` | **Loads Wigle Wi-Fi network CSV data into a pandas DataFrame.** | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/wigle_wifi_android/data_pre-processing.py) |

### 📁 `detect_analyze_broad_spectrum.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `RTL-SDRv4/detect_analyze_broad_spectrum.py` | **Plots raw and smoothed signal amplitudes from a CSV file.** | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/RTL-SDRv4/detect_analyze_broad_spectrum.py) |

### 📁 `discover_stuff.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `RTL-SDRv4/discover_stuff.py` | **RTL-SDR script to scan and capture 2.4GHz signals** | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/RTL-SDRv4/discover_stuff.py) |

### 📁 `file_integrity_monitoring` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Blue_Team_Scripts/file_integrity_monitoring/file_integrity_monitor.py` | The provided code is for a graphical user interface (GUI) application that allows users to create and manage file system baselines, as we... | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Blue_Team_Scripts/file_integrity_monitoring/file_integrity_monitor.py) |

### 📁 `flipper_log_rf.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Flipper_Zero/flipper_log_rf.py` | **Flipper Zero serial listener script** | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Flipper_Zero/flipper_log_rf.py) |

### 📁 `flipper_rf_lock.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Flipper_Zero/flipper_rf_lock.py` | **RF signal scanner using Flipper device** | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Flipper_Zero/flipper_rf_lock.py) |

### 📁 `flipper_rf_scan_log.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Flipper_Zero/flipper_rf_scan_log.py` | **RF signal scanner using Flipper Zero device** | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Flipper_Zero/flipper_rf_scan_log.py) |

### 📁 `frequency_plot.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `wigle_wifi_android/frequency_plot.py` | **Wi-Fi network analyzer script** | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/wigle_wifi_android/frequency_plot.py) |

### 📁 `geospatial_mapping.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `wigle_wifi_android/geospatial_mapping.py` | Creates interactive Wi-Fi network maps with filters from Wigle CSV data. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/wigle_wifi_android/geospatial_mapping.py) |

### 📁 `lnx_syslog_flipper_badusb_identifiers.yml` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Custom_Sigma_Rules/lnx_syslog_flipper_badusb_identifiers.yml` | Detects Flipper Zero BadUSB devices via unusual USB identifiers. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Custom_Sigma_Rules/lnx_syslog_flipper_badusb_identifiers.yml) |

### 📁 `lnx_syslog_flipper_badusb_inconsistent_branding.yml` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Custom_Sigma_Rules/lnx_syslog_flipper_badusb_inconsistent_branding.yml` | Detects Flipper Zero BadUSB devices with inconsistent branding. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Custom_Sigma_Rules/lnx_syslog_flipper_badusb_inconsistent_branding.yml) |

### 📁 `network_monitoring` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Network_Security/network_monitoring/sniffer.py` | **Extended Packet Sniffer GUI Application**

This is a graphical user interface (GUI) application for an extended packet sniffer. The app... | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Network_Security/network_monitoring/sniffer.py) |

### 📁 `new_thing.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `wigle_wifi_android/new_thing.py` | **Wi-Fi network visualizer with distance calculations.** | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/wigle_wifi_android/new_thing.py) |

### 📁 `plot_groups_of_devices.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `wigle_wifi_android/plot_groups_of_devices.py` | **Bluetooth Device Clustering Script** | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/wigle_wifi_android/plot_groups_of_devices.py) |

### 📁 `rf_auto_scan_decode.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Flipper_Zero/rf_auto_scan_decode.py` | **RF frequency scanner using Flipper device** | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Flipper_Zero/rf_auto_scan_decode.py) |

### 📁 `signal_strength_heatmap.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `wigle_wifi_android/signal_strength_heatmap.py` | **Wi-Fi RSSI heatmap generator** | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/wigle_wifi_android/signal_strength_heatmap.py) |

### 📁 `virusTotalAPI` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Malware_Analysis/virusTotalAPI/virus_total_scan.py` | VirusTotal API scanner for IOCs, loading keys & querying VT database. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Malware_Analysis/virusTotalAPI/virus_total_scan.py) |

### 📁 `weak_auth.py` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `wigle_wifi_android/weak_auth.py` | **Identifies & reports WiFi networks using weak authentication (open/WEP).** | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/wigle_wifi_android/weak_auth.py) |

### 📁 `wireless_security` Directory
| 📄 **Script Name** | **Description** | **Link** |
|-----------------|---------------|--------|
| `Network_Security/wireless_security/WiFi_Discover/wifi_packet_sniff.py` | **WiFi Packet Sniffing and Analysis Script**
=============================================

This script is designed to capture and analyz... | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Network_Security/wireless_security/WiFi_Discover/wifi_packet_sniff.py) |
| `Network_Security/wireless_security/WiFi_Discover/wifi_signal_discovery.py` | Scans nearby WiFi, plots signal strengths, and generates a report. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Network_Security/wireless_security/WiFi_Discover/wifi_signal_discovery.py) |
| `Network_Security/wireless_security/Wifi_Attack/wifi_deauth.py` | WiFi deauthentication attack script sending spoofed packets. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Network_Security/wireless_security/Wifi_Attack/wifi_deauth.py) |
| `Network_Security/wireless_security/Wifi_Attack/wifi_jam.py` | WiFi beacon flooding attack script. Sends fake beacons with random SSIDs/BSSIDs. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Network_Security/wireless_security/Wifi_Attack/wifi_jam.py) |
