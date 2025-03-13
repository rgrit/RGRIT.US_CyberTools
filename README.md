
# 🚀 **RGRIT CyberTools** 🔥  
**The Ultimate Cybersecurity Toolkit** – Built for **Hackers, Defenders, and Cyber Warriors**.  

# Disclaimer

**Educational & Research Purposes Only**  
Everything in this repository is provided solely for educational and research purposes. The demos, scripts, and materials are intended to demonstrate security practices and generative AI (GenAI) skills in a lawful, ethical, and responsible manner.

**Ethical & Legal Use**  
All content is designed for users to explore and learn. It is your responsibility to ensure that any use of these materials complies with all applicable laws, regulations, and ethical standards. This repository does not endorse or encourage any malicious or unauthorized activities.

**AI-Generated Content**  
Approximately **99%** of the content in this repository has been generated using advanced AI tools. This reflects the significant role that generative AI plays in the creation of these materials, showcasing modern capabilities in the field.

**No Warranty**  
The content is provided "as-is," without any warranty—express or implied. The authors are not responsible for any misuse or consequences arising from the use of this material.

By using this repository, you agree to the above terms and acknowledge that you are solely responsible for ensuring the ethical and legal application of the information provided.  
🔗 **[Explore the Repo](https://github.com/rgrit/RGRIT.US_CyberTools)**  

## Recent Updates (as of 2025-03-13)
- 🆕 **Added** `Ansible/Purple_Team_Lab_Infra_As_Code/deploy_vms.yml`
- 🆕 **Added** `Ansible/Purple_Team_Lab_Infra_As_Code/download-proxmox-isos.yml`
- 🆕 **Added** `Ansible/Purple_Team_Lab_Infra_As_Code/hosts.yml`
- 🆕 **Added** `Ansible/Purple_Team_Lab_Infra_As_Code/proxmox-initial-setup.yml`
- 🆕 **Added** `Auto_Documetation/auto_readme.py`
- 🆕 **Added** `Blue_Team_Scripts/Email/email_generate_sigma.py`
- 🆕 **Added** `Blue_Team_Scripts/Email/email_grab_attachments.py`
- 🆕 **Added** `Blue_Team_Scripts/Email/email_list_senders.py`
- 🆕 **Added** `Blue_Team_Scripts/Email/email_overview.py`
- 🆕 **Added** `Blue_Team_Scripts/Email/email_security_report.py`
- 🆕 **Added** `Blue_Team_Scripts/Secure_Code_Review/scan_for_credentials.py`
- 🆕 **Added** `Blue_Team_Scripts/file_integrity_monitoring/file_integrity_monitor.py`
- 🆕 **Added** `Custom_Sigma_Rules/correlation_lnx_syslog_flipper_badusb_repeated_enumeration.yml`
- 🆕 **Added** `Custom_Sigma_Rules/lnx_syslog_flipper_badusb_identifiers.yml`
- 🆕 **Added** `Custom_Sigma_Rules/lnx_syslog_flipper_badusb_inconsistent_branding.yml`
- 🆕 **Added** `Ducky_Scripts/convert_to_ducky.py`
- 🆕 **Added** `Elastic/check_cluster_healthy.py`
- 🆕 **Added** `Malware_Analysis/virusTotalAPI/virus_total_scan.py`
- 🆕 **Added** `Network_Security/network_monitoring/sniffer.py`
- 🆕 **Added** `Network_Security/wireless_security/WiFi_Discover/wifi_packet_sniff.py`
- 🆕 **Added** `Network_Security/wireless_security/WiFi_Discover/wifi_signal_discovery.py`
- 🆕 **Added** `Network_Security/wireless_security/Wifi_Attack/wifi_deauth.py`
- 🆕 **Added** `Network_Security/wireless_security/Wifi_Attack/wifi_jam.py`
- 🆕 **Added** `OSINT_Scripts/CTI_and_Detection/rss_feed_mgmt_csv_to_OPML.py`
- 🆕 **Added** `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/analysis/text_analysis.py`
- 🆕 **Added** `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/analysis/threat_analysis.py`
- 🆕 **Added** `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/config.py`
- 🆕 **Added** `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/heatmap_generator.py`
- 🆕 **Added** `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/main.py`
- 🆕 **Added** `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/reporting/report_generator.py`
- 🆕 **Added** `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/api_utils.py`
- 🆕 **Added** `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/file_utils.py`
- 🆕 **Added** `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/rss_utils.py`

## Repository Overview
Below is an overview of all Python and YAML scripts organized by the second-level directory:

### 📁 `CTI_and_Detection/` Directory
| 📄 **Script Name** | **Description** | **Link** |
| ----------------- | --------------- | -------- |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_mgmt_csv_to_OPML.py` | CSV to OPML converter. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_mgmt_csv_to_OPML.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/analysis/text_analysis.py` | Summarizes articles with cybersecurity focus. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/analysis/text_analysis.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/analysis/threat_analysis.py` | This code appears to be a collection of functions designed to analyze and generate content related to cybersecurity, specifically threat detection and analysis. The functions seem to be focused on generating text based on input summaries, suggesting Sigma tags, and creating detection stories.  Here is a high-level overview of the code:  1. **Threat Analysis Functions**:    - `identify_threats()`: Not shown in this snippet, but presumably identifies potential threats based on input.    - `assess_vulnerabilities()`: Also not shown, likely assesses vulnerabilities related to identified threats.  2. **Content Generation Functions**:    - `generate_detection_story(summary_text)`: Creates a structured detection story including context, assumptions, detection approach, evaluation, and limitations.    - `suggest_sigma_tags(summary_text, analysis_details=None)`: Recommends Sigma tags based on the input summary and additional analysis details if provided.  3. **Sigma Tag Suggestion**:    - The `suggest_sigma_tags` function uses a prompt to guide the suggestion of Sigma tags according to the Sigma Tag Specification (Version 2.1.0). It considers various namespaces like attack, car, cve, d3fend, detection, stp, and tlp.  4. **Detection Approach and Evaluation**:    - The detection approach seems to involve analyzing log source references mentioned in the input text and comparing them with known patterns of malicious activity.    - Evaluation metrics such as precision, recall, and F1 score are used to assess the effectiveness of the detection approach.  5. **Limitations and Future Improvements**:    - The code acknowledges limitations, particularly regarding the accuracy of log source references and suggests future improvements like incorporating additional data sources or using more advanced machine learning algorithms.  6. **API Interaction**:    - Functions like `call_ollama_api_with_retry` (not shown in this snippet) are used to interact with an API, presumably for generating text based on prompts or retrieving relevant information for analysis.  To write similar code, you would need to focus on the following steps:  1. **Define Your Analysis Functions**: Create functions that can analyze input summaries and identify potential threats or vulnerabilities. 2. **Develop Content Generation Logic**: Design logic to generate structured content like detection stories based on analysis results. 3. **Implement Sigma Tag Suggestion**: Follow the Sigma Tag Specification to suggest relevant tags for given scenarios. 4. **Integrate with API for Text Generation**: If applicable, use APIs to generate text or retrieve necessary information for your analysis and content generation tasks.  Remember, this code snippet seems to be part of a larger system, possibly involving machine learning models or extensive cybersecurity databases for threat intelligence. Replicating its functionality would require access to similar resources or the development of equivalent capabilities. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/analysis/threat_analysis.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/config.py` | Configures API and file paths for email report generation. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/config.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/heatmap_generator.py` | Extracts MITRE codes from markdown files. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/heatmap_generator.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/main.py` | Fetches and analyzes threat intel articles. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/main.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/reporting/report_generator.py` | It seems like you provided a large chunk of code that appears to be a Python script for generating threat intelligence reports in Markdown format. The code includes functions for sanitizing filenames, creating individual reports, and writing report content to files.  However, it looks like the code was truncated, and there's no specific question or problem statement provided. Could you please clarify what you need help with? Are you trying to:  1. Fix an issue with the existing code? 2. Understand how a particular part of the code works? 3. Add new functionality to the script? 4. Something else?  Please provide more context or information about your question, and I'll do my best to assist you. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/reporting/report_generator.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/api_utils.py` | Queries LLaMA API with retries. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/api_utils.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/file_utils.py` | Loads/saves article IDs to/from JSON file. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/file_utils.py) |
| `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/rss_utils.py` | Fetches and parses an RSS feed from a given URL. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/utils/rss_utils.py) |

### 📁 `Email/` Directory
| 📄 **Script Name** | **Description** | **Link** |
| ----------------- | --------------- | -------- |
| `Blue_Team_Scripts/Email/email_generate_sigma.py` | Email report analyzer & Sigma rule generator. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Blue_Team_Scripts/Email/email_generate_sigma.py) |
| `Blue_Team_Scripts/Email/email_grab_attachments.py` | Extracts email attachments from Thunderbird IMAP storage. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Blue_Team_Scripts/Email/email_grab_attachments.py) |
| `Blue_Team_Scripts/Email/email_list_senders.py` | Extracts email senders from Thunderbird IMAP mailboxes. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Blue_Team_Scripts/Email/email_list_senders.py) |
| `Blue_Team_Scripts/Email/email_overview.py` | Analyzes emails for immediate action requirements. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Blue_Team_Scripts/Email/email_overview.py) |
| `Blue_Team_Scripts/Email/email_security_report.py` | Email security analyzer using LLMs. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Blue_Team_Scripts/Email/email_security_report.py) |

### 📁 `Purple_Team_Lab_Infra_As_Code/` Directory
| 📄 **Script Name** | **Description** | **Link** |
| ----------------- | --------------- | -------- |
| `Ansible/Purple_Team_Lab_Infra_As_Code/deploy_vms.yml` | Creates VMs on Proxmox with specified resources. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Ansible/Purple_Team_Lab_Infra_As_Code/deploy_vms.yml) |
| `Ansible/Purple_Team_Lab_Infra_As_Code/download-proxmox-isos.yml` | Downloads ISOs to Proxmox. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Ansible/Purple_Team_Lab_Infra_As_Code/download-proxmox-isos.yml) |
| `Ansible/Purple_Team_Lab_Infra_As_Code/hosts.yml` | Proxmox host config for Ansible. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Ansible/Purple_Team_Lab_Infra_As_Code/hosts.yml) |
| `Ansible/Purple_Team_Lab_Infra_As_Code/proxmox-initial-setup.yml` | Sets up Proxmox server. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Ansible/Purple_Team_Lab_Infra_As_Code/proxmox-initial-setup.yml) |

### 📁 `Secure_Code_Review/` Directory
| 📄 **Script Name** | **Description** | **Link** |
| ----------------- | --------------- | -------- |
| `Blue_Team_Scripts/Secure_Code_Review/scan_for_credentials.py` | Scans Python files for security vulnerabilities using Ollama LLM. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Blue_Team_Scripts/Secure_Code_Review/scan_for_credentials.py) |

### 📁 `auto_readme.py/` Directory
| 📄 **Script Name** | **Description** | **Link** |
| ----------------- | --------------- | -------- |
| `Auto_Documetation/auto_readme.py` | It appears you've provided a script designed to generate and update a README file for a GitHub repository. The script is quite extensive and performs several tasks:  1. **Scans the Repository**: It scans the repository for Python and YAML files, organizing them by their second-level directory. 2. **Generates Descriptions**: For each file found, it attempts to generate a description using an AI model (though the specifics of how this is done aren't detailed in the script snippet you provided). 3. **Compares with Previous State**: It compares the current state of files and their descriptions with a previous state stored in a history file to detect changes. 4. **Constructs README Content**: Based on the organized files, their descriptions, and detected changes, it constructs the content for a README file. This includes sections for recent updates, repository overview, and detailed listings of scripts by directory. 5. **Saves README and History**: Finally, it saves the generated README content to a specified location within the repository and updates the history file with the current state of descriptions.  To address your request for a "description," I'll provide an overview that could serve as a concise summary or abstract of the script's functionality:  **Script Overview**  This script automates the generation and maintenance of a GitHub repository's README file. It organizes Python and YAML scripts by directory, generates descriptions using AI, tracks changes, and constructs a detailed README with recent updates, repository overviews, and script listings. The script ensures the README remains up-to-date and reflective of the repository's current state, facilitating easier navigation and understanding for users.  If you're looking to modify or extend this script, focusing on areas like improving description generation accuracy, enhancing change detection logic, or incorporating additional repository insights could be beneficial. However, without more specific requirements or questions about the script, it's challenging to provide a more targeted response. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Auto_Documetation/auto_readme.py) |

### 📁 `check_cluster_healthy.py/` Directory
| 📄 **Script Name** | **Description** | **Link** |
| ----------------- | --------------- | -------- |
| `Elastic/check_cluster_healthy.py` | Checks Elasticsearch cluster health. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Elastic/check_cluster_healthy.py) |

### 📁 `convert_to_ducky.py/` Directory
| 📄 **Script Name** | **Description** | **Link** |
| ----------------- | --------------- | -------- |
| `Ducky_Scripts/convert_to_ducky.py` | Encodes Ducky scripts to binary. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Ducky_Scripts/convert_to_ducky.py) |

### 📁 `correlation_lnx_syslog_flipper_badusb_repeated_enumeration.yml/` Directory
| 📄 **Script Name** | **Description** | **Link** |
| ----------------- | --------------- | -------- |
| `Custom_Sigma_Rules/correlation_lnx_syslog_flipper_badusb_repeated_enumeration.yml` | Detects repeated Flipper Zero BadUSB insertions. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Custom_Sigma_Rules/correlation_lnx_syslog_flipper_badusb_repeated_enumeration.yml) |

### 📁 `file_integrity_monitoring/` Directory
| 📄 **Script Name** | **Description** | **Link** |
| ----------------- | --------------- | -------- |
| `Blue_Team_Scripts/file_integrity_monitoring/file_integrity_monitor.py` | It appears that you've posted a large portion of code for a GUI application in Python using the Tkinter library. The application seems to be designed for file integrity monitoring, allowing users to select directories, create baselines, and check for changes.  However, it looks like the code is incomplete, as there are some missing parts (e.g., the `handle_check` method and the completion of the `handle_baseline` method). Additionally, there's no clear question or problem statement provided.  If you could provide more context or specify what you'd like help with, I'll be happy to assist. Here are a few potential areas where I can offer guidance:  1. **Completing the code**: If you provide the missing parts of the code, I can help you fill in the gaps and ensure that everything works as expected. 2. **Troubleshooting issues**: If you're experiencing specific problems or errors with the current implementation, please describe them, and I'll do my best to help you resolve them. 3. **Improving the design**: If you'd like feedback on the overall structure and organization of your code, I can offer suggestions for improvement.  Please let me know how I can assist you further!   Here is a more complete version of the `handle_baseline` method: ```python def handle_baseline(self):     if not self.selected_directory:         messagebox.showerror("Error", "Please select a directory first.")         return      baseline_file_name = f"baseline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"     create_result = create_baseline(self.selected_directory, baseline_file_name, lambda msg: self.log(msg))     if create_result:         self.add_baseline_radio(baseline_file_name)         self.log(f"Baseline created successfully: {baseline_file_name}")     else:         self.log("Failed to create baseline.") ``` And here is a complete version of the `handle_check` method: ```python def handle_check(self):     selected_baseline = self.selected_baseline_var.get()     if not selected_baseline:         messagebox.showerror("Error", "Please select a baseline file first.")         return      if not self.selected_directory:         messagebox.showerror("Error", "Please select a directory first.")         return      check_result, changes = check_integrity(self.selected_directory, selected_baseline, lambda msg: self.log(msg))     if check_result:         self.log(f"Integrity check completed successfully for {selected_baseline}.")         # Update the history table with new changes         self.update_history_table(changes)     else:         self.log("Failed to perform integrity check.") ``` I hope this helps! Let me know if you have any questions or need further assistance. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Blue_Team_Scripts/file_integrity_monitoring/file_integrity_monitor.py) |

### 📁 `lnx_syslog_flipper_badusb_identifiers.yml/` Directory
| 📄 **Script Name** | **Description** | **Link** |
| ----------------- | --------------- | -------- |
| `Custom_Sigma_Rules/lnx_syslog_flipper_badusb_identifiers.yml` | Detects Flipper Zero BadUSB devices via USB events. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Custom_Sigma_Rules/lnx_syslog_flipper_badusb_identifiers.yml) |

### 📁 `lnx_syslog_flipper_badusb_inconsistent_branding.yml/` Directory
| 📄 **Script Name** | **Description** | **Link** |
| ----------------- | --------------- | -------- |
| `Custom_Sigma_Rules/lnx_syslog_flipper_badusb_inconsistent_branding.yml` | Detects masquerading BadUSB device. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Custom_Sigma_Rules/lnx_syslog_flipper_badusb_inconsistent_branding.yml) |

### 📁 `network_monitoring/` Directory
| 📄 **Script Name** | **Description** | **Link** |
| ----------------- | --------------- | -------- |
| `Network_Security/network_monitoring/sniffer.py` | The provided code appears to be a part of a network packet capture tool. It's written in Python and utilizes the Scapy library for packet capture and manipulation. Here's a breakdown of the code:  **Packet Capture Functionality**  1. The code initializes several variables, including `capture_running`, `capture_start_time`, `capture_duration`, and others. 2. It defines a function to log messages (`log_callback`) and another to update the progress bar (`update_progress`). 3. The main packet capture functionality is implemented in an unnamed function ( likely a callback or event handler). This function: 	* Captures packets using Scapy's `sniff()` function. 	* Analyzes the captured packets, extracting various statistics such as TCP, UDP, ICMP, and ARP packet counts. 	* Checks for unusual network activity based on predefined thresholds (e.g., high packet rates, unusual protocol usage). 	* Logs the results, including any detected unusual activity. 	* Saves the captured packets to a PCAP file using Scapy's `wrpcap()` function.  **Progress Updates and Countdown**  1. The `update_progress()` function updates the countdown label and progress bar based on the elapsed time since the capture started. 2. It calculates the remaining time, progress percentage, and updates the GUI components accordingly. 3. The function schedules itself to be called again after a 1-second delay using the `root.after()` method.  **GUI Integration**  The code seems to be integrated with a graphical user interface (GUI) built using a library like Tkinter (given the presence of `root`, `countdown_label`, and `progress_bar` variables). The GUI likely provides a countdown timer, progress bar, and possibly other controls for starting and stopping the packet capture.  **Notes**  * The code is truncated, so some parts might be missing. * There are no error handling mechanisms in place, which could lead to issues if something goes wrong during packet capture or analysis. * Some variables (e.g., `pcap_filename`, `threshold`) seem to be defined elsewhere in the codebase, as they are not initialized in this snippet.  To write similar code, you would need to:  1. Import necessary libraries (Scapy, Tkinter, etc.). 2. Initialize variables and set up the GUI components. 3. Implement the packet capture functionality using Scapy's `sniff()` function. 4. Analyze the captured packets and extract relevant statistics. 5. Update the GUI with progress information and detected unusual activity. 6. Save the captured packets to a PCAP file.  Here is an example of how you might structure your code: ```python import scapy.all as scapy import tkinter as tk  class PacketCaptureTool:     def __init__(self):         self.capture_running = False         self.capture_start_time = None         self.capture_duration = 0         self.pcap_filename = "capture.pcap"          # Set up GUI components         self.root = tk.Tk()         self.countdown_label = tk.Label(self.root, text="Remaining time: ")         self.progress_bar = tk.Progressbar(self.root)      def start_capture(self):         # Start packet capture using Scapy's sniff() function         scapy.sniff(prn=self.packet_callback, timeout=self.capture_duration)      def packet_callback(self, packet):         # Analyze the captured packet and update statistics         if packet.haslayer(scapy.TCP):             self.tcp_count += 1         elif packet.haslayer(scapy.UDP):             self.udp_count += 1         # ...      def update_progress(self):         # Update countdown label and progress bar         elapsed = time.time() - self.capture_start_time         remaining = max(0, self.capture_duration - elapsed)         progress_percentage = min(100, (elapsed / self.capture_duration) * 100)         self.countdown_label.config(text=f"Remaining time: {remaining:.0f} sec")         self.progress_bar['value'] = progress_percentage      def save_capture(self):         # Save captured packets to a PCAP file         scapy.wrpcap(self.pcap_filename, self.packets)  if __name__ == "__main__":     tool = PacketCaptureTool()     tool.start_capture()     tool.root.mainloop() ``` Note that this is a simplified example and you will likely need to add more functionality, error handling, and customization to suit your specific requirements. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Network_Security/network_monitoring/sniffer.py) |

### 📁 `virusTotalAPI/` Directory
| 📄 **Script Name** | **Description** | **Link** |
| ----------------- | --------------- | -------- |
| `Malware_Analysis/virusTotalAPI/virus_total_scan.py` | VirusTotal IOC scanner. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Malware_Analysis/virusTotalAPI/virus_total_scan.py) |

### 📁 `wireless_security/` Directory
| 📄 **Script Name** | **Description** | **Link** |
| ----------------- | --------------- | -------- |
| `Network_Security/wireless_security/WiFi_Discover/wifi_packet_sniff.py` | This is a Python script that appears to be designed for WiFi packet sniffing and analysis. It uses the Scapy library to capture and analyze WiFi packets, and then generates a Markdown report based on the captured data.  Here's a breakdown of what the script does:  1. **Initialization**: The script starts by importing necessary libraries, including Scapy and setting up some constants. 2. **Packet Capture**: The script captures WiFi packets using Scapy's `sniff` function, filtering out packets that don't contain a Dot11 layer (which is the layer for WiFi packets). 3. **Packet Analysis**: For each captured packet, the script checks if it's a management frame (type 0), control frame (type 1), or data frame (type 2). It then tallies the counts of each type. 4. **Network Discovery**: If the packet is a beacon or probe response, the script extracts the SSID, BSSID, encryption type, channel, and signal strength (if available). 5. **Client Detection**: The script tries to detect client connections by checking if the transmitter or receiver address is a known BSSID and the other address is unicast. 6. **Report Generation**: The script generates a Markdown report based on the captured data, including: 	* A summary of the capture duration and total packets captured. 	* A breakdown of management, control, and data frames. 	* A table of discovered networks, including SSID, BSSID, channel, encryption type, average signal strength, and associated clients. 7. **Next Steps**: The script also generates example commands for deauthenticating or jamming each discovered network (using external scripts `wifi_deauth.py` and `wifi_jam.py`, which are not included in this code snippet).  Some notes on the code:  * The script assumes that the WiFi interface is already configured to monitor mode. * The script uses a simple threshold-based approach to detect client connections, which may not be accurate in all cases. * The script generates example commands for deauthenticating or jamming networks, but these should only be used for educational purposes and with proper authorization.  Overall, this script appears to be designed for educational purposes or for use in a controlled environment, rather than for malicious activities. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Network_Security/wireless_security/WiFi_Discover/wifi_packet_sniff.py) |
| `Network_Security/wireless_security/WiFi_Discover/wifi_signal_discovery.py` | Scans WiFi networks. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Network_Security/wireless_security/WiFi_Discover/wifi_signal_discovery.py) |
| `Network_Security/wireless_security/Wifi_Attack/wifi_deauth.py` | WiFi deauth attack script. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Network_Security/wireless_security/Wifi_Attack/wifi_deauth.py) |
| `Network_Security/wireless_security/Wifi_Attack/wifi_jam.py` | WiFi beacon flood attack. | [Link](https://github.com/rgrit/RGRIT.US_CyberTools/blob/main/Network_Security/wireless_security/Wifi_Attack/wifi_jam.py) |
