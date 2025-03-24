Here's a clear, professional, and informative `README.md` you can use in your directory to document your automated Incident Response workflow, emphasizing the benefits of automation over manual investigation:

---

# Automated Incident Response: Kernel-Level Rootkit Investigation

## 📌 Overview
This repository contains an automated incident response (IR) script developed to investigate a Wazuh alert indicating a possible kernel-level rootkit infection. Previously, investigating these alerts required manual execution and analysis of multiple forensic commands, significantly increasing response times and potential human error.

This specific IR demonstration is based on a real-world Wazuh alert:

```
Process '[PID]' hidden from /proc. Possible kernel-level rootkit detected.
Rule ID: 521 (MITRE ATT&CK Technique T1014 - Rootkit, Tactic: Defense Evasion)
Detected on Host: [host-obfuscated]
Wazuh Manager: [manager-obfuscated]
Timestamp: [timestamp-obfuscated]

```

*(Note: Identifiers have been obfuscated.)*

---

## 🚀 What the Script Does

The Python script automates the following essential IR tasks:

- **Process Verification:** Validates the existence and legitimacy of any suspicious PID.
- **Hidden Process Detection:** Automatically identifies hidden processes using forensic utilities (`unhide`).
- **Filesystem Inspection:** Examines `/proc/[PID]` entries for anomalies.
- **Network Connections Analysis:** Identifies suspicious network activities linked to the PID using `netstat` and `lsof`.
- **Kernel and System Log Analysis:** Checks loaded kernel modules (`lsmod`) and kernel logs (`dmesg`) for evidence of malicious manipulation.
- **Rootkit Detection:** Performs comprehensive scans using industry-standard rootkit detection utilities (`chkrootkit`, `rkhunter`) in a fully automated, non-interactive manner.
- **AI-Powered Analysis:** Integrates with a local AI model (Gemma via Ollama) to rapidly summarize forensic findings, greatly reducing analysis time and complexity.

The script also generates a **Markdown-formatted incident report** for clear documentation and communication of results.

---

## 🛠️ Benefits of Automation

By automating this previously manual and labor-intensive process, you significantly:

- **Reduce Incident Response Time:** Rapidly identify threats, enabling quicker containment and remediation.
- **Minimize Human Error:** Standardize procedures and reduce oversight risks inherent in manual analysis.
- **Improve Efficiency:** Free your cybersecurity analysts' time to focus on critical strategic tasks, such as threat hunting, improving detection capabilities, or incident preparedness.

---

## 📂 Directory Contents
- `possible_rootkit_investigation.py`: Fully automated IR script.
- Generated Markdown reports (`incident_response_<PID>_<timestamp>.md`): Automatically created incident reports after each investigation.

---

## ⚙️ How to Run the Script
Ensure dependencies and the AI model (`Gemma`) are installed and running locally:

```bash
sudo apt install unhide lsof net-tools chkrootkit rkhunter python3-requests
ollama serve
ollama run gemma:27b
```

Then, execute the script with root privileges:

```bash
sudo python3 possible_rootkit_investigation.py
```

---

## 🎯 Use-Case and Impact
This automated IR workflow demonstrates practical, scalable cybersecurity incident management fully aligned with NIST SP 800-61 guidelines. By transitioning traditionally manual and resource-intensive forensic processes into an automated, AI-powered workflow, it streamlines threat detection, analysis, and reporting, greatly reducing time-to-response and enhancing accuracy. Leveraging cutting-edge techniques—including live forensic data collection, real-time kernel-level threat detection, automated rootkit scans, and local AI-driven analysis—this solution showcases proficiency not only in cybersecurity best practices but also in proactive innovation. It empowers security teams by freeing valuable analyst time for advanced threat hunting, strategic planning, and proactive security enhancements, significantly strengthening organizational resilience against sophisticated cyber threats.
