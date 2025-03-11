# 🔐 Blue Team Scripts 

This repository contains categorized security tools for:  

- **📧 Email Security** – Analyzing email threats & metadata  
- **🛡️ File Integrity Monitoring** – Detecting unauthorized file changes  
- **🔍 Secure Code Review** – Scanning for credentials & vulnerabilities  

Each tool **automates security checks** and **generates reports** to enhance cybersecurity analysis.

---

## 📧 Email Security  

Tools for analyzing **email security threats, extracting metadata**, and **automating risk assessment**.

| 🛠️ **Script** | 📌 **Description** |
|--------------|-----------------|
| `email_overview.py` | 🔍 Scans Thunderbird mailboxes for emails requiring immediate action. |
| `email_grab_attachments.py` | 📎 Extracts email attachments and generates reports. |
| `email_security_report.py` | 📊 Analyzes email headers for authentication issues and suspicious patterns. |
| `email_list_senders.py` | 📨 Compiles a list of all senders from a mailbox for analysis. |
| `email_generate_sigma.py` | ⚠️ Extracts Indicators of Compromise (IoCs) from emails and generates Sigma rules. |

### **🔹 Key Features**  
✅ **Threat Analysis** – Identifies phishing attempts and anomalies in email headers.  
✅ **Automation** – Uses AI models to analyze emails and assess risk levels.  
✅ **Forensics** – Extracts metadata, sender information, and attachments for investigation.  

---

## 🔐 File Integrity Monitoring  

Monitors file changes in a directory to detect **unauthorized modifications**.

| 🛠️ **Script** | 📌 **Description** |
|--------------|-----------------|
| `file_integrity_monitor.py` | 🛡️ Tracks file changes using SHA-256 hashes and alerts on modifications. |

### **🔹 Key Features**  
✅ **Baseline Creation** – Captures the initial file state for integrity verification.  
✅ **Change Detection** – Identifies modified, new, or deleted files.  
✅ **GUI Interface** – Provides a user-friendly interface for monitoring directories.  

---

## 🛡️ Secure Code Review  

Analyzes Python code for **hardcoded credentials** and **security vulnerabilities**.

| 🛠️ **Script** | 📌 **Description** |
|--------------|-----------------|
| `scan_for_credentials.py` | 🔑 Scans Python scripts for hardcoded API keys, passwords, and sensitive data. |

### **🔹 Key Features**  
✅ **AI-Powered Detection** – Uses LLM models to find insecure coding practices.  
✅ **Automated Reporting** – Generates Markdown security reports.  
✅ **Best Practices** – Provides recommendations for securing credentials.  

---

## 📌 Usage Guide  

Each category contains scripts that can be run **independently**.  
Make sure to install dependencies before running the scripts:

```bash
pip install -r requirements.txt
