# 🕵️‍♂️ CTI and Detection Toolkit  

This repository provides **Cyber Threat Intelligence (CTI) and Detection Engineering tools**, enabling security teams to **automate RSS threat feed management, analyze security articles, and generate detection rules** based on extracted intelligence.

---

## 📡 Threat Intelligence Automation  

Automates the **ingestion, processing, and enrichment** of threat intelligence feeds.

| 🛠️ **Script** | 📌 **Description** |
|--------------|-----------------|
| `rss_feed_mgmt_csv_to_OPML.py` | 📥 Converts a CSV list of threat intelligence blogs into an OPML file for easy RSS feed import. |
| `rss_feed_to_detection/main.py` | 📰 Fetches, analyzes, and processes RSS feeds for security articles. |

### **🔹 Key Features**  
✅ **Streamlined Threat Feeds** – Converts CSV data into OPML for easy RSS subscription.  
✅ **Automated Article Processing** – Extracts and enriches articles for CTI.  
✅ **Reduces Manual Work** – Automates the identification of security-relevant content.  

---

## 🎯 Detection Engineering  

Generates **structured threat intelligence reports** and **creates detection rules** to enhance security monitoring.

| 🛠️ **Script** | 📌 **Description** |
|--------------|-----------------|
| `heatmap_generator.py` | 🔥 Extracts MITRE ATT&CK techniques from reports and generates a heatmap for detection coverage. |
| `report_generator.py` | 📝 Generates markdown reports from processed threat articles. |
| `rss_utils.py` | 📡 Fetches RSS feeds and extracts security-related content. |

### **🔹 Key Features**  
✅ **MITRE ATT&CK Mapping** – Automatically extracts and visualizes tactics & techniques.  
✅ **Automated Report Generation** – Produces structured reports with **IoCs, Sigma rule feasibility, and threat insights**.  
✅ **Enhances Threat Detection** – Transforms intelligence feeds into actionable security content.  

---

## 📌 **Usage Guide**  

### **Step 1: Prepare Your Threat Feeds**  
1. Create a CSV file (e.g., `Awesome_Threat_Intel_Blogs.csv`) with two columns:  
   - **Blog Name** (Threat intelligence blog name)  
   - **Feed Link** (RSS feed URL)  

2. Convert it to OPML format:  
   ```bash
   python rss_feed_mgmt_csv_to_OPML.py
   ```

### **Step 2: Automate Threat Intelligence Processing**  
1. Configure your RSS feed URL in `config.py`.  
2. Run the article processor:  
   ```bash
   python rss_feed_to_detection/main.py
   ```

### **Step 3: Generate Detection Reports**  
1. Run the heatmap generator to extract MITRE ATT&CK techniques:  
   ```bash
   python heatmap_generator.py
   ```

2. Generate structured markdown reports:  
   ```bash
   python report_generator.py
   ```

---

## 🛡️ **Why This Toolkit Matters**  
With the increasing volume of threat intelligence, security teams **need automated tools** to process feeds, extract actionable insights, and **develop effective detection mechanisms**. This toolkit provides:  

- 📡 **Automated Threat Feed Management** – Converts RSS feeds into structured data.  
- 🔎 **Enrichment & Analysis** – Identifies IoCs, MITRE techniques, and relevant security information.  
- 🚀 **Detection Engineering** – Generates Sigma rules, detection stories, and security reports.  

---

## 🚀 **Future Enhancements**  
🔹 **Additional Data Sources** – Expand feeds beyond RSS (e.g., Twitter, public CTI reports).  
🔹 **Threat Correlation** – Link articles with previous intelligence for deeper insights.  
🔹 **Automated Sigma Rule Generation** – Convert extracted techniques into structured detection logic.  

Stay ahead of **emerging threats** with this **automated CTI and detection toolkit!** 🛡️🔥