import os
import json
import re
import ollama
from datetime import datetime

# === Configuration ===
REPO_PATH = "/home/administrator/PycharmProjects/RGRIT.US_CyberTools"
OUTPUT_DIR = "Auto_Documetation/docs"
MODEL_NAME = "gemma3:27b"
GITHUB_URL = "https://github.com/rgrit/RGRIT.US_CyberTools/blob/main"
README_FILENAME = os.path.join(REPO_PATH, "README.md")
HISTORY_PATH = os.path.join(REPO_PATH, OUTPUT_DIR, "readme_index.json")

# === Helper Functions ===
def log_info(msg):
    print(f"\033[94m[INFO]\033[0m {msg}")

def log_success(msg):
    print(f"\033[92m[SUCCESS]\033[0m {msg}")

def log_warn(msg):
    print(f"\033[93m[WARNING]\033[0m {msg}")

def log_error(msg):
    print(f"\033[91m[ERROR]\033[0m {msg}")

def sanitize_desc(text):
    """Collapse and trim description to make it Markdown table-safe."""
    text = text.replace('\n', ' ').replace('\r', '')
    text = re.sub(r'\s+', ' ', text)
    return text.strip()[:140]

# === Setup Output Directory ===
os.makedirs(os.path.join(REPO_PATH, OUTPUT_DIR), exist_ok=True)
log_info(f"Ensured output directory exists at: {OUTPUT_DIR}")

# === Load or Initialize History ===
if os.path.exists(HISTORY_PATH):
    with open(HISTORY_PATH, 'r', encoding='utf-8') as hist_file:
        history = json.load(hist_file)
    log_info(f"Loaded existing history with {len(history)} files.")
else:
    history = {}
    log_info("No previous history found. Starting fresh.")

new_descriptions = {}
files_scanned = 0
new_files = 0

# === File Scanning & Description Generation ===
for root, dirs, files in os.walk(REPO_PATH):
    dirs[:] = [d for d in dirs if d not in ['.venv', OUTPUT_DIR.split('/')[0], '__pycache__']]
    for file in files:
        if file.endswith(('.py', '.yml')) and file != os.path.basename(__file__):
            rel_path = os.path.relpath(os.path.join(root, file), REPO_PATH)
            files_scanned += 1

            if rel_path not in history:
                log_info(f"🧠 Analyzing: {rel_path}")
                try:
                    with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                        content = f.read()

                    response = ollama.chat(model=MODEL_NAME, messages=[
                        {"role": "user", "content": f"Provide a concise description (max 140 chars) of this script:\n{content}"}
                    ])
                    desc = sanitize_desc(response['message']['content'])
                    new_descriptions[rel_path] = desc
                    history[rel_path] = desc
                    new_files += 1
                    log_success(f"📝 Documented: {rel_path}")
                except Exception as e:
                    log_error(f"❌ Failed to analyze {rel_path}: {e}")
                    history[rel_path] = "*(Description generation failed)*"

# === Save Updated History ===
with open(HISTORY_PATH, 'w', encoding='utf-8') as f:
    json.dump(history, f, indent=2)
log_success("📚 History file updated.")

# === Disclaimer Block ===
DISCLAIMER_TEXT = """
# 🚨 Disclaimer

**Educational & Research Purposes Only**  
All content provided in this repository is strictly for educational and research purposes. Users must adhere to ethical and legal guidelines when utilizing any scripts, tools, or resources contained herein.

**Ethical and Legal Responsibility**  
You are solely responsible for ensuring that your use of these materials complies with all applicable laws and ethical standards. Unauthorized or malicious use is strictly prohibited and may result in legal action.

**No Warranty**  
All scripts, tools, and documentation are provided "as-is" without any warranty. The authors and contributors assume no responsibility for any consequences arising from the use or misuse of these resources.

By using this repository, you acknowledge and agree to these terms.
"""

# === README Generation ===
update_date = datetime.now().strftime("%Y-%m-%d")
readme_lines = [
    "# 🚀 RGRIT CyberTools 🔥",

    "## 👋 About Me\n"
    "Hi, I’m an AI-native cybersecurity technologist who prototypes fast, solves hard problems, and shares tools that defenders can actually use. "
    "This repo is my personal lab — part red team, part blue team, part builder. I combine rapid programming, open-source, and AI-assisted development to accelerate threat detection, automation, and research.\n",

    "## 🧠 Mission\n"
    "This repository is a living archive of tools I’ve built or prototyped to support cybersecurity research, network monitoring, detection engineering, "
    "and incident response. AI isn’t a crutch — it’s a catalyst that lets me go from idea to working tool faster than traditional methods. "
    "These projects are here to educate, inspire, and empower defenders.\n",

    DISCLAIMER_TEXT,

    f"\n## 📅 Recent Updates ({update_date})\n"
]

for new_file in new_descriptions:
    readme_lines.append(f"- 🆕 **Added** `{new_file}`")

readme_lines.append("\n## 🔍 Featured Tools\n")
readme_lines.extend([
    "- **🕵️‍♂️ Rootkit Investigator** – Linux incident response script that investigates potential rootkits or malware on a live system.\n"
    "  → `Incident_Response/possible_rootkit_investigation.py`\n",
    "- **🌐 Network Flow Analyzer (GUI)** – Visualizes unencrypted flows and credentials using Scapy and Tkinter. Fully interactive.\n"
    "  → `Network_Security/network_monitoring/flow_analyzer.py`\n",
    "- **🧠 AI-Powered Threat Intel** – RSS-to-report pipeline that extracts IOCs, generates detection heatmaps, and summarizes articles using LLMs.\n"
    "  → `OSINT_Scripts/CTI_and_Detection/rss_feed_to_detection/`\n",
    "- **📡 Flipper + Sigma Rules** – RF scanning, BadUSB detection, and Slack alerting with Flipper Zero + Kismet + custom Sigma rules.\n"
    "  → `Flipper_Zero/`, `Custom_Sigma_Rules/`\n"
])

readme_lines.append("\n## 📁 Repository Overview\n")

# Group by first-level folder (category)
categories = {}
for file, desc in history.items():
    parts = file.split(os.sep)
    category = parts[1] if len(parts) > 1 else "Root"
    categories.setdefault(category, {})[file] = desc

for cat, files in sorted(categories.items()):
    readme_lines.append(f"### 📁 `{cat}` Directory")
    readme_lines.append("| 📄 **Script Name** | **Description** | **Link** |")
    readme_lines.append("|--------------------|----------------|----------|")
    for file, desc in sorted(files.items()):
        link = f"{GITHUB_URL}/{file}"
        clean_desc = sanitize_desc(desc)
        readme_lines.append(f"| `{file}` | {clean_desc} | [Link]({link}) |")
    readme_lines.append("")

# === Save README ===
with open(README_FILENAME, 'w', encoding='utf-8') as f:
    f.write("\n".join(readme_lines))
log_success(f"🗂️ README generated at {README_FILENAME}")

# === Summary ===
print("\n\033[96m📊 Summary:\033[0m")
print(f"- Files scanned: {files_scanned}")
print(f"- New files documented: {new_files}")
print(f"- README updated: ✅")
print(f"- History file: {HISTORY_PATH}")
print()
