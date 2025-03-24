import os
import json
import ollama
from datetime import datetime

# Configuration
REPO_PATH = "/home/administrator/PycharmProjects/CyberTools"
OUTPUT_DIR = "Auto_Documetation/docs"
MODEL_NAME = "gemma3:27b"
GITHUB_URL = "https://github.com/rgrit/RGRIT.US_CyberTools/blob/main"
README_FILENAME = os.path.join(REPO_PATH, "README.md")
HISTORY_PATH = os.path.join(REPO_PATH, OUTPUT_DIR, "readme_index.json")

# Ensure output directory exists
os.makedirs(os.path.join(REPO_PATH, OUTPUT_DIR), exist_ok=True)

# Load or initialize history
if os.path.exists(HISTORY_PATH):
    with open(HISTORY_PATH, 'r', encoding='utf-8') as hist_file:
        history = json.load(hist_file)
else:
    history = {}

new_descriptions = {}

# Scan repository for files
for root, dirs, files in os.walk(REPO_PATH):
    dirs[:] = [d for d in dirs if d not in ['.venv', OUTPUT_DIR.split('/')[0]]]
    for file in files:
        if file.endswith(('.py', '.yml')) and file != "auto_readme.py":
            rel_path = os.path.relpath(os.path.join(root, file), REPO_PATH)

            if rel_path not in history:
                print(f"[INFO] Analyzing new file: {rel_path}")
                try:
                    with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                        content = f.read()
                    response = ollama.chat(model=MODEL_NAME, messages=[{"role": "user", "content": f"Provide a concise description (max 140 chars) of this script:\n{content}"}])
                    desc = response['message']['content'].strip()[:140]
                except Exception as e:
                    desc = "*(Description generation failed)*"

                history[rel_path] = desc
                new_descriptions[rel_path] = desc

# Save updated history
with open(HISTORY_PATH, 'w', encoding='utf-8') as f:
    json.dump(history, f, indent=2)

# Robust Disclaimer
DISCLAIMER_TEXT = """
# 🚨 Disclaimer

**Educational & Research Purposes Only**  
All content provided in this repository is strictly for educational and research purposes. Users must adhere to ethical and legal guidelines when utilizing any scripts, tools, or resources contained herein.

**Ethical and Legal Responsibility**  
You are solely responsible for ensuring that your use of these materials complies with all applicable laws and ethical standards. Unauthorized or malicious use is strictly prohibited and may result in legal action.

**No Warranty**  
All scripts, tools, and documentation are provided \"as-is\" without any warranty. The authors and contributors assume no responsibility for any consequences arising from the use or misuse of these resources.

By using this repository, you acknowledge and agree to these terms.
"""

# Generate main README
update_date = datetime.now().strftime("%Y-%m-%d")
readme_lines = ["# 🚀 RGRIT CyberTools 🔥\n", DISCLAIMER_TEXT, f"\n## Recent Updates ({update_date})\n"]

for new_file in new_descriptions:
    readme_lines.append(f"- 🆕 **Added** `{new_file}`")

categories = {}
for file, desc in history.items():
    category = file.split(os.sep)[1] if len(file.split(os.sep)) > 1 else "Root"
    categories.setdefault(category, {})[file] = desc

readme_lines.append("\n## Repository Overview\n")
for cat, files in sorted(categories.items()):
    readme_lines.append(f"### 📁 `{cat}` Directory")
    readme_lines.append("| 📄 **Script Name** | **Description** | **Link** |")
    readme_lines.append("|-----------------|---------------|--------|")
    for file, desc in files.items():
        link = f"{GITHUB_URL}/{file}"
        readme_lines.append(f"| `{file}` | {desc} | [Link]({link}) |")
    readme_lines.append("")

with open(README_FILENAME, 'w', encoding='utf-8') as f:
    f.write("\n".join(readme_lines))

print("[INFO] README and documentation successfully updated.")