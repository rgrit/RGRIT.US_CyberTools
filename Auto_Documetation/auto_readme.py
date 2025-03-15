import os
import json
import ollama
from datetime import datetime

# Configuration
REPO_PATH = "/home/administrator/PycharmProjects/CyberTools"
OUTPUT_DIR = "Auto_Documetation/docs"
README_FILENAME = "/home/administrator/PycharmProjects/CyberTools/README.md"
MODEL_NAME = "llama3.3"
GITHUB_URL = "https://github.com/rgrit/RGRIT.US_CyberTools/blob/main"

print("[INFO] Starting README auto-generator in repository:", REPO_PATH)

os.makedirs(os.path.join(REPO_PATH, OUTPUT_DIR), exist_ok=True)

# Load existing descriptions
history_path = os.path.join(REPO_PATH, OUTPUT_DIR, "readme_index.json")
existing_history = {}
if os.path.exists(history_path):
    try:
        with open(history_path, 'r', encoding='utf-8') as hist_file:
            existing_history = json.load(hist_file)
        print("[INFO] Loaded existing history successfully.")
    except json.JSONDecodeError:
        print("[WARNING] JSON decode error; starting fresh.")
else:
    print("[INFO] No existing history found; starting fresh.")

# Find new files to analyze
files_found = []
for root, dirs, files in os.walk(REPO_PATH):
    dirs[:] = [d for d in dirs if d != '.venv' and d != 'docs']
    for file in files:
        if file.endswith((".py", ".yml")) and file != "auto_readme.py":
            file_path = os.path.relpath(os.path.join(root, file), REPO_PATH)
            if file_path not in existing_history:
                files_found.append(file_path)

print(f"[INFO] {len(files_found)} new files to analyze.")

# Description generator
def generate_description(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        prompt = f"Analyze this file and provide a concise description strictly limited to 280 characters:\n{content}\nDescription:"
        response = ollama.chat(model=MODEL_NAME, messages=[{"role": "user", "content": prompt}])
        desc = response['message']['content'].strip()
        return desc[:140] + "..." if len(desc) > 140 else desc
    except Exception as e:
        print(f"[ERROR] Generating description failed for {file_path}: {e}")
        return "*(Description generation failed)*"

# Generate descriptions with clear debugging
categories = {}
new_descriptions = {}
for idx, file_rel_path in enumerate(files_found, start=1):
    print(f"[ANALYZING {idx}/{len(files_found)}]: {file_rel_path}")
    file_full_path = os.path.join(REPO_PATH, file_rel_path)
    desc = generate_description(file_full_path)
    new_category = file_rel_path.split(os.sep)[1] if len(file_rel_path.split(os.sep)) > 1 else "Root"
    categories.setdefault(new_category, []).append(file_rel_path)
    existing_history[file_rel_path] = desc

# Prepare recent updates
recent_updates = [f"🆕 **Added** `{file}`" for file in files_found]
update_date = datetime.now().strftime("%Y-%m-%d")

# Build README
readme_content = [f"# 🚀 **RGRIT CyberTools** 🔥", f"## Recent Updates (as of {update_date})"]
readme_content += [f"- {update}" for update in recent_updates] or ["- *(No recent changes detected)*"]

readme_content.append("\n## Repository Overview")
for category in sorted(categories):
    readme_content.append(f"### 📁 `{category}/` Directory")
    readme_content.append("| 📄 **Script Name** | **Description** | **Link** |");
    readme_content.append("| ----------------- | --------------- | -------- |");
    for file in categories[category]:
        desc = existing_history.get(file, "*(No description provided)*")
        file_link = f"{GITHUB_URL}/{file}"
        readme_content.append(f"| `{file}` | {desc} | [Link]({file_link}) |");
    readme_content.append("")

# Save README
output_path = os.path.join(REPO_PATH, OUTPUT_DIR, README_FILENAME)
with open(output_path, 'w', encoding='utf-8') as f:
    f.write("\n".join(readme_content))

# Update history
existing_history.update({f: existing_history.get(f, desc) for f, desc in new_descriptions.items()})
with open(history_path, 'w', encoding='utf-8') as f:
    json.dump(existing_history, f, indent=2)

print(f"[INFO] README saved to {output_path}")
print(f"[INFO] Descriptions history updated at {history_path}")
print("[INFO] Script execution complete.")