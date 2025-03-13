import os
import json
import ollama
from datetime import datetime

# Configuration
REPO_PATH = "/home/administrator/PycharmProjects/CyberTools"  # Path to the root of the repository
OUTPUT_DIR = "/home/administrator/PycharmProjects/CyberTools/Auto_Documetation/docs"  # Directory to save the README file
README_FILENAME = "/home/administrator/PycharmProjects/CyberTools/README.md"
MODEL_NAME = "llama3.3:latest"  # Example model name for Ollama or API (adjust as needed)
GITHUB_URL = "https://github.com/rgrit/RGRIT.US_CyberTools/blob/main"  # Base GitHub URL for the repository

print("[INFO] Starting README auto-generator in repository:", REPO_PATH)

# Ensure output directory exists
os.makedirs(os.path.join(REPO_PATH, OUTPUT_DIR), exist_ok=True)
print(f"[INFO] Output directory verified: {OUTPUT_DIR}")

# 1. Scan for all .py and .yml files in the repository, skipping .venv directories
files_found = []
print("[INFO] Scanning for Python and YAML files...")

for root, dirs, files in os.walk(REPO_PATH):
    # Skip the .venv directory and the output directory itself to avoid processing previous README or JSON
    if '.venv' in dirs:
        dirs.remove('.venv')
        print(f"[DEBUG] Skipping .venv in {root}")
    if OUTPUT_DIR in root.split(os.sep):
        continue
    for file in files:
        if file.endswith((".py", ".yml")):  # Include both .py and .yml files
            file_path = os.path.join(root, file)
            # Get path relative to repo root for categorization
            rel_path = os.path.relpath(file_path, REPO_PATH)
            files_found.append(rel_path)

files_found.sort()
print(f"[INFO] Found {len(files_found)} Python and YAML files.")

# 2. Categorize files by second-level folder structure
categories = {}  # e.g., {"folder/subfolder": [file1.py, file2.py], "": [file_in_root.py]}
print("[INFO] Categorizing files...")
for rel_path in files_found:
    # Split the path and grab the second-level directory (ignore first-level folder)
    path_parts = rel_path.split(os.sep)
    if len(path_parts) >= 2:
        second_level_dir = path_parts[1]
    else:
        second_level_dir = "Root"  # in case there is no second-level directory (root-level files)

    categories.setdefault(second_level_dir, []).append(rel_path)

print(f"[INFO] Categorized into {len(categories)} folders.")


# 3. Define a helper to generate a concise description using an AI model (via Ollama Python package)
def generate_description(file_path):
    """Use an AI model to generate a one- or two-sentence description of the given file."""
    try:
        print(f"[DEBUG] Analyzing {file_path}...")
        # Read the file content
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # (Optional) Truncate or summarize content if it's too large for the model
        if len(content) > 10000:  # if file is extremely large, truncate for prompt
            content = content[:10000] + "\n... (truncated)"

        # Prepare the prompt for the model
        prompt = (
            "Analyze the following file and provide a concise description of its functionality. Please STRICTLY limit the description to 140 characters:\n"
            f"{content}\n"
            "Description:"
        )

        # Call the Ollama Python API to get the description
        response = ollama.chat(model=MODEL_NAME, messages=[{"role": "user", "content": prompt}])

        # Log the full response for debugging
        print(f"[DEBUG] API Response: {response}")

        # Check if the response contains the message with content
        if 'message' in response and 'content' in response['message']:
            desc = response['message']['content'].strip()
        else:
            print(
                f"[ERROR] 'message' or 'content' key not found in API response for {file_path}. Full response: {response}")
            desc = "*(No description provided by AI)*"

        # Fallback if no description provided
        if not desc:
            desc = "*(No description provided by AI)*"

        print(f"[DEBUG] Description for {file_path}: {desc[:60]}...")
        return desc
    except Exception as e:
        # In case of errors (e.g., model not available), return a placeholder
        print(f"[ERROR] Failed to generate description for {file_path}: {e}")
        return f"*(Description generation failed): {e}*"


# 4. Generate descriptions for each Python and YAML file
descriptions = {}
print("[INFO] Generating descriptions for each file...")
for category, files in categories.items():
    for filename in files:
        # Determine full path of the file
        file_path = os.path.join(REPO_PATH, filename)
        # Generate AI description for the file
        descriptions[filename] = generate_description(file_path)

print(f"[INFO] Generated descriptions for {len(descriptions)} files.")

# 5. Load previous descriptions (if available) to identify recent updates
history_path = os.path.join(REPO_PATH, OUTPUT_DIR, "readme_index.json")
prev_descriptions = {}
if os.path.exists(history_path):
    try:
        with open(history_path, 'r', encoding='utf-8') as hist_file:
            prev_descriptions = json.load(hist_file)
        print("[INFO] Loaded previous descriptions for comparison.")
    except json.JSONDecodeError:
        print("[WARNING] Failed to decode previous history file; starting fresh.")
        prev_descriptions = {}
else:
    print("[INFO] No previous history file found; starting fresh.")

# Compare current and previous descriptions to detect changes
added_files = [f for f in descriptions.keys() if f not in prev_descriptions]
removed_files = [f for f in prev_descriptions.keys() if f not in descriptions]
changed_files = [
    f for f in descriptions.keys()
    if f in prev_descriptions and descriptions[f] != prev_descriptions[f]
]

print(f"[INFO] Changes detected: {len(added_files)} added, {len(removed_files)} removed, {len(changed_files)} updated.")

# Prepare the Recent Updates entries
recent_updates = []
if added_files:
    for f in sorted(added_files):
        recent_updates.append(f"🆕 **Added** `{f}`")
if removed_files:
    for f in sorted(removed_files):
        recent_updates.append(f"❌ **Removed** `{f}`")
if changed_files:
    for f in sorted(changed_files):
        recent_updates.append(f"✏️ **Updated** `{f}`")

# Include timestamp for the updates section
update_date = datetime.now().strftime("%Y-%m-%d")

# 6. Build the README content with Markdown formatting
readme_lines = []

# Disclaimer Section in Markdown format
disclaimer_text = """
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
"""
readme_lines.append(disclaimer_text)

# Recent Updates Section
readme_lines.append("## Recent Updates (as of {})".format(update_date))
if recent_updates:
    for entry in recent_updates:
        readme_lines.append(f"- {entry}")
else:
    readme_lines.append("- *(No recent changes detected)*")
readme_lines.append("")  # blank line

# Repository Overview introduction
readme_lines.append("## Repository Overview")
readme_lines.append("Below is an overview of all Python and YAML scripts organized by the second-level directory:")
readme_lines.append("")  # blank line

# List each second-level directory with its files and descriptions in a table
for category in sorted(categories.keys()):
    readme_lines.append(f"### 📁 `{category}/` Directory")
    # Table header
    readme_lines.append("| 📄 **Script Name** | **Description** | **Link** |")
    readme_lines.append("| ----------------- | --------------- | -------- |")
    for filename in sorted(categories[category]):
        desc = descriptions.get(filename, "")
        # Ensure the description is a single line (strip newlines)
        desc_clean = " ".join(desc.splitlines()).strip()
        github_link = f"{GITHUB_URL}/{filename}"
        readme_lines.append(f"| `{filename}` | {desc_clean} | [Link]({github_link}) |")
    readme_lines.append("")  # blank line after each category

# 7. Save the README content to the docs/ directory
output_path = os.path.join(REPO_PATH, OUTPUT_DIR, README_FILENAME)
with open(output_path, 'w', encoding='utf-8') as outfile:
    outfile.write("\n".join(readme_lines))
print(f"[INFO] README saved to: {output_path}")

# Also save the current descriptions state for the next run
with open(history_path, 'w', encoding='utf-8') as hist_file:
    json.dump(descriptions, hist_file, indent=2)
print(f"[INFO] Descriptions history saved to: {history_path}")

print("[INFO] Script execution complete.")
