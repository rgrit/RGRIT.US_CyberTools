import os
import ollama

# Directories to exclude from scanning
EXCLUDED_DIRS = {".venv", "venv", ".env", "__pycache__", ".git"}

# Directory to store security reports
REPORTS_DIR = "security_reports"
os.makedirs(REPORTS_DIR, exist_ok=True)  # Ensure the directory exists


# Function to find all .py files, excluding certain directories
def find_python_files(directory):
    python_files = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]  # Exclude unwanted directories
        for file in files:
            if file.endswith(".py"):
                python_files.append(os.path.join(root, file))
    return python_files


# Function to analyze a Python file using Ollama LLM
def analyze_with_llm(file_path):
    try:
        print(f"[INFO] Sending {file_path} to LLM for analysis...")

        with open(file_path, "r", encoding="utf-8") as file:
            code = file.read()

        # Prompt for LLM analysis
        prompt = f"""
        Analyze the following Python script for security vulnerabilities, 
        particularly hardcoded API keys, passwords, access tokens, credentials, 
        or other sensitive information.

        Return:
        - A summary of issues found.
        - Line numbers where possible.
        - Secure code recommendations.

        ```python
        {code}
        ```
        """

        response = ollama.chat(model='mistral-nemo:latest', messages=[{"role": "user", "content": prompt}])
        analysis = response.get('message', {}).get('content', 'No response from LLM.')

        print(f"[DEBUG] LLM Analysis for {file_path}:\n{analysis[:500]}...\n")  # Print first 500 chars for preview

        return analysis

    except Exception as e:
        print(f"[ERROR] Failed to analyze {file_path} with LLM: {e}")
        return "Error retrieving analysis. Please manually review."


# Function to create a Markdown report
def create_markdown_report(file_path, analysis):
    base_name = os.path.basename(file_path)
    md_filename = os.path.join(REPORTS_DIR, f"{base_name}.md")

    with open(md_filename, "w", encoding="utf-8") as md_file:
        md_file.write(f"# Security Report for `{base_name}`\n\n")
        md_file.write(analysis + "\n\n")

        md_file.write("### 🔒 General Security Best Practices:\n")
        md_file.write("- Store credentials in **environment variables** (`os.getenv()`)\n")
        md_file.write("- Use a **`.env` file** with `python-dotenv`\n")
        md_file.write("- Secure **AWS credentials** using IAM roles instead of hardcoding\n")
        md_file.write("- Never commit credentials to version control (use `.gitignore`)\n")

    print(f"[INFO] Report saved: {md_filename}")


# Main function
def main():
    root_directory = "<<YOUR ROOT DIRECTORY>>"  # Set the absolute path
    print(f"[INFO] Scanning for Python files in '{root_directory}' (excluding .venv, .env, etc.)...")

    python_files = find_python_files(root_directory)

    if not python_files:
        print("[INFO] No Python files found.")
        return

    for file_path in python_files:
        print(f"[INFO] Analyzing: {file_path}")
        analysis = analyze_with_llm(file_path)
        create_markdown_report(file_path, analysis)

    print(f"[INFO] Scan completed. Reports saved in `{REPORTS_DIR}` directory.")

if __name__ == "__main__":
    main()

