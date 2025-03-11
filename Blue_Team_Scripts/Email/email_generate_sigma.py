import os
import re
import json
import glob
import yaml
from datetime import datetime
from utils.api_utils import call_ollama_api_with_retry

# Directory where email_*.md files are stored
EMAIL_REPORTS_DIR = "./email_reports"
SIGMA_OUTPUT_DIR = "./sigma_rules"

# Regex patterns for extracting IoCs and key metadata
ioc_patterns = {
    "ip_address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    "domain": r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    "url": r'https?://[^\s]+',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "hash": r'\b[0-9a-fA-F]{32,64}\b'
}

# Relevant log sources for email security
log_sources = {
    "O365": "Office 365 logs (Message Trace, Secure Score, Threat Explorer)",
    "Sysmon": "System monitoring logs (e.g., Sysmon Event IDs 1, 3, 7, 11)",
    "Firewall": "Network firewall logs detecting unusual outbound connections",
    "Email Security Gateway": "Logs from email security appliances (Proofpoint, Mimecast)"
}


def extract_metadata_and_iocs(content):
    """Extracts email metadata and IoCs from the markdown report."""
    metadata = {}
    iocs = {}

    # Extract JSON metadata block
    metadata_match = re.search(r'Extracted Metadata\n```json\n(.*?)\n```', content, re.DOTALL)
    if metadata_match:
        try:
            metadata = json.loads(metadata_match.group(1))
        except json.JSONDecodeError:
            pass

    # Extract IoCs using regex
    for ioc_type, pattern in ioc_patterns.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            iocs[ioc_type] = list(set(matches))  # Remove duplicates

    return metadata, iocs


def generate_sigma_rule(email_filename, metadata, iocs):
    """Generates a Sigma rule based on extracted metadata and IoCs."""
    rule_name = f"Detect_Suspicious_Email_{email_filename.replace('.md', '')}"
    rule_id = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{hash(rule_name) % (10 ** 8)}"
    description = f"Sigma rule generated based on analysis of {email_filename}."
    logsource = "O365"

    sigma_rule = {
        "title": rule_name,
        "id": rule_id,
        "description": description,
        "status": "experimental",
        "references": ["https://attack.mitre.org/techniques/T1566/"],
        "author": "Automated Generator",
        "date": datetime.utcnow().strftime('%Y-%m-%d'),
        "logsource": {"category": "email", "service": logsource},
        "detection": {
            "selection": {"field": []},
            "condition": "selection"
        },
        "falsepositives": ["Legitimate bulk email providers"],
        "level": "medium"
    }

    # Add IoCs to the detection section
    for ioc_type, values in iocs.items():
        sigma_rule["detection"]["selection"][ioc_type] = values

    return sigma_rule


def analyze_email_with_llm(metadata, iocs):
    """Sends extracted metadata and IoCs to an LLM for deeper threat analysis."""
    prompt = f"""
    You are a cybersecurity expert. Analyze the extracted email metadata and IoCs for potential threats.

    Extracted Metadata:
    {json.dumps(metadata, indent=2)}

    Extracted IoCs:
    {json.dumps(iocs, indent=2)}

    Provide a concise threat assessment, detection recommendations, and potential Sigma rule adjustments.
    """
    return call_ollama_api_with_retry(prompt)


def process_email_reports():
    """Processes all email markdown reports and generates Sigma rules."""
    os.makedirs(SIGMA_OUTPUT_DIR, exist_ok=True)
    email_files = glob.glob(os.path.join(EMAIL_REPORTS_DIR, "email_*.md"))

    for email_file in email_files:
        with open(email_file, "r", encoding="utf-8") as f:
            content = f.read()

        metadata, iocs = extract_metadata_and_iocs(content)
        if not iocs:
            print(f"No IoCs found in {email_file}, skipping Sigma rule generation.")
            continue

        llm_analysis = analyze_email_with_llm(metadata, iocs)
        print(f"LLM Analysis for {email_file}:\n{llm_analysis}\n")

        sigma_rule = generate_sigma_rule(os.path.basename(email_file), metadata, iocs)
        sigma_filename = os.path.join(SIGMA_OUTPUT_DIR, os.path.basename(email_file).replace(".md", ".yml"))

        with open(sigma_filename, "w", encoding="utf-8") as f:
            yaml.dump(sigma_rule, f, default_flow_style=False, sort_keys=False)

        print(f"Generated Sigma rule: {sigma_filename}")


if __name__ == "__main__":
    process_email_reports()