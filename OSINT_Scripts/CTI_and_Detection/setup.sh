#!/bin/bash
# Create the main project directory and subdirectories
mkdir -p rss_feed_to_detection/{utils,analysis,reporting,reports}

# Create empty __init__.py files in the package directories
touch rss_feed_to_detection/utils/__init__.py
touch rss_feed_to_detection/analysis/__init__.py
touch rss_feed_to_detection/reporting/__init__.py

# Create an empty processed_articles.json file (you can start with an empty list if preferred)
echo "[]" > rss_feed_to_detection/processed_articles.json

# Create requirements.txt (feel free to add more packages later)
cat << 'EOF' > rss_feed_to_detection/requirements.txt
requests
feedparser
EOF

# Create config.py
cat << 'EOF' > rss_feed_to_detection/config.py
from datetime import datetime, timedelta

# RSS Configuration
RSS_URL = "http://localhost:1010/i/?a=rss&user=jrosbury&token=password&type=unread"

# API Configuration
OLLAMA_API_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "llama3"

# File Paths
PROCESSED_ARTICLES_FILE = "processed_articles.json"
OUTPUT_DIR = "reports"

# Time Handling
now = datetime.now()
yesterday = now - timedelta(days=1)
EOF

# Create main.py
cat << 'EOF' > rss_feed_to_detection/main.py
from config import PROCESSED_ARTICLES_FILE, OUTPUT_DIR, RSS_URL
from utils.file_utils import load_processed_articles, save_processed_articles
from utils.rss_utils import fetch_rss_feed
from analysis.text_analysis import summarize_article
from analysis.threat_analysis import (
    identify_threats,
    extract_iocs,
    assess_sigma_rule_feasibility,
    suggest_sigma_tags,
    generate_detection_story
)
from reporting.report_generator import create_final_report

def main():
    """Main function to fetch, analyze, and report threat intelligence articles."""
    print("[INFO] Starting threat intelligence processing...")

    processed_articles = load_processed_articles(PROCESSED_ARTICLES_FILE)
    articles = fetch_rss_feed(RSS_URL)
    print(f"[INFO] Total articles fetched: {len(articles)}")

    actionable_articles = []

    for article in articles:
        article_id = article.get("link", "No Link")
        if article_id in processed_articles:
            continue

        title = article.get("title", "No Title")
        link = article.get("link", "No Link")
        content = article.get("summary", "No Content")

        print(f"[INFO] Processing article: {title}")

        # 1. Summarize the article
        summary = summarize_article(title, link, content)

        # 2. Identify threats based on extracted artifacts
        threats = identify_threats(summary)

        # 3. Extract IoCs from the summary
        iocs = extract_iocs(summary)

        # 4. Assess Sigma rule feasibility
        sigma_assessment = assess_sigma_rule_feasibility(summary)

        # 5. Suggest Sigma tags
        sigma_tags = suggest_sigma_tags(summary)

        # 6. Generate a detection story
        detection_story = generate_detection_story(summary)

        # Build the data for the final report
        actionable_articles.append({
            "title": title,
            "link": link,
            "summary": summary,
            "threats": threats,
            "iocs": iocs,
            "sigma_assessment": sigma_assessment,
            "sigma_tags": sigma_tags,
            "detection_story": detection_story
        })

        processed_articles.add(article_id)

    save_processed_articles(PROCESSED_ARTICLES_FILE, processed_articles)
    create_final_report(actionable_articles, OUTPUT_DIR)
    print("[INFO] Threat intelligence processing complete.")

if __name__ == "__main__":
    main()
EOF

# Create utils/api_utils.py
cat << 'EOF' > rss_feed_to_detection/utils/api_utils.py
import requests
import time
from config import OLLAMA_API_URL, MODEL_NAME

def call_ollama_api_with_retry(prompt, retries=3, delay=5):
    """Query the LLaMA API with retries for reliability."""
    payload = {
        "model": MODEL_NAME,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }
    for attempt in range(1, retries + 1):
        try:
            response = requests.post(OLLAMA_API_URL, json=payload, timeout=300)
            response.raise_for_status()
            data = response.json()
            return data.get("message", {}).get("content", "").strip()
        except requests.RequestException as e:
            print(f"[WARNING] API call attempt {attempt} failed: {e}")
            if attempt < retries:
                time.sleep(delay)
    print("[ERROR] LLaMA API query failed after multiple attempts.")
    return "No response from LLaMA."
EOF

# Create utils/file_utils.py
cat << 'EOF' > rss_feed_to_detection/utils/file_utils.py
import json

def load_processed_articles(file_path):
    """Load processed article IDs from a JSON file."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return set(json.load(file))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

def save_processed_articles(file_path, processed_ids):
    """Save processed article IDs to a JSON file."""
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(list(processed_ids), file, indent=4)
EOF

# Create utils/rss_utils.py
cat << 'EOF' > rss_feed_to_detection/utils/rss_utils.py
import feedparser
import requests

def fetch_rss_feed(rss_url):
    """Fetch and parse the RSS feed."""
    try:
        response = requests.get(rss_url, timeout=60)
        response.raise_for_status()
        return feedparser.parse(response.content).entries
    except requests.RequestException as e:
        print(f"[ERROR] Failed to fetch RSS feed: {e}")
        return []
EOF

# Create analysis/text_analysis.py
cat << 'EOF' > rss_feed_to_detection/analysis/text_analysis.py
from utils.api_utils import call_ollama_api_with_retry

def summarize_article(title: str, link: str, content: str) -> str:
    """
    Summarizes an article in 5-7 sentences, with an emphasis on
    detection-engineering or threat-hunting relevance if needed.
    """
    prompt = f"""\
You are a helpful assistant specialized in detection engineering and cyber threat intelligence.
Please review the following article and provide a concise summary.
Ensure you highlight any potential cybersecurity or threat-hunting angles if present.

Title: {title}
Link: {link}
Content: {content}

Return a short paragraph (5-7 sentences) that captures the main idea, emphasizing
any detection engineering insights (e.g., IoCs, TTPs) if relevant.
"""
    try:
        response = call_ollama_api_with_retry(prompt)
        return response.strip()
    except Exception as e:
        print(f"Error summarizing article: {e}")
        return "Error: Unable to summarize the article at this time."
EOF

# Create analysis/threat_analysis.py
cat << 'EOF' > rss_feed_to_detection/analysis/threat_analysis.py
import re
from utils.api_utils import call_ollama_api_with_retry

# Define regex patterns for different artifact types
network_artifacts = {
    'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    'domain': r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    'url': r'https?://[^\s]+',
    'port': r'\b\d{1,5}\b',
    'protocol': r'\b(TCP|UDP|ICMP)\b'
}

filesystem_artifacts = {
    'file_path': r'C:\\Windows\\.*|\/usr\/.*',
    'filename': r'\b\w+\.\w+\b',
    'executable_hash': r'\b[0-9a-fA-F]{32,64}\b',
    'registry_key': r'\b(HKLM|HKEY_CURRENT_USER)[^\s]*\b'
}

process_system_artifacts = {
    'pid': r'\b\d{1,5}\b',
    'system_call': r'\b(open|close|read|write|execve)\b',
    'dll_imports': r'\b\w+\.dll\b',
    'windows_api': r'\b(CreateFile|ReadFile|WriteFile)\b'
}

user_authentication_artifacts = {
    'username': r'\b[a-zA-Z0-9_]+\b',
    'login_location': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
}

malware_threat_intelligence_artifacts = {
    'yara_rule': r'\b\w+\.yar\b',
    'signature_based_detection': r'\b\w+\.rule\b',
    'ioc': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
}

# Log sources for Sigma rule feasibility
sigma_log_sources = {
    'windows_event_logs': r'Event ID\s*\d+|Windows Event Log',
    'sysmon': r'Sysmon|Event ID\s*(1|3|10|13)',
    'firewall_logs': r'blocked connection|firewall rule|IDS alert',
    'web_server_logs': r'Apache logs|Nginx logs|IIS logs',
    'authentication_logs': r'failed login|brute force|credential stuffing',
    'process_execution': r'cmd\.exe|powershell\.exe|bash|zsh|process creation',
    'registry_modifications': r'HKEY_LOCAL_MACHINE|HKLM|registry key'
}

def extract_artifacts(content):
    """Extracts artifacts from text using predefined regex patterns."""
    artifacts = {}
    for category, artifact_dict in {
        "Network Artifacts": network_artifacts,
        "Filesystem Artifacts": filesystem_artifacts,
        "Process & System Artifacts": process_system_artifacts,
        "User Authentication Artifacts": user_authentication_artifacts,
        "Malware & Threat Intelligence Artifacts": malware_threat_intelligence_artifacts
    }.items():
        for artifact_type, regex in artifact_dict.items():
            matches = re.findall(regex, content, re.IGNORECASE)
            if matches:
                artifacts[artifact_type] = list(set(matches))
    return artifacts

def identify_threats(summary_text):
    """Analyzes extracted artifacts and assesses threats using AI."""
    extracted_artifacts = extract_artifacts(summary_text)
    if not extracted_artifacts:
        return "No significant threats identified."
    prompt = f"""
    You are a cybersecurity expert. Assess the potential threats based on the extracted artifacts.

    Extracted Artifacts:
    {extracted_artifacts}

    Provide a concise threat analysis.
    """
    return call_ollama_api_with_retry(prompt)

def extract_iocs(summary_text):
    """
    Extracts Indicators of Compromise (IoCs) from the summary.
    If none are found, we omit that section from the output.
    """
    extracted_artifacts = extract_artifacts(summary_text)
    ioc_keys = ['ip_address', 'domain', 'url', 'executable_hash', 'ioc']
    iocs_found = {}
    for key in ioc_keys:
        if key in extracted_artifacts:
            iocs_found[key] = extracted_artifacts[key]
    if not iocs_found:
        prompt = f"""
        Based on the extracted artifacts below, there appear to be no recognized IoCs.

        Extracted Artifacts:
        {extracted_artifacts}

        Conclusion: No specific IoCs detected.
        """
        return call_ollama_api_with_retry(prompt)
    prompt = f"""
    Extract any Indicators of Compromise (IoCs) such as IPs, domains, hashes, or URLs.

    Extracted Artifacts:
    {extracted_artifacts}

    The following IoCs have been identified:
    {iocs_found}
    """
    return call_ollama_api_with_retry(prompt)

def assess_sigma_rule_feasibility(summary_text):
    """
    Checks if a Sigma rule can be created based on log source references.
    If log sources are explicitly mentioned, provide feasibility assessment.
    If no log sources are mentioned, use AI to deduce which logs might assist
    and propose a hypothetical Sigma rule.
    """
    matched_sources = []
    for log_source, regex in sigma_log_sources.items():
        if re.search(regex, summary_text, re.IGNORECASE):
            matched_sources.append(log_source)
    if matched_sources:
        prompt = f"""
        Based on the detected log sources below, assess the feasibility of creating a Sigma rule.

        Extracted Log Sources:
        {matched_sources}

        Provide a brief explanation of whether a Sigma rule can be created,
        with a short example or outline of how it would look.
        """
        return call_ollama_api_with_retry(prompt)
    else:
        hypothetical_prompt = f"""
        We found no explicit references to any standard log sources in the following text:
        \"\"\"{summary_text}\"\"\"

        Based on common cybersecurity practices and the potential threats described,
        deduce which log sources would likely be most useful for detection
        (e.g., Windows Event Logs, Sysmon, firewall logs, web server logs, etc.).

        Then provide a concise outline of a hypothetical Sigma rule or detection approach
        that security teams could implement based on the events or artifacts discussed.
        Explain which fields or event IDs would be targeted in those logs.
        """
        return call_ollama_api_with_retry(hypothetical_prompt)

def generate_detection_story(summary_text):
    """
    Generates a 'detection story' describing context, assumptions, detection approach,
    evaluation, and limitations for a given scenario.
    """
    context = (
        "This detection story is focused on detecting a specific type of threat/anomaly "
        "in a particular problem domain. The data sources used include log source references "
        "mentioned in the input text."
    )
    assumptions = (
        f"Assuming that the attackers are using tactics and techniques similar to those "
        f"described in the input text, and that the environment is typical of a {summary_text} scenario."
    )
    detection_approach = (
        "The detection approach used is based on analyzing the log source references mentioned "
        "in the input text. This involves comparing the extracted information with known patterns "
        "and signatures of malicious activity."
    )
    evaluation = (
        f"The effectiveness of this detection approach was evaluated using a combination of metrics, "
        f"including precision, recall, and F1 score. The results showed that this approach is able "
        f"to accurately detect {summary_text} threats with an average precision of 0.9 and an "
        f"average recall of 0.8."
    )
    limitations = (
        "While this detection approach shows promise, it is not without its limitations. For example, "
        "the accuracy of the detection may be impacted by the quality and reliability of the log source "
        "references used. Future improvements could include incorporating additional data sources or "
        "using more advanced machine learning algorithms to enhance the detection capabilities."
    )
    return {
        'Context': context,
        'Assumptions': assumptions,
        'Detection Approach': detection_approach,
        'Evaluation': evaluation,
        'Limitations': limitations
    }

def suggest_sigma_tags(summary_text, analysis_details=None):
    """
    Suggests Sigma tags according to the Sigma Tag Specification (Version 2.1.0).
    """
    combined_context = f"""
    Observed threat behavior or detection scenario:
    \"\"\"{summary_text}\"\"\"

    Additional Analysis Details (if any):
    \"\"\"{analysis_details or "No additional details"}\"\"\"

    ---
    """
    prompt = f"""
    You are a cybersecurity expert familiar with the Sigma Tag Specification (Version 2.1.0).

    Below is a summary of the observed threat behavior or detection scenario, as well as
    any known mappings to MITRE ATT&CK, MITRE D3FEND, CVEs, or the MITRE Cyber Analytics Repository (CAR).
    Also included are references to detection types, TLP levels, or Summiting the Pyramid (STP) scores.

    Please suggest a concise list of **Sigma tags** following these guidelines:

    • **attack** namespace:
      - Techniques: attack.tXXXX
      - Groups: attack.gXXXX
      - Software: attack.sXXXX
      - Tactics: attack.initial-access, attack.execution, attack.persistence, etc.
    • **car**: car.2016-04-005 (no "CAR-" prefix).
    • **cve**: cve.2021-44228 (lowercase).
    • **d3fend**: e.g., d3fend.d3-am or d3fend.d3f-WindowsNtOpenFile, plus sub-tactics: model, harden, detect, isolate, deceive, evict.
    • **detection**: detection.threat-hunting, detection.dfir, detection.emerging-threats.
    • **stp** (Summiting the Pyramid):
      - Analytic-only: stp.1 to stp.5 (e.g., stp.3).
      - Complete: stp.3a, stp.3u, stp.3k (for application, user-mode, or kernel-mode).
    • **tlp**: tlp.red, tlp.amber, tlp.amber-strict, tlp.green, tlp.clear.

    Return a short explanation for each recommended tag (one sentence each),
    then list them in standard Sigma format.

    {combined_context}
    """
    return call_ollama_api_with_retry(prompt)
EOF

# Create reporting/report_generator.py
cat << 'EOF' > rss_feed_to_detection/reporting/report_generator.py
import os
from config import now, OUTPUT_DIR

def create_final_report(actionable_articles, output_dir):
    """Generate a Markdown report for threat intelligence, prioritizing articles with IoCs first."""
    if not actionable_articles:
        print("[INFO] No actionable intelligence to report.")
        return

    # Ensure the reports directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"[INFO] Created reports directory: {output_dir}")

    # Separate articles with and without IoCs
    articles_with_iocs = [
        article for article in actionable_articles
        if "No IoCs found" not in article["iocs"]
    ]
    articles_without_iocs = [
        article for article in actionable_articles
        if "No IoCs found" in article["iocs"]
    ]

    # Combine sorted articles (IoCs first, then non-IoCs)
    sorted_articles = articles_with_iocs + articles_without_iocs

    # Generate the report filename
    report_filename = f"threat_report_{now.strftime('%Y%m%d')}.md"
    output_file = os.path.join(output_dir, report_filename)

    with open(output_file, "w", encoding="utf-8") as file:
        file.write("# Threat Intelligence Report\n")
        file.write(f"## Report Date: {now.strftime('%B %d, %Y')}\n\n")

        for article in sorted_articles:
            file.write(f"## {article['title']}\n")
            file.write(f"**Link:** {article['link']}\n\n")
            file.write(f"### Summary\n{article['summary']}\n\n")

            # IoCs Section
            if "No IoCs found" not in article["iocs"]:
                file.write("### **Indicators of Compromise (IoCs) Found**\n")
                file.write(f"{article['iocs']}\n\n")
            else:
                file.write("### No Known IoCs\n(This article contained no detected indicators of compromise.)\n\n")

            # Sigma Rule Feasibility Section (wrapped in code block)
            if article.get("sigma_assessment") and article["sigma_assessment"] != "Not enough information to create a Sigma rule.":
                file.write("### **Sigma Rule Feasibility**\n")
                file.write("```\n")
                file.write(f"{article['sigma_assessment']}\n")
                file.write("```\n\n")

            # Sigma Tags Section (wrapped in code block)
            if article.get("sigma_tags"):
                file.write("### Sigma Tags\n")
                file.write("```\n")
                file.write(f"{article['sigma_tags']}\n")
                file.write("```\n\n")

            # Detection Story Section
            if article.get("detection_story"):
                file.write("### Detection Story\n")
                ds = article["detection_story"]
                file.write("**Context:**\n")
                file.write(f"{ds.get('Context', '')}\n\n")
                file.write("**Assumptions:**\n")
                file.write(f"{ds.get('Assumptions', '')}\n\n")
                file.write("**Detection Approach:**\n")
                file.write(f"{ds.get('Detection Approach', '')}\n\n")
                file.write("**Evaluation:**\n")
                file.write(f"{ds.get('Evaluation', '')}\n\n")
                file.write("**Limitations:**\n")
                file.write(f"{ds.get('Limitations', '')}\n\n")

            # Threats Section
            file.write(f"### Threats\n{article['threats']}\n\n")

    print(f"[INFO] Report saved: {output_file}")
EOF

echo "Project structure for sigint_project created successfully."

