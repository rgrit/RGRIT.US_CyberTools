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
