#!/usr/bin/env python3
import os
import mailbox
import json
import time
import ollama
from datetime import datetime

# API Configuration
MODEL_NAME = "qwen2.5-coder:latest"  # Change this to the model you want to use

# Define the Thunderbird IMAP storage path (adjust as needed)
THUNDERBIRD_PROFILE = "ImapMail/127.0.0.1"

OUTPUT_DIR = "email_reports"  # Folder to store individual email reports

def list_available_mailboxes():
    """Returns a list of available mailbox files in the Thunderbird profile directory."""
    print("🔍 Scanning for available mailboxes...")
    mailboxes = []
    for file in os.listdir(THUNDERBIRD_PROFILE):
        full_path = os.path.join(THUNDERBIRD_PROFILE, file)
        if os.path.isfile(full_path) and not file.endswith((".msf", ".sqlite", ".dat")):
            mailboxes.append(file)
    print(f"📂 Found {len(mailboxes)} mailboxes.")
    return mailboxes

def find_mbox_file(mbox_file):
    """Search for the mailbox file by name in the Thunderbird profile directory."""
    possible_path = os.path.join(THUNDERBIRD_PROFILE, mbox_file)
    return possible_path if os.path.exists(possible_path) else None

def extract_security_metadata(msg):
    """Extracts security-relevant metadata from an email message."""
    metadata = {
        "Message-ID": msg.get("Message-ID", "(none)"),
        "From": msg.get("From", "(none)"),
        "Return-Path": msg.get("Return-Path", "(none)"),
        "Reply-To": msg.get("Reply-To", "(none)"),
        "Authentication-Results": msg.get("Authentication-Results", "(none)"),
        "DKIM-Signature": msg.get("DKIM-Signature", "(none)"),
        "Digital Signatures": [],
        "Received Headers": [],
        "X-Headers": []
    }

    if msg.get("SMIME-Version"):
        metadata["Digital Signatures"].append("SMIME present")
    if msg.get("PGP-Signature"):
        metadata["Digital Signatures"].append("PGP-Signature present")
    metadata["Digital Signatures"] = metadata["Digital Signatures"] or ["(none)"]

    for key, value in msg.items():
        if key.lower().startswith("received"):
            metadata["Received Headers"].append(f"{key}: {value}")
    metadata["Received Headers"] = metadata["Received Headers"] or ["(none)"]

    for key, value in msg.items():
        if key.lower().startswith("x-"):
            metadata["X-Headers"].append(f"{key}: {value}")
    metadata["X-Headers"] = metadata["X-Headers"] or ["(none)"]

    return metadata

def analyze_email_with_ollama(metadata):
    """Analyzes email metadata using the Ollama Python module."""
    metadata_str = json.dumps(metadata, indent=2)

    prompt = f"""
You are a **Network Security Monitoring Expert** with specialized expertise in **email communication security**. Your task is to analyze the following email metadata for potential security threats. 

### **Key Threat Indicators to Consider:**
- **Authentication Failures or Absences**  
  - Missing or invalid **DKIM, SPF, or DMARC** results.
- **Digital Signature Issues**  
  - Lack of **S/MIME** or **PGP signatures** or indications of tampering.
- **Inconsistent Received Headers**  
  - Anomalies in the email path (unexpected servers, delays, missing hops).
- **Return-Path and From/Reply-To Mismatches**  
  - Domain mismatches or unexpected reply-to addresses.
- **Unusual X-Headers**  
  - High spam scores, phishing flags, or manipulated headers.

### **Email Metadata for Analysis**

```json
{metadata_str}
```

Provide a concise summary highlighting any potential security concerns and classify them as **Info, Warning, Error, or Critical**.
"""

    try:
        print("🧠 Sending email metadata to LLM for analysis...")
        response = ollama.chat(model=MODEL_NAME, messages=[{"role": "user", "content": prompt}])
        return response.get("message", {}).get("content", "No response received from model.")
    except Exception as e:
        return f"Request error: {e}"

def generate_markdown_report(selected_folder):
    """Creates a Markdown report for each email."""
    mbox_path = find_mbox_file(selected_folder)
    if not mbox_path:
        print(f"❌ Mailbox '{selected_folder}' not found!")
        return

    mbox = mailbox.mbox(mbox_path)
    print(f"📧 Processing {len(mbox)} emails...")

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    for i, msg in enumerate(mbox, start=1):
        metadata = extract_security_metadata(msg)
        analysis = analyze_email_with_ollama(metadata)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"email_{i}_{timestamp}.md"
        output_path = os.path.join(OUTPUT_DIR, filename)

        with open(output_path, "w") as md_file:
            md_file.write(f"# Security Report for Email #{i}\n")
            md_file.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            md_file.write("## Extracted Metadata\n")
            md_file.write("```json\n" + json.dumps(metadata, indent=2) + "\n```\n\n")
            md_file.write("## LLM Analysis\n")
            md_file.write(analysis + "\n")

        print(f"✅ Report generated: {output_path}")

def main():
    """Main function to list mailboxes, prompt user selection, and generate reports."""
    mailboxes = list_available_mailboxes()
    if not mailboxes:
        print("❌ No mailbox files found in the specified profile directory.")
        return

    print("\n📂 Available Mailboxes:")
    for idx, mb in enumerate(mailboxes, start=1):
        print(f"{idx}. {mb}")

    selection = input("\nEnter the number of the mailbox to analyze: ").strip()
    try:
        selected_index = int(selection) - 1
        selected_folder = mailboxes[selected_index]
        generate_markdown_report(selected_folder)
    except (ValueError, IndexError):
        print("❌ Invalid selection. Exiting.")

if __name__ == "__main__":
    main()