import os
import mailbox
import json
import time
import ollama
import concurrent.futures
from datetime import datetime

# API Configuration
MODEL_NAME = "granite3.2"  # Change to the desired model

# Thunderbird IMAP storage path (adjust as needed)
THUNDERBIRD_PROFILE = "ImapMail/127.0.0.1"

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

def extract_email_content(msg):
    """
    Extracts key details from an email message including headers and plain text body.
    """
    content = {
        "Message-ID": msg.get("Message-ID", "(none)"),
        "Subject": msg.get("Subject", "(none)"),
        "From": msg.get("From", "(none)"),
        "To": msg.get("To", "(none)"),
        "Date": msg.get("Date", "(none)")
    }
    # Extract plain text from the email body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                try:
                    charset = part.get_content_charset() or 'utf-8'
                    body += part.get_payload(decode=True).decode(charset, errors='replace')
                except Exception as e:
                    body += ""
    else:
        try:
            charset = msg.get_content_charset() or 'utf-8'
            body = msg.get_payload(decode=True).decode(charset, errors='replace')
        except Exception as e:
            body = msg.get_payload()
    content["Body"] = body
    return content

def analyze_email_for_actions(email_content):
    """
    Sends only the email body to the LLM and asks it to analyze whether you need to take immediate action.
    The assistant should respond with either "Immediate action required" or "No immediate action required" along with a brief explanation.
    """
    email_body = email_content.get("Body", "")
    prompt = f"""
You are a personal assistant. Read the following email and decide if it requires immediate action from you. 
Consider if you need to respond quickly, schedule a meeting, or address any urgent matter.
Please respond in a concise format as follows:
- If immediate action is required, state "Immediate action required" and briefly explain why.
- If no immediate action is required, state "No immediate action required" with a brief explanation.
Do not include extraneous commentary or analyze non-essential details.

Email:
{email_body}
"""
    print("🧠 Analyzing email for immediate action requirement...")
    response = ollama.chat(model=MODEL_NAME, messages=[{"role": "user", "content": prompt}])
    return response.get("message", {}).get("content", "No response received from model.")

def safe_analyze(email_content):
    """Wrapper for the analyze_email_for_actions function."""
    return analyze_email_for_actions(email_content)

def generate_markdown_report(selected_folder, output_file="email_reports/email_action_report.md"):
    """
    Creates a Markdown report summarizing whether each email requires immediate action.
    The report includes email details and the corresponding immediate action analysis.
    """
    mbox_path = find_mbox_file(selected_folder)
    if not mbox_path:
        print(f"❌ Mailbox '{selected_folder}' not found!")
        return

    mbox = mailbox.mbox(mbox_path)
    report_lines = [
        f"# Immediate Action Analysis Report for '{selected_folder}'",
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    ]
    total_emails = len(mbox)
    print(f"📧 Processing {total_emails} emails...")

    for i, msg in enumerate(mbox):
        start_time = datetime.now()
        print(f"🔹 Processing Email {i + 1}/{total_emails} at {start_time}...")
        email_content = extract_email_content(msg)
        analysis = ""
        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(safe_analyze, email_content)
                analysis = future.result(timeout=30)  # Timeout after 30 seconds
        except concurrent.futures.TimeoutError:
            analysis = "API call timed out."
            print(f"⏰ Timeout processing Email #{i + 1}")
        except Exception as e:
            analysis = f"Error during analysis: {e}"
            print(f"❌ Error processing Email #{i + 1}: {e}")
        end_time = datetime.now()
        print(f"✅ Finished processing Email {i + 1} at {end_time}. Duration: {end_time - start_time}")

        subject = email_content.get("Subject", "(no subject)")
        report_lines.append(f"**Email #{i + 1}**")
        report_lines.append(f"**Subject:** {subject}")
        report_lines.append(f"**From:** {email_content.get('From', '(none)')}")
        report_lines.append(f"**Date:** {email_content.get('Date', '(none)')}\n")
        report_lines.append("### Immediate Action Analysis")
        report_lines.append(analysis)
        report_lines.append("\n---\n")

        time.sleep(0.5)  # Small delay to be gentle on the API

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as md_file:
        md_file.write("\n".join(report_lines))
    print(f"✅ Markdown report generated: {output_file}")

def main():
    """Main function to list mailboxes, prompt user selection, and generate the immediate action analysis report."""
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
        if selected_index < 0 or selected_index >= len(mailboxes):
            print("❌ Invalid selection. Exiting.")
            return
    except ValueError:
        print("❌ Please enter a valid number. Exiting.")
        return

    selected_folder = mailboxes[selected_index]
    generate_markdown_report(selected_folder)

if __name__ == "__main__":
    main()
