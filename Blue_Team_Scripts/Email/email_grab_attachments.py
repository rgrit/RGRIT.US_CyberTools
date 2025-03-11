import os
import mailbox
import email
import base64
import mimetypes
from datetime import datetime
from collections import Counter

# Define the Thunderbird IMAP storage path (adjust as needed)
THUNDERBIRD_PROFILE = "ImapMail/127.0.0.1"
ATTACHMENTS_DIR = "email_attachments"


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


def extract_attachments(msg, email_index):
    """Extracts email_attachments from an email message and returns metadata about them."""
    attachments = []

    if not os.path.exists(ATTACHMENTS_DIR):
        os.makedirs(ATTACHMENTS_DIR)

    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get_content_disposition() is None:
            continue

        filename = part.get_filename()
        if filename:
            content_type = part.get_content_type()
            file_extension = mimetypes.guess_extension(content_type) or "unknown"
            file_data = part.get_payload(decode=True)

            if not file_data:
                print(f"⚠️ Skipping attachment '{filename}' (No valid payload)")
                continue

            file_size = len(file_data)
            attachment_path = os.path.join(ATTACHMENTS_DIR, f"email{email_index}_{filename}")

            with open(attachment_path, "wb") as f:
                f.write(file_data)

            attachments.append({
                "Filename": filename,
                "Type": content_type,
                "Extension": file_extension,
                "Size (KB)": round(file_size / 1024, 2),
                "Saved Path": attachment_path
            })

    return attachments


def generate_markdown_report(selected_folder, output_file="email_reports/email_attachments_report.md"):
    """Creates a Markdown report listing extracted email email_attachments with metadata."""
    mbox_path = find_mbox_file(selected_folder)
    if not mbox_path:
        print(f"❌ Mailbox '{selected_folder}' not found!")
        return

    mbox = mailbox.mbox(mbox_path)
    report_lines = [
        f"# Attachment Report for '{selected_folder}'",
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
        "## Extracted Attachments",
        "| Email # | Filename | Type | Extension | Size (KB) | Saved Path |",
        "|---------|----------|------|-----------|----------|-----------|"
    ]

    total_emails = len(mbox)
    print(f"📧 Processing {total_emails} emails...")

    extension_counter = Counter()

    for i, msg in enumerate(mbox):
        print(f"🔹 Extracting email_attachments from Email {i + 1}/{total_emails}...")
        email_message = email.message_from_bytes(msg.as_bytes())
        attachments = extract_attachments(email_message, i + 1)

        for attachment in attachments:
            report_lines.append(
                f"| {i + 1} | {attachment['Filename']} | {attachment['Type']} | {attachment['Extension']} | {attachment['Size (KB)']} | {attachment['Saved Path']} |"
            )
            extension_counter[attachment['Extension']] += 1

    report_lines.append("\n## Attachment Type Summary")
    report_lines.append("| File Extension | Count |")
    report_lines.append("|---------------|-------|")
    for ext, count in extension_counter.most_common():
        report_lines.append(f"| {ext} | {count} |")

    with open(output_file, "w") as md_file:
        md_file.write("\n".join(report_lines))

    print(f"✅ Markdown report generated: {output_file}")


def main():
    """Main function to list mailboxes, prompt user selection, and extract email_attachments."""
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
