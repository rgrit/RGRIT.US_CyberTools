import os
import mailbox
import email
from collections import Counter

# Define the Thunderbird IMAP storage path (adjust as needed)
THUNDERBIRD_PROFILE = "/ImapMail/127.0.0.1"


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


def extract_senders(selected_folder, output_file="Email/email_reports/email_senders_list.md"):
    """Extracts a list of all senders' email addresses and their occurrence count."""
    mbox_path = find_mbox_file(selected_folder)
    if not mbox_path:
        print(f"❌ Mailbox '{selected_folder}' not found!")
        return

    mbox = mailbox.mbox(mbox_path)
    sender_counter = Counter()

    total_emails = len(mbox)
    print(f"📧 Processing {total_emails} emails...")

    for i, msg in enumerate(mbox):
        print(f"🔹 Extracting sender from Email {i + 1}/{total_emails}...")
        email_message = email.message_from_bytes(msg.as_bytes())
        sender = email_message.get("From", "Unknown")
        sender_counter[sender] += 1

    report_lines = [
        f"# Senders List for '{selected_folder}'",
        "## Email Sender Count",
        "| Sender | Count |",
        "|--------|-------|"
    ]

    for sender, count in sender_counter.most_common():
        report_lines.append(f"| {sender} | {count} |")

    with open(output_file, "w") as md_file:
        md_file.write("\n".join(report_lines))

    print(f"✅ Sender list report generated: {output_file}")


def main():
    """Main function to list mailboxes, prompt user selection, and extract sender addresses."""
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
    extract_senders(selected_folder)


if __name__ == "__main__":
    main()
