import csv
from collections import Counter


def filter_open_and_wep(csv_file):
    """
    Reads the CSV file and returns a list of rows (as dictionaries) for
    networks that are either open (no strong encryption) or use WEP encryption.

    A network is considered open if its AuthMode does not contain any of:
      - WPA, WPA2, RSN, WPA-EAP, RSN-EAP

    Additionally, any network with "WEP" in the AuthMode (case-insensitive) is included.
    """
    filtered_networks = []
    with open(csv_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            authmode = row.get('AuthMode', '').upper()
            # If the network uses WEP encryption, include it.
            if "WEP" in authmode:
                filtered_networks.append(row)
            # Otherwise, if none of the strong encryption keywords are present, consider it open.
            elif not any(keyword in authmode for keyword in ["WPA", "WPA2", "RSN", "WPA-EAP", "RSN-EAP"]):
                filtered_networks.append(row)
    return filtered_networks


def generate_markdown_report(networks, output_file='weak_auth_report.md'):
    """
    Generates a Markdown report with a table at the top listing the AuthModes
    (from the filtered networks) sorted by descending count, followed by details
    for each network.
    """
    # Count AuthModes in the filtered list
    auth_modes = [row.get("AuthMode", "N/A").strip() for row in networks]
    auth_counter = Counter(auth_modes)

    # Sort auth modes by descending count
    sorted_auth = sorted(auth_counter.items(), key=lambda x: x[1], reverse=True)

    with open(output_file, 'w', encoding='utf-8') as f:
        # Report title
        f.write("# Open and WEP WiFi Networks Report\n\n")
        f.write("This report lists WiFi networks found with no encryption (open networks) or with WEP encryption.\n\n")

        # AuthMode table header
        f.write("## AuthMode Frequency\n\n")
        f.write("| AuthMode | Count |\n")
        f.write("|----------|-------|\n")
        for mode, count in sorted_auth:
            f.write(f"| {mode} | {count} |\n")
        f.write("\n---\n\n")

        # List details for each network
        if not networks:
            f.write("No networks found with open or WEP encryption.\n")
        else:
            for i, row in enumerate(networks, start=1):
                f.write(f"### Network {i}\n")
                f.write(f"- **MAC:** {row.get('MAC', 'N/A')}\n")
                f.write(f"- **SSID:** {row.get('SSID', 'N/A')}\n")
                f.write(f"- **AuthMode:** {row.get('AuthMode', 'N/A')}\n")
                f.write(f"- **FirstSeen:** {row.get('FirstSeen', 'N/A')}\n")
                f.write(f"- **Channel:** {row.get('Channel', 'N/A')}\n")
                f.write(f"- **Frequency:** {row.get('Frequency', 'N/A')}\n")
                f.write(f"- **RSSI:** {row.get('RSSI', 'N/A')}\n")
                f.write("\n")
    print("Markdown report generated:", output_file)


if __name__ == "__main__":
    csv_file = "<<YOUR CLEANED DATA>>"  # Update with your CSV file path
    networks = filter_open_and_wep(csv_file)
    print(f"Found {len(networks)} networks with open or WEP encryption.")
    generate_markdown_report(networks)
