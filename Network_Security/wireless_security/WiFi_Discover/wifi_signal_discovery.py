# import os
# import subprocess
# import re
# import matplotlib
# import matplotlib.pyplot as plt
#
# # Use TkAgg to avoid issues in non-GUI environments
# matplotlib.use("TkAgg")
#
#
# def scan_wifi():
#     """Scans nearby WiFi networks and returns a list of SSIDs with signal strength."""
#     networks = {}
#
#     try:
#         # Linux/macOS: Use `nmcli`
#         if os.name != "nt":
#             scan_output = subprocess.check_output(["nmcli", "-f", "SSID,SIGNAL", "dev", "wifi"],
#                                                   universal_newlines=True)
#             lines = scan_output.strip().split("\n")[1:]  # Skip header
#
#             for line in lines:
#                 parts = line.split()
#                 if len(parts) >= 2:
#                     ssid = " ".join(parts[:-1]).strip() or "Hidden Network"
#                     signal_strength = int(parts[-1])
#
#                     # Store the highest signal strength per SSID
#                     if ssid not in networks or networks[ssid] < signal_strength:
#                         networks[ssid] = signal_strength
#
#         # Windows: Use `netsh`
#         else:
#             scan_output = subprocess.check_output("netsh wlan show networks mode=bssid", shell=True,
#                                                   universal_newlines=True)
#             ssids = re.findall(r"SSID \d+ : (.+)", scan_output)
#             strengths = [int(s) for s in re.findall(r"Signal\s*:\s*(\d+)", scan_output)]
#
#             for ssid, signal in zip(ssids, strengths):
#                 ssid = ssid.strip() or "Hidden Network"
#                 if ssid not in networks or networks[ssid] < signal:
#                     networks[ssid] = signal
#
#     except Exception as e:
#         print(f"Error scanning WiFi networks: {e}")
#
#     return networks
#
#
# def plot_wifi(networks):
#     """Plots WiFi networks based on signal strength."""
#     if not networks:
#         print("No WiFi networks found.")
#         return
#
#     sorted_networks = sorted(networks.items(), key=lambda x: x[1], reverse=True)
#
#     ssids = [n[0] for n in sorted_networks]
#     strengths = [n[1] for n in sorted_networks]
#
#     plt.figure(figsize=(12, 6))
#     plt.barh(ssids, strengths, color='blue', alpha=0.7)
#     plt.xlabel("Signal Strength (%)")
#     plt.ylabel("WiFi Network (SSID)")
#     plt.title("Nearby WiFi Networks")
#     plt.gca().invert_yaxis()
#     plt.grid(axis='x', linestyle='--', alpha=0.7)
#
#     # Save image instead of displaying (useful for headless environments)
#     plt.savefig("wifi_signal_chart.png")
#     print("✅ WiFi visualization saved as 'wifi_signal_chart.png'")
#
#
# if __name__ == "__main__":
#     print("🔍 Scanning for WiFi networks...")
#     wifi_networks = scan_wifi()
#
#     if wifi_networks:
#         print("\n📡 Available WiFi Networks:\n")
#         for ssid, strength in wifi_networks.items():
#             print(f"SSID: {ssid}, Signal: {strength}%")
#
#         print("\n📊 Generating visualization...")
#         plot_wifi(wifi_networks)
#     else:
#         print("❌ No WiFi networks found.")
#
import os
import subprocess
import re
import matplotlib
import matplotlib.pyplot as plt
from datetime import datetime

# Use TkAgg to avoid issues in non-GUI environments
matplotlib.use("TkAgg")


def scan_wifi():
    """Scans nearby WiFi networks and returns a dictionary of SSIDs with their highest signal strength."""
    networks = {}
    try:
        # Linux/macOS: Use `nmcli`
        if os.name != "nt":
            scan_output = subprocess.check_output(
                ["nmcli", "-f", "SSID,SIGNAL", "dev", "wifi"],
                universal_newlines=True
            )
            lines = scan_output.strip().split("\n")[1:]  # Skip header

            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    ssid = " ".join(parts[:-1]).strip() or "Hidden Network"
                    signal_strength = int(parts[-1])
                    # Store the highest signal strength per SSID
                    if ssid not in networks or networks[ssid] < signal_strength:
                        networks[ssid] = signal_strength

        # Windows: Use `netsh`
        else:
            scan_output = subprocess.check_output(
                "netsh wlan show networks mode=bssid", shell=True,
                universal_newlines=True
            )
            ssids = re.findall(r"SSID \d+ : (.+)", scan_output)
            strengths = [int(s) for s in re.findall(r"Signal\s*:\s*(\d+)", scan_output)]
            for ssid, signal in zip(ssids, strengths):
                ssid = ssid.strip() or "Hidden Network"
                if ssid not in networks or networks[ssid] < signal:
                    networks[ssid] = signal

    except Exception as e:
        print(f"Error scanning WiFi networks: {e}")

    return networks


def plot_wifi(networks):
    """Plots WiFi networks based on signal strength and saves the figure."""
    if not networks:
        print("No WiFi networks found.")
        return

    sorted_networks = sorted(networks.items(), key=lambda x: x[1], reverse=True)
    ssids = [n[0] for n in sorted_networks]
    strengths = [n[1] for n in sorted_networks]

    plt.figure(figsize=(12, 6))
    bars = plt.barh(ssids, strengths, color='blue', alpha=0.7)
    # Add signal strength labels to each bar
    plt.bar_label(bars)
    plt.xlabel("Signal Strength (%)")
    plt.ylabel("WiFi Network (SSID)")
    plt.title("Nearby WiFi Networks")
    plt.gca().invert_yaxis()  # Highest signal at the top
    plt.grid(axis='x', linestyle='--', alpha=0.7)

    # Save image instead of displaying (useful for headless environments)
    plt.savefig("wireless_security/wireless_reports/wifi_signal_chart.png")
    print("✅ WiFi visualization saved as 'wifi_signal_chart.png'")


def generate_wifi_report(networks, output_file="wireless_security/wireless_reports/wifi_report.md"):
    """Generates a detailed Markdown report including a summary table, detailed results, and a reference to the visualization."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sorted_networks = sorted(networks.items(), key=lambda x: x[1], reverse=True)
    report_lines = [
        f"# WiFi Scan Report",
        f"Generated on: {timestamp}",
        "",
        "## Summary of Networks",
        "",
        "| Rank | SSID | Signal Strength (%) | Category |",
        "|------|------|---------------------|----------|"
    ]
    # Define categories based on signal strength
    for rank, (ssid, strength) in enumerate(sorted_networks, start=1):
        if strength >= 75:
            category = "Strong"
        elif strength >= 50:
            category = "Good"
        else:
            category = "Weak"
        report_lines.append(f"| {rank} | {ssid} | {strength} | {category} |")

    report_lines.extend([
        "",
        "## Detailed Results",
        ""
    ])
    for ssid, strength in sorted_networks:
        if strength >= 75:
            category = "Strong"
        elif strength >= 50:
            category = "Good"
        else:
            category = "Weak"
        report_lines.extend([
            f"- **SSID:** {ssid}",
            f"  - Signal Strength: {strength}%",
            f"  - Category: {category}",
            ""
        ])

    report_lines.extend([
        "## Visualization",
        "The following chart shows the WiFi networks and their signal strengths:",
        "![WiFi Signal Chart](wifi_signal_chart.png)"
    ])

    with open(output_file, "w") as f:
        f.write("\n".join(report_lines))
    print(f"✅ Detailed WiFi report generated as '{output_file}'.")


if __name__ == "__main__":
    print("🔍 Scanning for WiFi networks...")
    wifi_networks = scan_wifi()

    if wifi_networks:
        print("\n📡 Available WiFi Networks:\n")
        for ssid, strength in wifi_networks.items():
            print(f"SSID: {ssid}, Signal: {strength}%")

        print("\n📊 Generating visualization...")
        plot_wifi(wifi_networks)
        print("\n📝 Generating detailed report...")
        generate_wifi_report(wifi_networks)
    else:
        print("❌ No WiFi networks found.")
