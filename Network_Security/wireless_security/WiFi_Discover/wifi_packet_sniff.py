#!/usr/bin/env python3
# sudo -E $(which python3) wifi_packet_sniff.py

"""
wifi_packet_sniff_report.py

Captures WiFi packets in monitor mode for 1 minute, then writes a detailed
Markdown report with:
  - SSID, BSSID
  - Channel
  - Encryption type guess
  - Signal strength (if available)
  - Associated clients
  - Potential next-step attack commands
"""

import os
import sys
import re
import getpass
import subprocess
from collections import defaultdict
from scapy.all import (
    sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11FCS,
    RadioTap
)

REPORT_FILENAME = "../wireless_reports/wifi_sniff_report.md"
CAPTURE_DURATION = 5 # seconds

###############################################################################
# 1) Privilege & Monitor Mode Setup
###############################################################################

def ensure_root():
    """If not running as root, prompt for sudo password and re-run the script."""
    if os.geteuid() != 0:
        print("🔑 Script not running as root, requesting sudo access...")
        sudo_password = getpass.getpass("Enter your sudo password: ")

        # Re-run this script with sudo
        cmd = ["sudo", "-S", sys.executable, *sys.argv]
        try:
            result = subprocess.run(cmd, input=sudo_password + "\n", text=True)
            if result.returncode != 0:
                print("❌ Failed to elevate privileges.")
            sys.exit(result.returncode)
        except subprocess.CalledProcessError as e:
            print("❌ Error running sudo:", e)
            sys.exit(e.returncode)

def enable_monitor_mode(interface="wlp3s0"):
    """
    Calls 'airmon-ng start <interface>' to enable monitor mode.
    Returns the new monitor interface name (e.g. 'wlp3s0mon').
    """
    print(f"🚀 Enabling monitor mode on {interface}...")
    result = subprocess.run(["airmon-ng", "start", interface],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print("❌ Failed to enable monitor mode:", result.stderr)
        sys.exit(1)

    new_iface = interface + "mon"  # fallback guess
    # Attempt to parse airmon-ng output
    match = re.search(r"monitor mode vif enabled on \[([^\]]+)\]", result.stdout)
    if match:
        new_iface = match.group(1)
    else:
        match2 = re.search(r"(\S+) \(monitor mode enabled\)", result.stdout)
        if match2:
            new_iface = match2.group(1)

    print(f"✅ Monitor mode enabled on {new_iface}")
    return new_iface

def disable_monitor_mode(interface):
    """
    Calls 'airmon-ng stop <interface>' to disable monitor mode.
    """
    print(f"💤 Disabling monitor mode on {interface}...")
    result = subprocess.run(["airmon-ng", "stop", interface],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print("❌ Failed to disable monitor mode:", result.stderr)
    else:
        print("✅ Monitor mode disabled.")

###############################################################################
# 2) Encryption + Channel + Clients + Signal
###############################################################################

def detect_encryption(pkt):
    """
    Attempt to detect encryption type (Open, WPA/RSN, WEP) by checking Dot11Elt layers.
    This is a simplified approach:
      - If we find an RSN/WPA or vendor-specific fields, we assume WPA/WPA2/WPA3.
      - If none found, likely 'Open' or WEP.
    """
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return None

    for elt in pkt.iterpayloads():
        # ID 48 => RSN info
        if isinstance(elt, Dot11Elt) and elt.ID == 48:
            return "WPA/WPA2 (RSN)"
        # ID 221 => vendor-specific; check for 'WPA' in info
        if isinstance(elt, Dot11Elt) and elt.ID == 221 and b"WPA" in elt.info:
            return "WPA (Vendor)"

    return "Open or WEP"

def parse_channel(pkt):
    """
    Extract channel from DS Parameter Set (Dot11Elt ID=3).
    If not found, return 'Unknown'.
    """
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        chan_elt = pkt.getlayer(Dot11Elt, ID=3)
        if chan_elt and chan_elt.info:
            return chan_elt.info[0]  # single byte channel
    return None

def parse_signal(pkt):
    """
    Attempt to get RSSI/dBm from the RadioTap header.
    Not always available depending on driver/OS.
    """
    radio = pkt.getlayer(RadioTap)
    if radio and hasattr(radio, 'dBm_AntSignal'):
        return radio.dBm_AntSignal
    return None

def is_broadcast_or_multicast(mac):
    """Check if MAC is broadcast (ff:ff:ff:ff:ff:ff) or multicast."""
    return mac.lower().startswith("ff:ff:ff") or mac.lower()[1] in ["1", "3", "5", "7", "9", "b", "d", "f"]

###############################################################################
# 3) Main
###############################################################################

def main():
    ensure_root()

    base_iface = "wlp3s0"
    mon_iface = enable_monitor_mode(base_iface)

    print(f"🕵️ Sniffing WiFi packets on {mon_iface} for {CAPTURE_DURATION} seconds...")

    # We'll store all packets to analyze after sniffing
    packets = sniff(iface=mon_iface, timeout=CAPTURE_DURATION, store=True)

    print(f"⏱ {CAPTURE_DURATION} seconds is up! Stopping sniff.")
    disable_monitor_mode(mon_iface)

    total_packets = len(packets)
    mgmt_count, ctrl_count, data_count = 0, 0, 0

    # { (SSID, BSSID): { "encryption": ..., "channel": ..., "signal": [..], "clients": set() } }
    discovered_networks = {}
    # Keep a quick set of known BSSIDs so we can track associated clients
    known_bssids = set()

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue

        # Tally mgmt/ctrl/data
        t = pkt[Dot11].type
        if t == 0:
            mgmt_count += 1
        elif t == 1:
            ctrl_count += 1
        elif t == 2:
            data_count += 1

        # If it's a beacon/probe, parse network info
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ssid = pkt[Dot11Elt].info.decode(errors="ignore") or "<hidden>"
            bssid = pkt[Dot11].addr2
            enc_type = detect_encryption(pkt)
            chan = parse_channel(pkt) or "?"
            rssi = parse_signal(pkt)

            # Insert or update discovered_networks
            key = (ssid, bssid)
            if key not in discovered_networks:
                discovered_networks[key] = {
                    "encryption": enc_type,
                    "channel": chan,
                    "signals": [],
                    "clients": set()
                }
            if rssi is not None:
                discovered_networks[key]["signals"].append(rssi)

            known_bssids.add(bssid)

        # Try to detect client connections
        # If a BSSID is in known_bssids, and the other address is unique
        # We add that to the 'clients' set.
        bssid_ta = pkt[Dot11].addr2  # transmitter
        bssid_ra = pkt[Dot11].addr1  # receiver

        # If transmitter is a known BSSID and receiver is unicast, store it
        if bssid_ta in known_bssids and bssid_ra and not is_broadcast_or_multicast(bssid_ra):
            # We need to find which SSID is associated with that BSSID
            for (ssid, bssid_k), data in discovered_networks.items():
                if bssid_k == bssid_ta:
                    data["clients"].add(bssid_ra)

        # If receiver is the known BSSID and transmitter is unicast, store it
        if bssid_ra in known_bssids and bssid_ta and not is_broadcast_or_multicast(bssid_ta):
            for (ssid, bssid_k), data in discovered_networks.items():
                if bssid_k == bssid_ra:
                    data["clients"].add(bssid_ta)

    ############################################################################
    # Construct the Markdown Report
    ############################################################################
    lines = []
    lines.append("# WiFi Packet Sniff Report\n")
    lines.append(f"**Capture Duration**: {CAPTURE_DURATION} seconds\n")
    lines.append(f"**Total Packets Captured**: {total_packets}")
    lines.append(f"- Management Frames: {mgmt_count}")
    lines.append(f"- Control Frames: {ctrl_count}")
    lines.append(f"- Data Frames: {data_count}\n")

    lines.append("## Discovered Networks\n")
    lines.append("| SSID        | BSSID             | Channel | Encryption             | Avg Signal (dBm) | Clients                             |")
    lines.append("|-------------|-------------------|---------|------------------------|------------------|--------------------------------------|")

    # We'll also store possible next-step commands in a separate section
    next_steps = []

    for (ssid, bssid), info in discovered_networks.items():
        enc = info["encryption"] or "Unknown"
        chan = info["channel"]
        signals = info["signals"]
        if signals:
            avg_signal = round(sum(signals) / len(signals), 1)
        else:
            avg_signal = "N/A"

        # List out clients
        if info["clients"]:
            client_list = ", ".join(sorted(info["clients"]))
        else:
            client_list = "-"

        lines.append(f"| {ssid} | {bssid} | {chan} | {enc} | {avg_signal} | {client_list} |")

        # Generate sample next steps for each discovered network
        # e.g., Deauth or jamming:
        # We'll pick the first client if it exists
        first_client = next(iter(info["clients"])) if info["clients"] else None
        # Example commands if we want to attack
        if first_client:
            # Deauth command
            deauth_cmd = f"sudo python3 wifi_deauth.py --ap {bssid} --target {first_client} --iface {mon_iface}"
            # Jamming command
            jam_cmd = f"sudo python3 wifi_jam.py --ap {bssid} --iface {mon_iface}"
            next_steps.append(f"**Deauth**: {deauth_cmd}\n**Jam**: {jam_cmd}")
        else:
            # If no clients found, broadcast jamming is still an option
            jam_cmd = f"sudo python3 wifi_jam.py --ap {bssid} --iface {mon_iface}"
            next_steps.append(f"For SSID '{ssid}' (BSSID={bssid}), no clients found.\n**Jam**: {jam_cmd}")

    # If we want a "Next Steps" heading
    lines.append("\n## Potential Next Steps\n")
    if next_steps:
        for step_cmd in next_steps:
            lines.append(f"- {step_cmd}")
    else:
        lines.append("*No specific next steps identified. Consider handshake capture or further analysis.*")

    report_text = "\n".join(lines)

    with open(REPORT_FILENAME, "w") as f:
        f.write(report_text)

    print(f"✅ Finished! Wrote expanded report to '{REPORT_FILENAME}'.\n")
    print("----- Report Preview -----")
    print(report_text)


if __name__ == "__main__":
    main()
