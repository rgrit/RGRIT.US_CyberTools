import scapy.all as scapy
from scapy.all import sniff, wrpcap, TCP, UDP, ICMP, ARP, IP, Raw, DNS
import time
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
import ipaddress

# Global variables for the progress update
capture_running = False
capture_start_time = None
capture_duration = None

# Helper: Check if an IP is private (local)
def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return ip_obj.is_private

def packet_sniffer_gui_extended(interface, duration, pcap_filename, threshold, log_callback):
    global capture_running
    log_callback(f"[*] Starting extended capture on {interface} for {duration} seconds...")
    start_time = time.time()
    # Capture packets using Scapy; this call blocks for 'duration' seconds.
    packets = sniff(iface=interface, timeout=duration, store=True)
    end_time = time.time()
    log_callback(f"[+] Capture complete. {len(packets)} packets captured in {end_time - start_time:.1f} seconds.")

    # Initialize counters for metrics
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    arp_count = 0
    arp_req_count = 0
    syn_count = 0
    fin_count = 0
    http_get_count = 0
    http_post_count = 0
    dns_resp_count = 0
    encrypted_count = 0
    local_count = 0
    external_count = 0
    others_count = 0
    packet_lengths = []

    # Initialize additional counters for new detections
    fragmented_count = 0          # Count of fragmented packets
    ip_traffic = {}               # Dictionary to track packets per source IP

    # Define encrypted ports (common for HTTPS, secure mail, SSH, etc.)
    encrypted_ports = {443, 8443, 993, 995, 465, 587, 990, 22}

    # Analyze each captured packet
    for pkt in packets:
        # Record packet size
        try:
            pkt_len = len(pkt)
            packet_lengths.append(pkt_len)
        except Exception:
            pass

        # ARP packets (no IP layer)
        if pkt.haslayer(ARP):
            arp_count += 1
            if pkt[ARP].op == 1:  # ARP request
                arp_req_count += 1
            # ARP is only used locally
            local_count += 1
            continue  # Skip further IP processing for ARP

        # Process IP packets
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            # Update per-IP traffic counter
            ip_traffic[src_ip] = ip_traffic.get(src_ip, 0) + 1

            if is_private_ip(src_ip):
                local_count += 1
            else:
                external_count += 1

            # Check for IP fragmentation (nonzero fragment field)
            if pkt[IP].frag != 0:
                fragmented_count += 1

            # TCP processing
            if pkt.haslayer(TCP):
                tcp_count += 1
                flags = pkt[TCP].flags
                if flags & 0x02:  # SYN flag
                    syn_count += 1
                if flags & 0x01:  # FIN flag
                    fin_count += 1
                # Check for HTTP GET/POST requests on port 80
                if (pkt[TCP].dport == 80 or pkt[TCP].sport == 80) and pkt.haslayer(Raw):
                    try:
                        payload = pkt[Raw].load.decode(errors="ignore")
                        if payload.startswith("GET "):
                            http_get_count += 1
                        elif payload.startswith("POST "):
                            http_post_count += 1
                    except Exception:
                        pass
                # Check if packet is likely encrypted (by common ports)
                if pkt[TCP].sport in encrypted_ports or pkt[TCP].dport in encrypted_ports:
                    encrypted_count += 1

            # UDP processing
            if pkt.haslayer(UDP):
                udp_count += 1
                if pkt.haslayer(DNS) and hasattr(pkt[DNS], "qr") and pkt[DNS].qr == 1:
                    dns_resp_count += 1

            # ICMP processing
            if pkt.haslayer(ICMP):
                icmp_count += 1

            # Count any other IP protocols (not ICMP, TCP, or UDP)
            proto = pkt[IP].proto
            if proto not in (1, 6, 17):
                others_count += 1

    total_packets = len(packets)
    unencrypted_count = total_packets - encrypted_count

    # Calculate packet size statistics if any packets were captured
    if packet_lengths:
        largest_size = max(packet_lengths)
        smallest_size = min(packet_lengths)
        avg_size = sum(packet_lengths) / len(packet_lengths)
    else:
        largest_size = smallest_size = avg_size = 0

    # Determine dominant IP traffic if available
    if ip_traffic:
        total_ip_packets = sum(ip_traffic.values())
        most_common_ip, common_count = max(ip_traffic.items(), key=lambda x: x[1])
        ip_ratio = common_count / total_ip_packets
    else:
        total_ip_packets = 0
        ip_ratio = 0

    # Detect unusual activity based on various heuristics and the threshold
    unusual_activity = []
    if syn_count > threshold:
        unusual_activity.append(f"High SYN packet count ({syn_count}) – potential SYN scan")
    if fin_count > threshold:
        unusual_activity.append(f"High FIN packet count ({fin_count}) – potential FIN scan")
    if arp_req_count > threshold:
        unusual_activity.append(f"High ARP request count ({arp_req_count}) – potential ARP scan")
    if icmp_count > threshold:
        unusual_activity.append(f"High ICMP packet count ({icmp_count}) – potential ping flood")
    if (http_get_count + http_post_count) > threshold:
        unusual_activity.append(f"High HTTP request volume ({http_get_count + http_post_count}) – possible HTTP flood")
    if dns_resp_count > threshold:
        unusual_activity.append(f"High DNS response count ({dns_resp_count}) – possible DNS amplification attack")
    if udp_count > (tcp_count * 2) and udp_count > threshold:
        unusual_activity.append(f"Unusually high UDP traffic ({udp_count}) compared to TCP ({tcp_count}) – potential UDP flood")
    if others_count > threshold:
        unusual_activity.append(f"Significant number of 'other' protocol packets ({others_count}) – investigate unknown protocols")
    if packet_lengths and avg_size < 40:
        unusual_activity.append(f"Very low average packet size ({avg_size:.1f} bytes) – could indicate scanning or fragmented traffic")
    if total_packets > 0 and (encrypted_count / total_packets) > 0.8:
        unusual_activity.append(f"High proportion of encrypted traffic ({encrypted_count}/{total_packets}) – check if expected")
    if external_count > threshold and local_count < (external_count * 0.1):
        unusual_activity.append("Very low local traffic compared to external traffic – potential external attack")
    if fragmented_count > threshold:
        unusual_activity.append(f"High number of fragmented packets ({fragmented_count}) – potential fragmentation attack or evasion technique")
    if ip_traffic and ip_ratio > 0.5:
        unusual_activity.append(f"High concentration of traffic from {most_common_ip} ({common_count} packets, {ip_ratio*100:.1f}% of IP traffic) – potential targeted attack or misconfiguration")

    # Print the summary of extended metrics, omitting metrics with zero counts
    log_callback("\n=== Extended Capture Statistics ===")
    if tcp_count:
        log_callback(f"Total TCP packets: {tcp_count}")
    if udp_count:
        log_callback(f"Total UDP packets: {udp_count}")
    if icmp_count:
        log_callback(f"Total ICMP packets: {icmp_count}")
    if arp_count:
        log_callback(f"Total ARP packets: {arp_count}")
    if arp_req_count:
        log_callback(f"ARP requests: {arp_req_count}")
    if syn_count:
        log_callback(f"TCP SYN packets: {syn_count}")
    if fin_count:
        log_callback(f"TCP FIN packets: {fin_count}")
    if http_get_count:
        log_callback(f"HTTP GET requests: {http_get_count}")
    if http_post_count:
        log_callback(f"HTTP POST requests: {http_post_count}")
    if dns_resp_count:
        log_callback(f"DNS response packets: {dns_resp_count}")
    if packet_lengths:
        log_callback(f"Largest packet: {largest_size} bytes")
        log_callback(f"Smallest packet: {smallest_size} bytes")
        log_callback(f"Average packet size: {avg_size:.1f} bytes")
    if encrypted_count:
        log_callback(f"Encrypted packets (SSL/TLS/SSH): {encrypted_count}")
    if unencrypted_count:
        log_callback(f"Unencrypted packets: {unencrypted_count}")
    if local_count:
        log_callback(f"Packets from local network: {local_count}")
    if external_count:
        log_callback(f"Packets from external network: {external_count}")
    if others_count:
        log_callback(f"Other protocol packets: {others_count}")
    if unusual_activity:
        log_callback("\n[Unusual network activity detected:]")
        for note in unusual_activity:
            log_callback(f" - {note}")
    else:
        log_callback("\nNo unusual network activity detected.")

    # Save captured packets to a PCAP file if any were captured
    if total_packets:
        wrpcap(pcap_filename, packets)
        log_callback(f"\n[+] Saved captured packets to {pcap_filename}")
    else:
        log_callback("\n[!] No packets captured; PCAP file not saved.")

    # Mark capture as finished for progress updates
    global capture_running
    capture_running = False


# Function to update the countdown label and progress bar
def update_progress():
    if capture_running and capture_start_time is not None and capture_duration:
        elapsed = time.time() - capture_start_time
        remaining = max(0, capture_duration - elapsed)
        progress_percentage = min(100, (elapsed / capture_duration) * 100)
        countdown_label.config(text=f"Remaining time: {remaining:.0f} sec")
        progress_bar['value'] = progress_percentage
        # Schedule update in 1 second
        root.after(1000, update_progress)
    else:
        # When finished, update progress to 100% and label
        progress_bar['value'] = 100
        countdown_label.config(text="Capture complete.")


# GUI functions
def start_sniffer():
    global capture_running, capture_start_time, capture_duration
    interface = interface_entry.get()
    try:
        duration = float(duration_entry.get())
    except ValueError:
        log("Invalid duration. Please enter a number.")
        return
    try:
        threshold = int(threshold_entry.get())
    except ValueError:
        log("Invalid threshold. Please enter an integer.")
        return
    pcap_filename = output_entry.get().strip() or "output.pcap"

    # Clear previous log messages and reset progress bar and countdown
    log_text.delete("1.0", tk.END)
    progress_bar['value'] = 0
    countdown_label.config(text=f"Remaining time: {duration:.0f} sec")

    # Set globals for progress tracking
    capture_running = True
    capture_start_time = time.time()
    capture_duration = duration

    # Start the progress update loop
    update_progress()

    # Start the capture in a separate thread so the GUI remains responsive
    thread = threading.Thread(target=packet_sniffer_gui_extended,
                              args=(interface, duration, pcap_filename, threshold, log))
    thread.daemon = True
    thread.start()


def log(message):
    log_text.insert(tk.END, message + "\n")
    log_text.see(tk.END)


# Create the main Tkinter window
root = tk.Tk()
root.title("Extended Packet Sniffer GUI")

# Create a title label with some ASCII art flair
title_label = tk.Label(root, text="=== Extended Packet Sniffer ===", font=("Courier", 16, "bold"), fg="blue")
title_label.grid(row=0, column=0, columnspan=2, padx=5, pady=5)

# Interface entry
tk.Label(root, text="Interface:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
interface_entry = tk.Entry(root)
interface_entry.grid(row=1, column=1, padx=5, pady=5)
interface_entry.insert(0, "enp2s0")  # Default (adjust as needed)

# Duration entry
tk.Label(root, text="Duration (sec):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
duration_entry = tk.Entry(root)
duration_entry.grid(row=2, column=1, padx=5, pady=5)
duration_entry.insert(0, "60")  # Default duration

# Threshold entry
tk.Label(root, text="Threshold (for alerts):").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
threshold_entry = tk.Entry(root)
threshold_entry.grid(row=3, column=1, padx=5, pady=5)
threshold_entry.insert(0, "100")  # Default threshold

# Output PCAP filename entry
tk.Label(root, text="Output PCAP Filename:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
output_entry = tk.Entry(root)
output_entry.grid(row=4, column=1, padx=5, pady=5)
output_entry.insert(0, "output.pcap")  # Default filename

# Start button
start_button = tk.Button(root, text="Start Sniffer", command=start_sniffer)
start_button.grid(row=5, column=0, columnspan=2, pady=10)

# Progress bar widget (using ttk)
progress_bar = ttk.Progressbar(root, orient="horizontal", mode="determinate", length=300)
progress_bar.grid(row=6, column=0, columnspan=2, padx=5, pady=5)

# Countdown label for remaining time
countdown_label = tk.Label(root, text="Remaining time: -- sec", font=("Helvetica", 12))
countdown_label.grid(row=7, column=0, columnspan=2, padx=5, pady=5)

# Scrolled text widget for log output
log_text = scrolledtext.ScrolledText(root, width=80, height=20)
log_text.grid(row=8, column=0, columnspan=2, padx=5, pady=5)

root.mainloop()
