import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import sniff, wrpcap, Raw, IP, TCP, UDP
from threading import Thread
import time
import re

class FlowAnalyzerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("🔍 Network Flow Analyzer")
        self.flows = {}
        self.captured_packets = []

        master.configure(bg='black')
        master.geometry("900x500")

        controls = tk.Frame(master, bg='black')
        controls.pack(fill='x', padx=10, pady=5)

        tk.Label(controls, text="Duration (sec):", fg="lime", bg='black').pack(side='left')
        self.duration_entry = tk.Entry(controls, width=10)
        self.duration_entry.insert(0, "30")
        self.duration_entry.pack(side='left', padx=5)

        tk.Button(controls, text="▶️ Start Scan", command=self.start_scan).pack(side='left', padx=10)

        main_panes = tk.PanedWindow(master, bg='black', sashwidth=5)
        main_panes.pack(fill='both', expand=True, padx=10, pady=5)

        live_frame = tk.Frame(main_panes, bg='black')
        summary_frame = tk.Frame(main_panes, bg='black')

        main_panes.add(live_frame, stretch="always")
        main_panes.add(summary_frame, stretch="always")

        tk.Label(live_frame, text="📟 Live Packet Stream", fg="lime", bg='black').pack()
        self.live_text = tk.Text(live_frame, bg='black', fg='lime', font=('Courier', 10))
        self.live_text.pack(fill='both', expand=True)

        tk.Label(summary_frame, text="📊 Unencrypted Flows", fg="lime", bg='black').pack()
        cols = ('source', 'destination', 'alerts')
        self.tree = ttk.Treeview(summary_frame, columns=cols, show='headings')

        for col in cols:
            self.tree.heading(col, text=col.title())
            self.tree.column(col, anchor='center')

        self.tree.pack(fill='both', expand=True)
        self.tree.bind("<Double-1>", self.on_drilldown)

    def start_scan(self):
        duration = int(self.duration_entry.get())
        self.flows.clear()
        self.captured_packets.clear()
        self.live_text.delete('1.0', tk.END)
        self.tree.delete(*self.tree.get_children())

        Thread(target=self.sniff_packets, args=(duration,), daemon=True).start()

    def sniff_packets(self, duration):
        sniff(prn=self.process_packet, timeout=duration, store=False)
        self.update_summary()

    def process_packet(self, pkt):
        self.captured_packets.append(pkt)

        if pkt.haslayer(IP):
            proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else None
            if not proto:
                return

            flow_key = (pkt[IP].src, pkt[IP].dst, proto, pkt.sport, pkt.dport)

            flow = self.flows.setdefault(flow_key, {'packets': [], 'first_seen': time.time(), 'last_seen': time.time(), 'reconnects': 0})

            if time.time() - flow['last_seen'] > 5:
                flow['reconnects'] += 1

            flow['packets'].append(pkt)
            flow['last_seen'] = time.time()

            self.live_text.insert(tk.END, f"{pkt[IP].src} → {pkt[IP].dst} {proto}\n")
            self.live_text.see(tk.END)

    def update_summary(self):
        for key, flow in self.flows.items():
            src, dst, proto, sport, dport = key

            combined_payload = b"".join([bytes(p[Raw]) for p in flow['packets'] if p.haslayer(Raw)])
            payload_sample = combined_payload[:500]
            is_readable = bool(re.match(rb'^[\x09\x0a\x0d\x20-\x7E]+$', payload_sample))

            tags = []
            if is_readable:
                tags.append('❌ Unencrypted')
                if re.search(rb'(login|user|pass|pwd|authorization|token)', payload_sample, re.I):
                    tags.append('🚨 Possible Credentials')
            else:
                tags.append('🔒 Encrypted/Binary')

            if flow['reconnects'] > 2:
                tags.append('🔁 Reconnected')

            self.tree.insert('', tk.END, values=(src, dst, ", ".join(tags)))

    def on_drilldown(self, event):
        item = self.tree.selection()[0]
        flow_info = self.tree.item(item, "values")

        detail_win = tk.Toplevel(self.master)
        detail_win.title(f"🔍 Flow details: {flow_info[0]} → {flow_info[1]}")
        detail_win.geometry("600x400")
        detail_win.configure(bg='black')

        payload_text = tk.Text(detail_win, bg='black', fg='lime', font=('Courier', 10))
        payload_text.pack(fill='both', expand=True)

        flow_key = next(k for k in self.flows if k[0] == flow_info[0] and k[1] == flow_info[1])

        combined_payload = b"".join([bytes(p[Raw]) for p in self.flows[flow_key]['packets'] if p.haslayer(Raw)])
        payload_sample = combined_payload[:500]
        is_readable = bool(re.match(rb'^[\x09\x0a\x0d\x20-\x7E]+$', payload_sample))

        if is_readable:
            payload_text.insert(tk.END, combined_payload.decode(errors='ignore'))
        else:
            payload_text.insert(tk.END, "[Binary/Encrypted Data]")

        tk.Button(detail_win, text="💾 Save to PCAP", command=lambda: self.save_to_pcap(flow_key)).pack(pady=5)

    def save_to_pcap(self, flow_key):
        filename = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if filename:
            wrpcap(filename, self.flows[flow_key]['packets'])
            messagebox.showinfo("Saved", f"Flow saved to {filename}")

if __name__ == '__main__':
    root = tk.Tk()
    app = FlowAnalyzerGUI(root)
    root.mainloop()
