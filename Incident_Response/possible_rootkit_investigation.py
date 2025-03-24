#!/usr/bin/env python3

import subprocess
import os
import requests
from datetime import datetime

def run_and_display(cmd):
    print(f"\n[🔍] Running: {cmd}\n{'-'*60}")
    process = subprocess.Popen(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    full_output = ""
    for line in process.stdout:
        print(line, end='')
        full_output += line

    process.wait()
    print(f"{'-'*60}\n[✓] Command completed.\n")
    return full_output.strip()

def ask_ollama(prompt, model="gemma3:27b"):
    url = "http://localhost:11434/api/chat"
    data = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False
    }
    try:
        response = requests.post(url, json=data)
        response.raise_for_status()
        return response.json()['message']['content'].strip()
    except Exception as e:
        return f"Ollama error: {e}"

def main():
    pid = input("Enter the suspicious PID to investigate: ").strip()
    if not pid.isdigit():
        print("Invalid PID. Exiting.")
        return

    findings = {}

    findings['pid_status'] = run_and_display(f"ps aux | grep -w {pid} | grep -v grep")
    findings['hidden_processes'] = run_and_display("unhide proc -v | grep PID")

    proc_path = f"/proc/{pid}"
    if os.path.exists(proc_path):
        findings['proc_cmdline'] = run_and_display(f"cat {proc_path}/cmdline")
        findings['proc_status'] = run_and_display(f"cat {proc_path}/status")
    else:
        findings['proc_cmdline'] = findings['proc_status'] = "Process files not found."

    findings['network_netstat'] = run_and_display(f"netstat -tulpn | grep {pid}")
    findings['network_lsof'] = run_and_display(f"lsof -p {pid}")

    findings['kernel_modules'] = run_and_display("lsmod | grep -i hidden")
    findings['kernel_warnings'] = run_and_display("dmesg | grep -i 'warning\\|rootkit'")

    findings['chkrootkit'] = run_and_display("chkrootkit")
    findings['rkhunter'] = run_and_display("rkhunter --checkall --sk")

    print("\n[*] Sending data to Ollama AI for analysis...")
    full_prompt = "Analyze these Linux forensic findings for signs of a rootkit or malicious activity:\n\n"
    for key, value in findings.items():
        full_prompt += f"### {key.replace('_',' ').title()}\n```\n{value if value else 'No Data Found'}\n```\n\n"

    analysis = ask_ollama(full_prompt)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_filename = f"incident_response_{pid}_{timestamp}.md"

    # Summary table
    summary_table = [
        ("PID Visible via ps", "Yes" if findings['pid_status'] else "No"),
        ("Hidden from unhide", "Yes" if findings['hidden_processes'] else "No"),
        ("/proc Data Found", "Yes" if findings['proc_cmdline'] or findings['proc_status'] else "No"),
        ("Network Activity", "Yes" if findings['network_netstat'] or findings['network_lsof'] else "No"),
        ("Suspicious Kernel Indicators", "Yes" if findings['kernel_modules'] or findings['kernel_warnings'] else "No"),
        ("Rootkit Scan Alerts", "See below")
    ]

    with open(output_filename, 'w') as md_file:
        md_file.write(f"# 🛡️ Incident Response Report (PID: {pid})\n\n")
        md_file.write(f"_Generated: {timestamp}_\n\n")

        md_file.write("## ✅ AI-Generated Summary\n\n")
        md_file.write(f"{analysis}\n\n")

        md_file.write("## 🔎 Summary of Findings\n\n")
        md_file.write("| Check | Result |\n|-------|--------|\n")
        for check, result in summary_table:
            md_file.write(f"| {check} | {result} |\n")

        md_file.write("\n---\n<details>\n<summary>🔍 Full Command Output</summary>\n\n")
        for key, value in findings.items():
            md_file.write(f"### {key.replace('_', ' ').title()}\n```\n{value if value else 'No data'}\n```\n\n")
        md_file.write("</details>\n")

    print(f"\n✅ Markdown file saved as: {output_filename}\n")
    print("🧠 AI-Generated Forensic Summary:\n")
    print(analysis)

if __name__ == "__main__":
    main()
