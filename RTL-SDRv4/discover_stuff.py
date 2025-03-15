import subprocess
import os
import time

# Define scanning and capture parameters
scan_duration = 15  # How long to scan the 2.4 GHz band (seconds)
scan_output = "2.4ghz_scan.csv"  # Where the scan results are saved
capture_duration = 10  # How long to capture raw RF data (seconds)
sample_rate = "2M"  # Sample rate (2 MHz for good resolution)
gain = "40"  # RTL-SDR gain level
capture_file = "keyboard_signal.cu8"  # Captured raw signal file


# Function to scan for active frequencies in the 2.4 GHz band
def scan_24ghz_band():
    print("🔍 Scanning 2.4 GHz band for active signals...")

    command = f"rtl_power -f 2400M:2483M:1M -g {gain} -e {scan_duration}s {scan_output}"
    subprocess.run(command, shell=True)

    # Check if scan output exists
    if os.path.exists(scan_output):
        print(f"📊 Scan complete. Analyzing {scan_output} for strongest signals...")
        best_freq = None
        max_power = -999

        # Read scan results
        with open(scan_output, "r") as file:
            for line in file:
                parts = line.strip().split(",")
                if len(parts) > 1:
                    freq, power = float(parts[0]), float(parts[1])
                    if power > max_power:
                        max_power = power
                        best_freq = freq

        if best_freq:
            print(f"🎯 Strongest signal detected at {best_freq} MHz")
            return str(int(best_freq)) + "M"  # Format for rtl_sdr command
        else:
            print("⚠️ No strong signals detected in the 2.4 GHz band.")
            return None
    else:
        print("❌ Scan file not found. Check rtl_power installation.")
        return None


# Function to capture raw RF signal from detected frequency
def capture_keyboard_signal(freq):
    print(f"🎤 Capturing raw signal at {freq} for {capture_duration} seconds...")

    command = f"rtl_sdr -f {freq} -s {sample_rate} -g {gain} -n {int(float(sample_rate.replace('M', '')) * 1e6 * capture_duration)} {capture_file}"
    subprocess.run(command, shell=True)

    if os.path.exists(capture_file):
        print(f"✅ Signal captured! Saved as {capture_file}.")
    else:
        print("⚠️ Capture failed. Check RTL-SDR connection.")


# Main function
if __name__ == "__main__":
    detected_freq = scan_24ghz_band()
    if detected_freq:
        capture_keyboard_signal(detected_freq)
    else:
        print("❌ No active frequencies detected. Try again while typing on the keyboard.")
