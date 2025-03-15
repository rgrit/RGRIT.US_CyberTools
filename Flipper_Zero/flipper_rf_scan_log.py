import serial
import time

flipper_port = "<<YOU GOTTA FIGURE THIS ONE YOURSELF"  # Adjust for Windows (e.g., "COM3")
baud_rate = 115200

frequencies = [433920000, 868000000, 915000000]  # Common RF frequencies

try:
    with serial.Serial(flipper_port, baud_rate, timeout=1) as ser:
        print("🔍 Scanning for RF signals...")

        for freq in frequencies:
            ser.write(f"subghz rx_raw {freq}\n".encode())
            time.sleep(5)  # Listen for 5 seconds per frequency
            response = ser.read(500).decode('utf-8', errors='ignore')

            if response:
                print(f"📡 Signal detected at {freq} Hz:")
                print(response)

                with open("rf_scan_log.txt", "a") as log_file:
                    log_file.write(f"Signal at {freq} Hz:\n{response}\n")

        print("✅ Scan complete. Results saved in 'rf_scan_log.txt'.")
except Exception as e:
    print(f"❌ Error: {e}")
