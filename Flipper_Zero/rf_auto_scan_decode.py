import serial
import time

flipper_port = "<<KEEP ON KEEPING ON>>"  # Adjust for Windows (e.g., "COM3")
baud_rate = 115200

# Define frequency range to scan (Modify as needed)
min_freq = 300000000   # 300 MHz
max_freq = 928000000   # 928 MHz
step_size = 20000000   # Scan every 20 MHz (adjust for granularity)

# Dictionary to track RF activity
rf_activity = {}

try:
    with serial.Serial(flipper_port, baud_rate, timeout=1) as ser:
        print("🔍 Scanning RF frequency range for activity...")

        # Step through the entire frequency range
        for freq in range(min_freq, max_freq, step_size):
            print(f"📡 Scanning {freq} Hz...")
            ser.write(f"subghz rx_raw {freq}\n".encode())
            time.sleep(3)  # Listen briefly per frequency
            response = ser.read(500).decode('utf-8', errors='ignore')

            if response.strip() and "subghz rx_raw" not in response:
                print(f"✅ Signal detected at {freq} Hz!")
                rf_activity[freq] = len(response)  # Store signal length as activity score

        # Find the top 3 most active frequencies
        sorted_frequencies = sorted(rf_activity, key=rf_activity.get, reverse=True)[:3]

        if sorted_frequencies:
            print("\n🎯 Top Noisiest Frequencies Detected:")
            for rank, freq in enumerate(sorted_frequencies, 1):
                print(f"{rank}. {freq} Hz - Activity Score: {rf_activity[freq]}")

            # Capture and decode signals from the noisiest frequencies
            with open("rf_dynamic_report.txt", "w") as report_file:
                report_file.write("📡 RF Dynamic Scan Report\n\n")

                for freq in sorted_frequencies:
                    print(f"\n🔎 Capturing detailed signal from {freq} Hz...")
                    ser.write(f"subghz rx_raw {freq}\n".encode())
                    time.sleep(10)  # Listen longer
                    locked_response = ser.read(500).decode('utf-8', errors='ignore')

                    # Save detailed signal
                    with open(f"rf_locked_{freq}.raw", "w") as locked_file:
                        locked_file.write(locked_response)

                    # Decode the captured signal
                    print(f"\n🛠️ Decoding signal from {freq} Hz...")
                    ser.write(f"subghz decode_raw rf_locked_{freq}.raw\n".encode())
                    time.sleep(5)  # Wait for decoding
                    decoded_response = ser.read(500).decode('utf-8', errors='ignore')

                    print(f"📜 Decoded Signal at {freq} Hz:\n{decoded_response}")

                    # Save decoded data
                    with open(f"decoded_signal_{freq}.txt", "w") as decoded_file:
                        decoded_file.write(decoded_response)

                    # Append to the report
                    report_file.write(f"\n🎯 Frequency: {freq} Hz\n")
                    report_file.write(f"📡 Raw Signal:\n{locked_response}\n")
                    report_file.write(f"📜 Decoded Data:\n{decoded_response}\n")
                    report_file.write("-" * 40 + "\n")

            print("\n✅ RF scanning, decoding, and reporting complete! Check 'rf_dynamic_report.txt'.")

except Exception as e:
    print(f"❌ Error: {e}")
