import serial
import time

flipper_port = "<<FIGURE IT OUT>>"  # Adjust for Windows (e.g., "COM3")
baud_rate = 115200

# Common RF frequencies (modify as needed)
frequencies = [300000000, 315000000, 433920000, 868000000, 915000000]

try:
    with serial.Serial(flipper_port, baud_rate, timeout=1) as ser:
        print("🔍 Rapidly scanning for RF signals...")

        while True:  # Continuous scanning loop
            for freq in frequencies:
                ser.write(f"subghz rx_raw {freq}\n".encode())
                time.sleep(1)  # Reduce delay for fast scanning
                response = ser.read(500).decode('utf-8', errors='ignore')

                if response:
                    print(f"📡 Signal detected at {freq} Hz!")
                    print(response)

                    # Log the active frequency
                    with open("rf_scan_log.txt", "a") as log_file:
                        log_file.write(f"Signal at {freq} Hz:\n{response}\n")

                    # Once a signal is found, lock onto that frequency
                    print(f"🎯 Locking onto {freq} Hz for deeper analysis...")
                    ser.write(f"subghz rx_raw {freq}\n".encode())
                    time.sleep(10)  # Listen longer on the active frequency
                    locked_response = ser.read(500).decode('utf-8', errors='ignore')

                    print("🔎 Detailed signal data:")
                    print(locked_response)

                    with open("rf_detailed_log.txt", "a") as detailed_log:
                        detailed_log.write(f"Detailed Signal at {freq} Hz:\n{locked_response}\n")

except Exception as e:
    print(f"❌ Error: {e}")
