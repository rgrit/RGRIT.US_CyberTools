import serial

flipper_port = "<<YOU CAN DO IT>>"  # Adjust if needed
baud_rate = 115200

try:
    with serial.Serial(flipper_port, baud_rate, timeout=1) as ser:
        print("Connected to Flipper Zero. Listening for data...\n")
        while True:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if line:
                print(line)  # Print received data
except Exception as e:
    print(f"Error: {e}")
