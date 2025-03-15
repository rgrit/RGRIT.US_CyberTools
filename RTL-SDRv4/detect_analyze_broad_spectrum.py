import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.signal import savgol_filter

csv_file = "scan_results.csv"  # Update this to the correct file path if needed

try:
    # Load CSV without headers
    data = pd.read_csv(csv_file, header=None)

    # Extract frequency and amplitude columns
    frequency = pd.to_numeric(data.iloc[:, 2], errors='coerce')  # Column 2 (Index 2) - Frequency
    amplitude = pd.to_numeric(data.iloc[:, 6], errors='coerce')  # Column 6 (Index 6) - Amplitude

    # Drop rows with missing data
    valid_data = data.dropna(subset=[2, 6])

    # Apply Savitzky-Golay smoothing filter
    smoothed_amplitude = savgol_filter(amplitude, window_length=5, polyorder=2)  # Adjust window_length if needed

    # Plot results
    plt.figure(figsize=(12, 6))
    plt.plot(frequency, amplitude, label="Raw Amplitude", alpha=0.5)
    plt.plot(frequency, smoothed_amplitude, label="Smoothed Amplitude", color='red', linewidth=2)
    plt.xlabel("Frequency (Hz)")
    plt.ylabel("Amplitude (dB)")
    plt.title("Signal Analysis - Raw vs. Smoothed")
    plt.legend()
    plt.grid()
    plt.show()

except FileNotFoundError:
    print(f"Error: File '{csv_file}' not found.")
except Exception as e:
    print(f"An error occurred: {e}")
