import pandas as pd
import matplotlib.pyplot as plt


def analyze_channel_distribution(csv_path, output_figure="channel_distribution.png"):
    """
    Analyze the Wi-Fi channel distribution by grouping data based on the 'Channel' column,
    then plotting a bar chart showing the number of networks per channel.

    Parameters:
        csv_path (str): Path to the cleaned CSV file.
        output_figure (str): Filename for saving the output plot.
    """
    # Load the cleaned CSV data
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return

    # Verify the 'Channel' column exists
    if 'Channel' not in df.columns:
        print("Column 'Channel' not found in the dataset.")
        return

    # Convert the 'Channel' column to numeric (if needed)
    df['Channel'] = pd.to_numeric(df['Channel'], errors='coerce')

    # Group by channel and count occurrences, then sort by channel number
    channel_counts = df['Channel'].value_counts().sort_index()

    # Plot the channel distribution as a bar chart
    plt.figure(figsize=(10, 6))
    plt.bar(channel_counts.index.astype(str), channel_counts.values, color='skyblue')
    plt.xlabel('Channel')
    plt.ylabel('Number of Networks')
    plt.title('Wi-Fi Channel Distribution')
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Save and show the plot
    plt.savefig(output_figure)
    plt.show()
    print(f"Channel distribution plot saved as {output_figure}")


def analyze_frequency_distribution(csv_path, output_figure="frequency_distribution.png"):
    """
    Optionally analyze and visualize the frequency distribution by classifying the networks
    into 2.4 GHz and 5 GHz bands (based on the 'Frequency' column), then plotting a pie chart.

    Parameters:
        csv_path (str): Path to the cleaned CSV file.
        output_figure (str): Filename for saving the output plot.
    """
    # Load the cleaned CSV data
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return

    # Verify the 'Frequency' column exists
    if 'Frequency' not in df.columns:
        print("Column 'Frequency' not found in the dataset.")
        return

    # Convert the 'Frequency' column to numeric (if needed)
    df['Frequency'] = pd.to_numeric(df['Frequency'], errors='coerce')

    # Define a helper function to classify frequency into bands
    def classify_frequency(freq):
        if pd.isna(freq):
            return 'Unknown'
        # Assuming frequency is in MHz, networks < 3000 MHz are in the 2.4 GHz band
        if freq < 3000:
            return '2.4 GHz'
        else:
            return '5 GHz'

    # Create a new column for the frequency band classification
    df['FrequencyBand'] = df['Frequency'].apply(classify_frequency)

    # Count the number of networks per frequency band
    freq_band_counts = df['FrequencyBand'].value_counts()

    # Plot the frequency distribution as a pie chart
    plt.figure(figsize=(6, 6))
    plt.pie(freq_band_counts.values, labels=freq_band_counts.index, autopct='%1.1f%%', startangle=140)
    plt.title('Wi-Fi Frequency Band Distribution')
    plt.tight_layout()

    # Save and show the pie chart
    plt.savefig(output_figure)
    plt.show()
    print(f"Frequency distribution plot saved as {output_figure}")


if __name__ == "__main__":
    # Set the path to your cleaned CSV file
    csv_file = "<<Your Cleaned Wifi>>"

    # Run channel distribution analysis
    analyze_channel_distribution(csv_file, output_figure="channel_distribution.png")

    # Optionally, run frequency band distribution analysis
    analyze_frequency_distribution(csv_file, output_figure="frequency_distribution.png")
