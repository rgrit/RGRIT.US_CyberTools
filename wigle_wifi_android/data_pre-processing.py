import pandas as pd


def load_wigle_csv(file_path):
    """
    Load a Wigle CSV file that has metadata lines preceding the actual header.

    Parameters:
        file_path (str): Path to the Wigle CSV file.

    Returns:
        pd.DataFrame: Cleaned DataFrame containing the Wi-Fi network data.
    """
    # Read all lines from the file
    with open(file_path, 'r') as f:
        lines = f.readlines()

    # Find the index of the header row (starts with "MAC,SSID")
    header_index = None
    for i, line in enumerate(lines):
        if line.startswith("MAC,SSID"):
            header_index = i
            break

    if header_index is None:
        raise ValueError("Header row not found. Ensure the file contains a row starting with 'MAC,SSID'")

    # Load the CSV data starting from the header row
    df = pd.read_csv(file_path, skiprows=header_index)

    # Basic cleanup steps:
    # 1. Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # 2. Replace empty strings with NaN (for better handling of missing values)
    df = df.replace("", pd.NA)

    # 3. Optional: Convert specific columns to appropriate datatypes.
    # For example, convert 'FirstSeen' to datetime if it exists.
    if 'FirstSeen' in df.columns:
        df['FirstSeen'] = pd.to_datetime(df['FirstSeen'], errors='coerce')

    return df


if __name__ == "__main__":
    input_file_path = "<<Your Raw File>>.csv"  # Path to your Wigle CSV file
    output_file_path = "<<Your Clean File>>.csv"  # Desired output file path

    try:
        df = load_wigle_csv(input_file_path)
        print("CSV data loaded successfully. Here are the first few rows:")
        print(df.head())

        # Write the cleaned DataFrame to a new CSV file
        df.to_csv(output_file_path, index=False)
        print(f"Cleaned data saved to {output_file_path}")
    except Exception as e:
        print("Error loading CSV data:", e)
