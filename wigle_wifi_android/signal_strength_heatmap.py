import pandas as pd
import folium
from folium.plugins import HeatMap

def create_rssi_heatmap(csv_path, output_html, offset=100, radius=15, blur=10, min_opacity=0.2, max_zoom=18):
    """
    Create an interactive heatmap for Wi-Fi signal strength based on RSSI values.

    Parameters:
        csv_path (str): Path to the cleaned Wigle CSV file.
        output_html (str): Output HTML file path for the heatmap.
        offset (int): Value added to RSSI to convert it into a positive weight.
                      (For RSSI values typically between -100 and -30, an offset of 100 works well.)
        radius (int): Radius of each heatmap point.
        blur (int): The amount of blur for each point.
        min_opacity (float): Minimum opacity of the heatmap.
        max_zoom (int): Maximum zoom level at which the heatmap is displayed.
    """
    # Load the cleaned CSV data
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return

    # Ensure necessary columns exist
    required_columns = ['CurrentLatitude', 'CurrentLongitude', 'RSSI']
    for col in required_columns:
        if col not in df.columns:
            print(f"Missing required column: {col}")
            return

    # Drop rows with missing coordinates or RSSI values
    df = df.dropna(subset=['CurrentLatitude', 'CurrentLongitude', 'RSSI'])

    # Convert RSSI to numeric and calculate weights:
    df['RSSI'] = pd.to_numeric(df['RSSI'], errors='coerce')
    df = df.dropna(subset=['RSSI'])
    df['weight'] = df['RSSI'].apply(lambda x: max(0, offset + x))

    # Prepare data in [latitude, longitude, weight] format for the HeatMap plugin
    heat_data = df[['CurrentLatitude', 'CurrentLongitude', 'weight']].values.tolist()

    # Calculate the center of the map
    center_lat = df['CurrentLatitude'].mean()
    center_lon = df['CurrentLongitude'].mean()

    # Create the base map with a standard OpenStreetMap tile layer
    m = folium.Map(
        location=[center_lat, center_lon],
        zoom_start=16,
        tiles='OpenStreetMap'  # using a standard tile layer for better detail visibility
    )

    # Use a custom gradient with string keys (if needed, you can adjust these colors)
    gradient = {"0.2": 'blue', "0.4": 'lime', "0.6": 'yellow', "0.8": 'orange', "1": 'red'}

    # Add the HeatMap layer with the custom gradient and adjusted opacity
    HeatMap(
        heat_data,
        radius=radius,
        blur=blur,
        min_opacity=min_opacity,
        max_zoom=max_zoom,
        gradient=gradient
    ).add_to(m)

    # Save the interactive heatmap to an HTML file
    m.save(output_html)
    print(f"Heatmap saved to {output_html}")

if __name__ == "__main__":
    input_csv = "<<YOUR CLEANED DATA>>"      # Path to your cleaned Wigle CSV file
    output_map = "wigle_heatmap.html"      # Output HTML file for the heatmap
    create_rssi_heatmap(input_csv, output_map)
