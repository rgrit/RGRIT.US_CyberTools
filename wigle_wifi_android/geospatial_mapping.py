import folium
import pandas as pd


def create_wifi_map_with_filter(csv_path, output_html):
    """
    Create an interactive map of Wi-Fi networks from a cleaned Wigle CSV file,
    grouping markers by device type so they can be filtered via a layer control.
    Each marker's popup includes additional metadata.

    Parameters:
        csv_path (str): Path to the cleaned CSV file.
        output_html (str): Output HTML file path for the interactive map.
    """
    # Load the cleaned CSV data
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return

    # Ensure required columns exist
    required_columns = ['CurrentLatitude', 'CurrentLongitude', 'SSID', 'RSSI', 'Type']
    for col in required_columns:
        if col not in df.columns:
            print(f"Missing required column: {col}")
            return

    # Define a list of colors to assign automatically.
    available_colors = [
        'blue', 'red', 'green', 'purple', 'orange', 'darkred', 'lightred',
        'beige', 'darkblue', 'darkgreen', 'cadetblue', 'darkpurple', 'pink',
        'lightblue', 'lightgreen', 'gray', 'black', 'lightgray'
    ]

    # Automatically assign a color to each unique device type
    unique_types = df['Type'].fillna('Unknown').unique()
    type_colors = {}
    for idx, device_type in enumerate(unique_types):
        type_colors[device_type] = available_colors[idx % len(available_colors)]

    # Calculate the center of the map
    center_lat = df['CurrentLatitude'].mean()
    center_lon = df['CurrentLongitude'].mean()

    # Create the base map with a closer zoom level (e.g., zoom_start=14)
    m = folium.Map(location=[center_lat, center_lon], zoom_start=14)

    # Create a dictionary to hold FeatureGroups for each device type
    feature_groups = {}
    for device_type in unique_types:
        # Use the device type as the layer name
        feature_groups[device_type] = folium.FeatureGroup(name=device_type)

    # Add markers to their corresponding FeatureGroup
    for _, row in df.iterrows():
        ssid = row.get('SSID', 'Unknown')
        rssi = row.get('RSSI', None)
        device_type = row.get('Type', 'Unknown')
        if pd.isna(device_type):
            device_type = 'Unknown'

        # Determine marker color based on device type
        marker_color = type_colors.get(device_type, 'gray')

        # Calculate marker radius based on RSSI (assuming RSSI is negative)
        try:
            rssi_value = float(rssi)
            radius = max(3, 10 - abs(rssi_value) * 0.1)
        except (ValueError, TypeError):
            radius = 3

        # Build a detailed HTML popup with additional metadata if available
        popup_content = (
            f"<b>SSID:</b> {ssid}<br>"
            f"<b>MAC:</b> {row.get('MAC', 'N/A')}<br>"
            f"<b>RSSI:</b> {rssi}<br>"
            f"<b>Type:</b> {device_type}<br>"
            f"<b>AuthMode:</b> {row.get('AuthMode', 'N/A')}<br>"
            f"<b>Channel:</b> {row.get('Channel', 'N/A')}<br>"
            f"<b>Frequency:</b> {row.get('Frequency', 'N/A')}<br>"
            f"<b>Altitude:</b> {row.get('AltitudeMeters', 'N/A')}<br>"
            f"<b>Accuracy:</b> {row.get('AccuracyMeters', 'N/A')}<br>"
            f"<b>First Seen:</b> {row.get('FirstSeen', 'N/A')}"
        )
        marker = folium.CircleMarker(
            location=[row['CurrentLatitude'], row['CurrentLongitude']],
            radius=radius,
            popup=folium.Popup(popup_content, max_width=300),
            color=marker_color,
            fill=True,
            fill_color=marker_color,
            fill_opacity=0.7
        )

        # Add the marker to the appropriate feature group
        feature_groups[device_type].add_child(marker)

    # Add each feature group to the map
    for group in feature_groups.values():
        group.add_to(m)

    # Add a layer control to toggle the display of each device type
    folium.LayerControl(collapsed=False).add_to(m)

    # Save the interactive map to an HTML file
    m.save(output_html)
    print(f"Map saved to {output_html}")


if __name__ == "__main__":
    input_csv = "<<Your CLeaned Data>>.csv"  # Path to your cleaned CSV file
    output_map = "wigle_map_with_filter.html"  # Output HTML file for the map
    create_wifi_map_with_filter(input_csv, output_map)
