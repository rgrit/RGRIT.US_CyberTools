import csv
import math
import numpy as np
import folium
from folium.plugins import MarkerCluster
from sklearn.cluster import DBSCAN

# Constants
EARTH_RADIUS = 6371000  # in meters
CLUSTER_THRESHOLD_METERS = .5  # devices within 5m will be grouped


def load_data(csv_file):
    """
    Loads the CSV data and returns only rows for Bluetooth-related devices,
    while skipping a specific device (MAC: d2:10:9f:88:14:fb and SSID: Versa 2).
    Devices are considered Bluetooth if the 'Type' column is one of:
    'bluetooth', 'bt', or 'ble' (case-insensitive).
    """
    valid_types = {'bluetooth', 'bt', 'ble'}
    skip_mac = "<<MAC ADDY YOU WANT TO EXCLUDE>>"
    skip_ssid = "<<SSID TO EXCLUDE>>  # lowercase for comparison
    data = []
    with open(csv_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            dev_type = row.get('Type', '').strip().lower()
            if dev_type not in valid_types:
                continue

            # Check if the device matches the one to skip.
            mac = row.get('MAC', '').strip().lower()
            ssid = row.get('SSID', '').strip().lower()
            if mac == skip_mac and ssid == skip_ssid:
                continue

            try:
                lat = float(row['CurrentLatitude'])
                lon = float(row['CurrentLongitude'])
                data.append({
                    'MAC': row['MAC'],
                    'SSID': row.get('SSID', ''),
                    'AuthMode': row.get('AuthMode', ''),
                    'Latitude': lat,
                    'Longitude': lon,
                    'row': row
                })
            except ValueError:
                continue  # Skip rows with invalid coordinate values
    return data


def cluster_devices(data):
    """
    Clusters devices based on their geographic location using DBSCAN.
    """
    # Convert latitude and longitude to radians for haversine metric.
    coords = np.array([
        [math.radians(item['Latitude']), math.radians(item['Longitude'])]
        for item in data
    ])

    # Calculate eps (threshold) in radians.
    eps_rad = CLUSTER_THRESHOLD_METERS / EARTH_RADIUS

    # Run DBSCAN using haversine metric.
    db = DBSCAN(eps=eps_rad, min_samples=1, metric='haversine').fit(coords)
    labels = db.labels_

    # Group devices by cluster label.
    clusters = {}
    for label, item in zip(labels, data):
        clusters.setdefault(label, []).append(item)
    return clusters


def generate_markdown_report(clusters, output_file='report.md'):
    """
    Writes a Markdown report summarizing each Bluetooth device group,
    with deduplicated device MAC addresses.
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# Bluetooth Device Proximity Report\n\n")
        f.write(
            "This report groups Bluetooth devices (BT and BLE) that are in close proximity (within approximately {} meters).\n\n".format(
                CLUSTER_THRESHOLD_METERS))
        f.write("## Summary\n")
        f.write("- Total clusters found: **{}**\n\n".format(len(clusters)))

        for label, devices in clusters.items():
            # Deduplicate the MAC addresses.
            unique_macs = sorted(set(device['MAC'] for device in devices))
            f.write("### Group {}\n".format(label))
            f.write("- Number of unique devices: **{}**\n".format(len(unique_macs)))
            f.write("- Device MAC addresses:\n")
            for mac in unique_macs:
                f.write("  - {}\n".format(mac))
            f.write("\n")

        f.write("*(End of Report)*\n")
    print("Markdown report generated:", output_file)


def generate_map(clusters, output_file='clusters_map.html'):
    """
    Generates an interactive map with markers for each Bluetooth device.
    """
    # Gather all coordinates.
    all_coords = []
    for devices in clusters.values():
        for device in devices:
            all_coords.append((device['Latitude'], device['Longitude']))
    if not all_coords:
        print("No coordinates available to display on the map.")
        return

    # Calculate average location for centering the map.
    avg_lat = sum(lat for lat, lon in all_coords) / len(all_coords)
    avg_lon = sum(lon for lat, lon in all_coords) / len(all_coords)

    m = folium.Map(location=[avg_lat, avg_lon], zoom_start=15)
    marker_cluster = MarkerCluster().add_to(m)

    # Define a list of colors for clusters.
    colors = ['blue', 'red', 'green', 'purple', 'orange', 'darkred', 'lightred', 'beige',
              'darkblue', 'darkgreen', 'cadetblue', 'darkpurple', 'white', 'pink', 'lightblue']

    for label, devices in clusters.items():
        # Cycle through colors; unknown clusters (label -1) are marked gray.
        color = colors[label % len(colors)] if label >= 0 else 'gray'
        for device in devices:
            popup_text = f"Group: {label}<br>MAC: {device['MAC']}<br>SSID: {device['SSID']}"
            folium.Marker(
                location=[device['Latitude'], device['Longitude']],
                popup=popup_text,
                icon=folium.Icon(color=color)
            ).add_to(marker_cluster)

    m.save(output_file)
    print("Map generated and saved as:", output_file)


if __name__ == "__main__":
    # Path to your CSV file containing device data.
    csv_file = "<<Your Cleaned Data>>"  # update with your actual file name/path

    # Load data filtered for Bluetooth devices (BT and BLE), excluding the specified device.
    data = load_data(csv_file)
    if not data:
        print("No Bluetooth data loaded. Please check the CSV file for BT/BLE devices.")
        exit(1)

    # Cluster devices based on location.
    clusters = cluster_devices(data)

    # Generate a deduplicated Markdown report.
    generate_markdown_report(clusters)

    # Generate an interactive map for the Bluetooth clusters.
    generate_map(clusters)
