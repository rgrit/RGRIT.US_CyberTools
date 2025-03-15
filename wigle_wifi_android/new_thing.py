import pandas as pd
import math
from itertools import combinations
from tabulate import tabulate
import tkinter as tk
from tkinter import ttk, messagebox
import folium
from folium.plugins import MarkerCluster
import webbrowser
import os


# ----------------------------
# Helper Functions
# ----------------------------

def haversine(lat1, lon1, lat2, lon2):
    """Calculate the great circle distance between two points (in meters)"""
    # Convert decimal degrees to radians
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.asin(math.sqrt(a))
    r = 6371000  # Radius of Earth in meters.
    return c * r


def process_data(csv_file):
    """
    Load the CSV and process it:
    - Round coordinates to create an "approximate location" (to mitigate sensor noise)
    - Group by SSID and count distinct approximate locations.
    - Return both the full DataFrame (df) and a summary DataFrame (results_df)
      that includes unique MAC counts, min and max pairwise distances.
    """
    df = pd.read_csv(csv_file)

    # Create rounded coordinates (adjust precision as needed; 4 decimals ~ 11m)
    df['RoundedLatitude'] = df['CurrentLatitude'].round(4)
    df['RoundedLongitude'] = df['CurrentLongitude'].round(4)
    df['ApproxLocation'] = list(zip(df['RoundedLatitude'], df['RoundedLongitude']))

    # Group by SSID to count unique approximate locations
    ssid_counts = df.groupby('SSID')['ApproxLocation'].nunique().reset_index(name='Distinct_Approx_Locations')
    # Filter for SSIDs with more than one location
    multi_loc_ssids = ssid_counts[ssid_counts['Distinct_Approx_Locations'] > 1]['SSID'].tolist()

    # Build summary statistics for each such SSID.
    summary_list = []
    for ssid in multi_loc_ssids:
        sub_df = df[df['SSID'] == ssid]
        unique_mac_count = sub_df['MAC'].nunique()
        points = list(zip(sub_df['CurrentLatitude'], sub_df['CurrentLongitude']))
        if len(points) < 2:
            continue
        distances = [haversine(lat1, lon1, lat2, lon2)
                     for (lat1, lon1), (lat2, lon2) in combinations(points, 2)]
        min_distance = min(distances) if distances else 0
        max_distance = max(distances) if distances else 0

        summary_list.append({
            'SSID': ssid,
            'Distinct_Approx_Locations': sub_df['ApproxLocation'].nunique(),
            'Unique_MAC_Count': unique_mac_count,
            'Min_Distance_m': round(min_distance, 2),
            'Max_Distance_m': round(max_distance, 2)
        })

    results_df = pd.DataFrame(summary_list)
    results_df = results_df.sort_values(by='Distinct_Approx_Locations', ascending=False)

    return df, results_df


def generate_map(filtered_df, output_file='selected_ssids_map.html'):
    """
    Generates an interactive map using Folium from filtered_df (which contains only the selected SSIDs).
    """
    if filtered_df.empty:
        messagebox.showinfo("No Data", "No records found for the selected SSID(s).")
        return

    # Gather valid coordinates
    coords = []
    for idx, row in filtered_df.iterrows():
        try:
            lat = float(row["CurrentLatitude"])
            lon = float(row["CurrentLongitude"])
            coords.append((lat, lon))
        except (ValueError, KeyError):
            continue

    if not coords:
        messagebox.showinfo("No Coordinates", "No valid coordinates found for the selected SSID(s).")
        return

    # Calculate average for centering the map.
    avg_lat = sum(lat for lat, lon in coords) / len(coords)
    avg_lon = sum(lon for lat, lon in coords) / len(coords)

    # Create map centered at the average location.
    m = folium.Map(location=[avg_lat, avg_lon], zoom_start=15)
    marker_cluster = MarkerCluster().add_to(m)

    for idx, row in filtered_df.iterrows():
        try:
            lat = float(row["CurrentLatitude"])
            lon = float(row["CurrentLongitude"])
        except (ValueError, KeyError):
            continue
        popup_text = f"<strong>SSID:</strong> {row.get('SSID', 'N/A')}<br>" \
                     f"<strong>MAC:</strong> {row.get('MAC', 'N/A')}<br>" \
                     f"<strong>Channel:</strong> {row.get('Channel', 'N/A')}<br>" \
                     f"<strong>RSSI:</strong> {row.get('RSSI', 'N/A')}"
        folium.Marker(location=[lat, lon], popup=popup_text).add_to(marker_cluster)

    m.save(output_file)
    # Open the generated map in the default web browser.
    webbrowser.open('file://' + os.path.realpath(output_file))


# ----------------------------
# GUI Code
# ----------------------------

class SSIDMapGUI:
    def __init__(self, master, full_df, summary_df):
        self.master = master
        self.full_df = full_df
        self.summary_df = summary_df

        master.title("SSID Map Viewer")

        label = ttk.Label(master, text="Select one or more SSIDs:")
        label.pack(pady=5)

        # Create a Listbox with multiple selection enabled.
        self.listbox = tk.Listbox(master, selectmode=tk.MULTIPLE, width=60, height=15)
        self.listbox.pack(padx=10, pady=5)

        # Populate the listbox with SSID info from summary_df.
        # Format: "SSID - X Locations, Y MACs, Min: A m, Max: B m"
        for idx, row in summary_df.iterrows():
            entry = f"{row['SSID']} - {row['Distinct_Approx_Locations']} Locations, " \
                    f"{row['Unique_MAC_Count']} MACs, Min: {row['Min_Distance_m']} m, Max: {row['Max_Distance_m']} m"
            self.listbox.insert(tk.END, entry)

        # Button to view selected SSIDs on map.
        self.view_button = ttk.Button(master, text="View on Map", command=self.view_on_map)
        self.view_button.pack(pady=10)

    def view_on_map(self):
        # Get selected indices
        selected_indices = self.listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("No Selection", "Please select at least one SSID.")
            return

        # Extract SSID names from the selected entries.
        selected_ssids = []
        for idx in selected_indices:
            # The SSID is the first part of the string, before the first " - "
            entry_text = self.listbox.get(idx)
            ssid = entry_text.split(" - ")[0]
            selected_ssids.append(ssid)

        # Filter the full DataFrame for rows with these SSIDs.
        filtered_df = self.full_df[self.full_df['SSID'].isin(selected_ssids)]
        generate_map(filtered_df)


def main():
    # Update CSV path if needed.
    csv_file = "<<YOur Cleaned Data>>"
    try:
        full_df, summary_df = process_data(csv_file)
    except Exception as e:
        print("Error processing CSV data:", e)
        return

    # Print the summary table in the console.
    print("Summary Table:")
    print(tabulate(summary_df, headers=["SSID", "Distinct_Approx_Locations", "Unique_MAC_Count", "Min_Distance_m",
                                        "Max_Distance_m"], tablefmt="psql", showindex=False))

    # Create and run the Tkinter GUI.
    root = tk.Tk()
    gui = SSIDMapGUI(root, full_df, summary_df)
    root.mainloop()


if __name__ == "__main__":
    main()
