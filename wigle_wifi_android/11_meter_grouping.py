import pandas as pd
import math
from itertools import combinations
from tabulate import tabulate


# Haversine distance function (in meters)
def haversine(lat1, lon1, lat2, lon2):
    """
    Calculate the great circle distance between two points on the Earth (in meters)
    """
    # convert decimal degrees to radians
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.asin(math.sqrt(a))
    r = 6371000  # Radius of Earth in meters.
    return c * r


# Configuration: update these as needed.
csv_file = "cleaned_WigleWifi_20250313060520.csv"  # Update with your CSV file path

# Load the CSV into a DataFrame.
df = pd.read_csv(csv_file)

# Create rounded coordinates to account for sensor noise.
# Adjust the rounding precision as needed (4 decimals ~ 11m precision).
df['RoundedLatitude'] = df['CurrentLatitude'].round(4)
df['RoundedLongitude'] = df['CurrentLongitude'].round(4)

# Create an "approximate location" tuple from the rounded coordinates.
df['ApproxLocation'] = list(zip(df['RoundedLatitude'], df['RoundedLongitude']))

# Group by SSID and count the number of unique approximate locations.
ssid_location_counts = df.groupby('SSID')['ApproxLocation'].nunique().reset_index(name='Distinct_Approx_Locations')

# Filter to include only SSIDs that appear in more than one unique approximate location.
multi_loc_ssids = ssid_location_counts[ssid_location_counts['Distinct_Approx_Locations'] > 1]['SSID'].tolist()

results = []
for ssid in multi_loc_ssids:
    sub_df = df[df['SSID'] == ssid]

    # Count unique MAC addresses for this SSID.
    unique_mac_count = sub_df['MAC'].nunique()

    # Gather original coordinates.
    points = list(zip(sub_df['CurrentLatitude'], sub_df['CurrentLongitude']))

    # Skip if there are less than two points.
    if len(points) < 2:
        continue

    # Compute all pairwise distances.
    distances = [haversine(lat1, lon1, lat2, lon2)
                 for (lat1, lon1), (lat2, lon2) in combinations(points, 2)]

    if distances:
        min_distance = min(distances)
        max_distance = max(distances)
    else:
        min_distance = 0
        max_distance = 0

    results.append({
        'SSID': ssid,
        'Distinct_Approx_Locations': sub_df['ApproxLocation'].nunique(),
        'Unique_MAC_Count': unique_mac_count,
        'Min_Distance_m': round(min_distance, 2),
        'Max_Distance_m': round(max_distance, 2)
    })

# Create a DataFrame from the results.
results_df = pd.DataFrame(results)

# Sort the results descending by the number of distinct locations.
results_df = results_df.sort_values(by='Distinct_Approx_Locations', ascending=False)

# Print the table using tabulate.
print("SSIDs (with more than one approximate location) with unique MAC count, closest and farthest neighbor distances:")
print(tabulate(results_df,
               headers=["SSID", "Distinct_Approx_Locations", "Unique_MAC_Count", "Min_Distance_m", "Max_Distance_m"],
               tablefmt="psql", showindex=False))
