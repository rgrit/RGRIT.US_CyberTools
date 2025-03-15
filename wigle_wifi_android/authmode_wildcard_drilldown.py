import pandas as pd
import re
from tabulate import tabulate


def wildcard_to_regex(pattern):
    """
    Converts a wildcard pattern (using '*' for any sequence and '?' for any single character)
    into a regular expression pattern.
    """
    # Escape regex special characters except for * and ?
    pattern = re.escape(pattern)
    # Replace the escaped wildcards with regex equivalents.
    pattern = pattern.replace(r"\*", ".*").replace(r"\?", ".")
    # The pattern should match anywhere in the string (case-insensitive).
    return pattern


# Configuration: update CSV file path if needed.
csv_file = "<<Your cleaned up file>>"

# Get the wildcard search pattern (you can modify this as desired).
# For example, 'lap*' will match any AuthMode that starts with "lap"
wildcard_pattern = "lapto*"

# Convert wildcard pattern to regex.
regex_pattern = wildcard_to_regex(wildcard_pattern)
print(f"Using regex pattern: {regex_pattern}")

# Load CSV data into a DataFrame.
df = pd.read_csv(csv_file)

# Filter for rows where AuthMode matches the wildcard pattern (case-insensitive).
df_wildcard = df[df['AuthMode'].str.contains(regex_pattern, flags=re.IGNORECASE, regex=True, na=False)]

# Total number of networks matching the wildcard criteria.
total_networks = len(df_wildcard)

# Frequency table by SSID.
ssid_counts = df_wildcard['SSID'].value_counts().reset_index()
ssid_counts.columns = ['SSID', 'Count']

# Define selected columns for detailed records.
selected_columns = [
    "MAC", "SSID", "AuthMode", "FirstSeen",
    "Channel", "Frequency", "RSSI",
    "CurrentLatitude", "CurrentLongitude"
]

# Generate the Markdown report.
output_file = "authmode_wildcard_drilldown.md"
with open(output_file, "w", encoding="utf-8") as f:
    # Report header.
    f.write("# Deep Dive Report: AuthMode Wildcard Search\n\n")
    f.write(f"Wildcard pattern used: **{wildcard_pattern}**\n\n")
    f.write(f"Total networks with AuthMode matching the pattern: **{total_networks}**\n\n")

    # Frequency table by SSID.
    f.write("## Frequency by SSID\n\n")
    f.write(tabulate(ssid_counts, headers="keys", tablefmt="pipe", showindex=False))
    f.write("\n\n---\n\n")

    # Detailed records section.
    f.write("## Detailed Records\n\n")
    if not df_wildcard.empty:
        f.write(tabulate(df_wildcard[selected_columns], headers="keys", tablefmt="pipe", showindex=False))
    else:
        f.write("No records found.\n")

print("Deep dive report generated:", output_file)
