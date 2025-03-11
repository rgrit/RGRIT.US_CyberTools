import os
import re
import json


def scrape_markdown(directory):
    """
    Walk through all markdown files in the specified directory,
    extract MITRE codes (tactics, techniques, and sub-techniques),
    and count their occurrences.
    """
    # Regex explanation:
    # - \b: word boundary to ensure we match standalone codes.
    # - (?:TA\d{4}): Matches tactics (e.g., TA0001).
    # - (?:T\d{4}(?:\.\d{3})?): Matches techniques (e.g., T1202) and sub-techniques (e.g., T1059.001).
    pattern = re.compile(r'\b(?:(?:TA\d{4})|(?:T\d{4}(?:\.\d{3})?))\b')
    counts = {}

    for filename in os.listdir(directory):
        if filename.endswith('.md'):
            filepath = os.path.join(directory, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                matches = pattern.findall(content)
                for code in matches:
                    counts[code] = counts.get(code, 0) + 1
    return counts


def generate_heatmap_json(counts, output_file):
    """
    Generate a JSON file for the ATT&CK Navigator heatmap.
    The JSON structure includes a list of techniques (or tactics)
    with a score based on the count from the markdown files.
    """
    techniques = []
    for code, score in counts.items():
        techniques.append({
            "techniqueID": code,
            "score": score
        })

    # Define a heatmap configuration.
    heatmap = {
        "version": "4.2",
        "name": "Extracted Heatmap",
        "description": "Heatmap generated from markdown files.",
        "domain": "mitre-enterprise",
        "techniques": techniques,
        "gradient": {
            "colors": [
                "#ffffff",
                "#ff0000"
            ],
            "minValue": 0,
            "maxValue": max(counts.values()) if counts else 1
        },
        "legendItems": [
            {
                "label": "Score",
                "color": "#ff0000"
            }
        ]
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(heatmap, f, indent=4)


def main():
    # Set the directory containing your markdown files.
    directory = "/home/administrator/PycharmProjects/Day-To-Day/CTI_and_Detection/rss_feed_to_detection/reports"  # <-- Modify this path accordingly
    output_file = "/home/administrator/PycharmProjects/Day-To-Day/CTI_and_Detection/rss_feed_to_detection/reportsattack_heatmap.json"

    counts = scrape_markdown(directory)
    print("Extracted MITRE codes and counts:")
    for code, count in counts.items():
        print(f"{code}: {count}")

    generate_heatmap_json(counts, output_file)
    print(f"Heatmap JSON file has been generated: {output_file}")


if __name__ == '__main__':
    main()
