import csv
import xml.etree.ElementTree as ET

# Define the input CSV filename and output OPML filename.
csv_filename = "/Awesome Threat Intel Blogs - MASTER.csv"
opml_filename = 'feeds.opml'

# Create the OPML structure.
opml = ET.Element('opml', version="1.0")
head = ET.SubElement(opml, 'head')
title = ET.SubElement(head, 'title')
title.text = "RSS Feeds"
body = ET.SubElement(opml, 'body')

# Open and read the CSV file.
with open(csv_filename, newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
    print("CSV Headers:", reader.fieldnames)  # Debug: show CSV headers
    for row in reader:
        print("Row:", row)  # Debug: show each row

        # Use the correct keys for your CSV.
        feed_title = row.get('Blog Name')
        feed_url = row.get('Feed Link')

        # Only add an outline if both title and URL exist.
        if feed_title and feed_url:
            ET.SubElement(body, 'outline',
                          text=feed_title,
                          title=feed_title,
                          type="rss",
                          xmlUrl=feed_url)

# Write the OPML XML to a file.
tree = ET.ElementTree(opml)
tree.write(opml_filename, encoding='utf-8', xml_declaration=True)

print(f"OPML file '{opml_filename}' has been created successfully.")
