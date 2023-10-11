import argparse
import json
import csv

# Define command-line arguments
parser = argparse.ArgumentParser(description="Convert JSON to CSV")
parser.add_argument("input_file", help="Input Naabu JSON file path")
parser.add_argument("output_file", help="Output CSV file path")
args = parser.parse_args()

# Open the input JSON file for reading
with open(args.input_file, 'r') as json_file:
    data = json_file.readlines()

# Open the output CSV file for writing
with open(args.output_file, 'w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)

    # Write the CSV header based on your desired fields
    csv_writer.writerow(['ip', 'port', 'protocol', 'tls', 'timestamp'])

    # Iterate over each JSON object in the file
    for line in data:
        item = json.loads(line)
        csv_writer.writerow([item['ip'], item['port'], item['protocol'], item['tls'], item['timestamp']])
