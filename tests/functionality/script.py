#!/usr/bin/env python3

import subprocess
import sys
import os

if len(sys.argv) < 4:
    print("Please pass in the testing app name, input file, and pcap file as arguments!")
    print("Format: [app_name] [input file path] [pcap file path]")
    sys.exit(1)

app_name = sys.argv[1]
input_file = sys.argv[2]
pcap_file = sys.argv[3] # path to config file, reads from pcap file use offline pcap
app_directory = os.path.join("..", "retina", "target", "debug", app_name)

args = [input_file, pcap_file]

try:
    result = subprocess.run(
            [app_directory],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
    )
    print("Output:\n", result.stdout)

# Check if output matches input file format / values
# Print whether passed or not

except subprocess.CalledProcessError as e:
    print("Error:\n", e.stderr)
