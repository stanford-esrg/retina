#!/usr/bin/env python3

import argparse
import subprocess
import os
import sys
import difflib

def main():
    parser = argparse.ArgumentParser(
        description="Run a debug build of the Retina test app with expected output and pcap files."
    )
    parser.add_argument("app_name", help="Name of the test application binary (e.g., basic_test)")
    parser.add_argument("expected_output_file_path", help="Path to the expected output binary file")
    parser.add_argument("output_file_path", help="Path to the output file")
    parser.add_argument("pcap_file", help="Path to the packet capture (pcap) file")

    args = parser.parse_args()

    app_directory = os.path.join("..", "retina", "target", "debug", args.app_name)
    command_args = [app_directory]

    try:
        result = subprocess.run(
            command_args,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print("Output:\n", result.stdout)

        # Skip the first 3 lines of output and save stdout (JSON from Rust app) to output file
        lines = result.stdout.splitlines()
        cleaned_output = "\n".join(lines[3:])

        with open(args.output_file_path, "w") as f:
            f.write(cleaned_output)

        print(f"Output written to {args.output_file_path}")

    except subprocess.CalledProcessError as e:
        print("Error:\n", e.stderr)
    except FileNotFoundError:
        print(f"Executable not found: {app_directory}")
        sys.exit(1)

    # Run diff on output file and expected_output file
    diff_files(args.output_file_path, args.expected_output_file_path)

# Helper function
def diff_files(file1, file2):
    with open(file1) as f1, open(file2) as f2:
        lines1 = f1.readlines()
        lines2 = f2.readlines()

    diff = difflib.unified_diff(
        lines1,
        lines2,
        fromfile=file1,
        tofile=file2,
        lineterm=""
    )

    diff_output = list(diff)
    if diff_output:
        print("Differences found:")
        for line in diff_output:
            print(line)
    else:
        print("Output files are identical. Test passed!")    

if __name__ == "__main__":
    main()
