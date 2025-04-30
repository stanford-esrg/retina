#!/usr/bin/env python3

import subprocess

app_directory = "../retina/target/debug/test_app"

args = []

try:
    result = subprocess.run(
            [app_directory] + args,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
    )
    print("Output:\n", result.stdout)
except subprocess.CalledProcessError as e:
    print("Error:\n", e.stderr)
