import os 
import sys
from datetime import datetime
import time

def run_multi(arg=""):
    with_sessions = "connections + sessions, high collapse"
    conn_only = "connections only, high collapse"
    conn_parse = "connections only, high collapse, with parsing"
    non_overlapping = "non_overlapping, lots of eq, high mutual excl"
    # for exp in [conn_only, with_sessions]:
    for exp in [non_overlapping]:
        for multi in [100, 500, 1000, 10000]:
            if exp == with_sessions or exp == conn_parse:
                os.system("python3 examples/basic/filtergen.py " + str(multi) + " sessions")
            elif exp == non_overlapping:
                os.system("python3 examples/basic/filtergen.py " + str(multi) + " non_overlapping")
            else:
                os.system("python3 examples/basic/filtergen.py " + str(multi))
            os.system("cargo build --bin basic --release")
            print("Running Retina with num subscriptions: " + str(multi) + " exp " + exp)
            os.system("sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/basic --config configs/online.toml")
            print("DONE RUNNING RETINA -- " + str(multi) + ", " + exp)
            print("********************************")

run_multi()