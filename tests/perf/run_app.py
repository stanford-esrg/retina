import argparse
import time
import subprocess
import signal
import sys
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd
import csv

CWD = os.getcwd()
HOME = os.environ.get("HOME")
LD_LIB_PATH = os.environ.get("LD_LIBRARY_PATH")
# MY_ENV = os.environ.copy()
PYTHON_EXEC = sys.executable

def run_app(args):
    # key: number of subscriptions, value: list of runtimes (nanoseconds) at different percentiles
    NUM_SUBS_TO_TIMES = {}

    print("CWD:", CWD)
    print("HOME:", HOME)
    print(f"LD_LIBRARY_PATH: {LD_LIB_PATH}")
    print("PYTHON_EXEC:", PYTHON_EXEC)

    for n in args.num_subs:
        # run generate_ip_subs.py script to generate TOML files with subscriptions
        print("Generating spec.toml...")
        subprocess.run([PYTHON_EXEC, "./tests/perf/generate_ip_subs.py", "-n", f"{n}"], cwd=CWD)

        print("Deleting old ip_subs binaries...")
        subprocess.run("rm -f ./target/release/deps/ip_subs-*", shell=True, cwd=CWD)

        print("Rebuilding ip_subs...")
        subprocess.run(["cargo", "build", "--release", "--bin", "ip_subs"], cwd=CWD)

        # run func_latency.py script on application ip_subs and profile process_packet() in nanoseconds
        cmd = [
            "sudo", "-E", "env", 
            f"LD_LIBRARY_PATH={LD_LIB_PATH}", 
            PYTHON_EXEC,
            "./tests/perf/func_latency.py", 
            "ip_subs", 
            "-b", "./target/release/ip_subs", 
            "-c", args.config,
            "-f", args.function,
        ]
        print("Running func_latency.py...")
        subprocess.run(cmd, cwd=CWD)

        # read generated csv to get the value at some percentile
        print("Reading ip_subs_latency_hist.csv...")
        df = pd.read_csv(f"{CWD}/tests/perf/stats/ip_subs_latency_hist.csv")
        STATS = ["cnt", "avg", "p25", "p50", "p75", "p95", "p99"]
        NUM_SUBS_TO_TIMES[n] = [df.loc[0, stat] for stat in STATS]

        print(f"Number of subscriptions: {n}")
        for stat in STATS:
            if stat == "cnt":
                print(f"{stat}: {df.loc[0, stat]} packets processed")
            else:
                print(f"{stat}: {df.loc[0, stat]} nanoseconds")

    write_stats_to_file("ip_sub", args.function, "nsecs", NUM_SUBS_TO_TIMES, STATS)
    plot_graph(NUM_SUBS_TO_TIMES, STATS, "nanoseconds", "ip_subs", args.function)

def write_stats_to_file(app, func, unit, num_subs_to_times, stats):
    dir = f"{CWD}/tests/perf/stats"
    os.makedirs(dir, exist_ok=True)

    csv_path = os.path.join(dir, f"{app}_latency_stats.csv")

    with open(csv_path, mode='w', newline='') as f:
        writer = csv.writer(f)
        headers = ["func", "unit", "num_subs"]
        headers.extend(stats)
        writer.writerow(headers)

        for k in sorted(num_subs_to_times.keys()):
            row = [func, unit, k]
            row.extend(num_subs_to_times[k])

            writer.writerow(row)

def plot_graph(d, labels, unit, app, func):
    dir = f"{CWD}/tests/perf/figs"
    os.makedirs(dir, exist_ok=True)

    x_vals = list(d.keys())
    y_lists = list(zip(*(d[x] for x in x_vals)))

    for label, y_vals in zip(labels, y_lists):
        # plot num of subscriptions vs. runtime for each stat of interest
        plt.plot(x_vals, y_vals, label=label)
        plt.xlabel('number of subscriptions')
        plt.ylabel(f'runtime ({unit})')
        plt.title(f"app: {app}, function: {func}")
        plt.legend()
        plt.savefig(os.path.join(dir, f"{app}_{label}.png"), dpi=300, bbox_inches='tight')
        plt.clf()

def comma_sep_list(value):
    return value.split(',')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--num_subs", type=comma_sep_list)
    parser.add_argument("-c", "--config")
    parser.add_argument("-f", "--function")
    args = parser.parse_args()

    run_app(args)


