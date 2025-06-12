import argparse
import subprocess
import sys
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd
import csv
import math

CWD = os.getcwd()
HOME = os.environ.get("HOME")
LD_LIB_PATH = os.environ.get("LD_LIBRARY_PATH")
PYTHON_EXEC = sys.executable

PERF_DIR = f"{CWD}/tests/perf"
PERF_FIGS_DIR = f"{PERF_DIR}/figs"
PERF_STATS_DIR = f"{PERF_DIR}/stats"

STATS = ["cnt", "avg", "p25", "p50", "p75", "p95", "p99"]

def run_app(args):
    os.makedirs(PERF_STATS_DIR, exist_ok=True)
    STATS_CSV_PATH = os.path.join(PERF_STATS_DIR, "ip_subs_latency_stats.csv")

    if args.force_execute and os.path.isfile(STATS_CSV_PATH):
        os.remove(STATS_CSV_PATH)

    for n in args.num_subs:
        n = next_pow_of_2(int(n))

        if not args.force_execute and already_profiled_sub_count(n, STATS_CSV_PATH):
            continue

        print("Generating spec.toml...")
        subprocess.run([PYTHON_EXEC, "./tests/perf/generate_ip_subs.py", "-n", f"{n}"], cwd=CWD)

        print("Deleting old ip_subs binaries...")
        subprocess.run("rm -f ./target/release/deps/ip_subs-*", shell=True, cwd=CWD)

        print("Rebuilding ip_subs...")
        subprocess.run(["cargo", "build", "--release", "--bin", "ip_subs"], cwd=CWD)

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

        print("Reading ip_subs_latency_hist.csv...")
        df = pd.read_csv(f"{PERF_STATS_DIR}/ip_subs_latency_hist.csv")
        results = [df.loc[0, stat] for stat in STATS]
        
        print(f"Writing stats for {n} subscriptions to ip_subs_latency_stats.csv...")
        write_stats(STATS_CSV_PATH, "ip_subs", args.function, "nsecs", n, results)
    
    print("Creating plots...")
    create_plots(STATS_CSV_PATH, "ip_subs", args.function, "nsecs")

def next_pow_of_2(n):
    exp = math.ceil(math.log2(n))
    return 2 ** exp

def already_profiled_sub_count(n, path):
    if not os.path.isfile(path):
        return False
    df = pd.read_csv(path)
    return df['num_subs'].isin([n]).any()

def create_stats_csv(path):
    with open(path, mode='a', newline='') as f:
        writer = csv.writer(f)
        headers = ["func", "unit", "num_subs"]
        headers.extend(STATS)
        writer.writerow(headers)

def write_stats(path, app, func, unit, n, results):
    if not os.path.isfile(path):
        create_stats_csv(path)

    with open(path, mode='a', newline='') as f:
        writer = csv.writer(f)

        row = [func, unit, n]
        row.extend(results)

        writer.writerow(row)

def create_plots(path, app, func, unit):
    os.makedirs(PERF_FIGS_DIR, exist_ok=True)

    df = pd.read_csv(path)
    df = df.sort_values(by='num_subs')

    x_vals = df['num_subs'].to_list()

    for stat in STATS:
        if stat == 'cnt':
            continue
        y_vals = df[stat].to_list()
        plt.plot(x_vals, y_vals, label=stat)
        plt.xlabel('number of subscriptions')
        plt.ylabel(f'latency ({unit})')
        plt.title(f"app: {app}, function: {func}")
        plt.legend()
        plt.savefig(os.path.join(PERF_FIGS_DIR, f"{app}_{stat}.png"), dpi=300, bbox_inches='tight')
        plt.clf()

def comma_sep_list(value):
    return value.split(',')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--num_subs", type=comma_sep_list)
    parser.add_argument("-c", "--config")
    parser.add_argument("-f", "--function")
    parser.add_argument("--force-execute", action="store_true", default=False)
    args = parser.parse_args()

    run_app(args)