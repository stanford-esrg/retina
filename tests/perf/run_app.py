import argparse
import time
import subprocess
import sys
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd

def run_app(args):
    # key: number of subscriptions, value: list of runtimes (nanoseconds) at different percentiles
    NUM_SUBS_TO_TIMES = {}

    cwd = os.getcwd()

    for n in args.num_subs:
        # if n isn't a power of 2, get the next power of 2
        if int(n) % 2 != 0:
            n = 1 << (n - 1).bit_length()
        # run generate_subs.py script to generate TOML files with subscriptions
        generate_subs_cmd = f"python3 {cwd}/tests/perf/generate_subs.py -n {n}"
        p0 = subprocess.run(generate_subs_cmd, shell=True, capture_output=True, text=True)
        print(p0.stdout)

        delete_binary_files = f"rm {cwd}/target/release/deps/ip_sub-*"
        subprocess.run(delete_binary_files, shell=True)
        force_binary_rebuild = f"cargo build --release --bin ip_sub"
        p1 = subprocess.run(force_binary_rebuild, shell=True)
        print(p1.stdout)

        # run func_latency.py script on application ip_sub and profile process_packet() in nanoseconds
        binary_path = f"{cwd}/target/release/ip_sub"
        ld_library_path = os.environ.get("LD_LIBRARY_PATH")
        print(f"ld_library_path: {ld_library_path}")
        cmd = f"sudo -E env LD_LIBRARY_PATH={ld_library_path} python3 {cwd}/tests/perf/func_latency.py ip_sub -b {binary_path} -c {args.config} -f {args.function}"
        subprocess.run(cmd, shell=True, capture_output=True, text=True)

        # read generated csv to get the value at some percentile
        df = pd.read_csv(f"{cwd}/tests/perf/stats/ip_sub_latency_hist.csv")
        STATS = ["avg", "p25", "p50", "p75", "p95", "p99"]
        NUM_SUBS_TO_TIMES[n] = [df.loc[0, stat] for stat in STATS]
        print('times:', NUM_SUBS_TO_TIMES[n])
        for stat in STATS:
            print(df.loc[0, stat])

        num_pkts_processed = df.loc[0, 'cnt']
        print(f"Number of subscriptions: {n}, Number of packets processed: {num_pkts_processed}")

    plot_graph(NUM_SUBS_TO_TIMES, STATS, "nanoseconds", "ip_sub", args.function)

def plot_graph(d, labels, unit, app, func):
    cwd = os.getcwd()
    dir = f"{cwd}/tests/perf/figs"
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
    parser.add_argument("-c", "--config", default="./configs/offline.toml")
    parser.add_argument("-f", "--function")
    args = parser.parse_args()

    run_app(args)


