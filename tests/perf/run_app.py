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
        # run generate_subs.py script to generate TOML files with subscriptions
        generate_subs_cmd = f"python3 {cwd}/tests/perf/generate_subs.py -n {n}"
        p0 = subprocess.run(generate_subs_cmd, shell=True, capture_output=True, text=True)
        print(p0.stdout)

        # run func_latency.py script on application ip_sub and profile process_packet() in nanoseconds
        # TODO: fix paths
        # ld_library_path = os.environ["LD_LIBRARY_PATH"]
        ld_library_path = "/home/dianaq/dpdk-21.08/lib/aarch64-linux-gnu"
        cmd = f"sudo -E env LD_LIBRARY_PATH={ld_library_path} python3 {cwd}/tests/perf/func_latency.py ip_sub -b {args.binary} -c {args.config} -f {args.function}"
        subprocess.run(cmd, shell=True)

        # read generated csv to get the value at some percentile
        df = pd.read_csv(f"{cwd}/tests/perf/stats/ip_sub_latency_hist.csv")
        STATS = ["avg", "p25", "p50", "p75", "p95", "p99"]
        NUM_SUBS_TO_TIMES[n] = [df.loc[0, stat] for stat in STATS]

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
    parser.add_argument("-b", "--binary")
    parser.add_argument("-c", "--config", default="./configs/offline.toml")
    parser.add_argument("-f", "--function")
    args = parser.parse_args()

    run_app(args)


