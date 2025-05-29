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

def run_app(args):
    # key: number of subscriptions, value: list of runtimes (nanoseconds) at different percentiles
    NUM_SUBS_TO_TIMES = {}

    cwd = os.getcwd()

    for n in args.num_subs:
        # if n isn't a power of 2, get the next power of 2
        if int(n) % 2 != 0:
            n = 1 << (n - 1).bit_length()
        # run generate_ip_subs.py script to generate TOML files with subscriptions
        print("Generating spec.toml...")
        generate_ip_subs_cmd = f"perf-env/bin/python3 {cwd}/tests/perf/generate_ip_subs.py -n {n}"
        p0 = subprocess.run(generate_ip_subs_cmd, shell=True, capture_output=True, text=True)
        print(p0.stdout)

        print("Deleting old ip_subs binaries...")
        delete_binary_files = f"rm -f {cwd}/target/release/deps/ip_subs-*"
        subprocess.run(delete_binary_files, shell=True)

        print("Rebuilding ip_subs...")
        home_path = os.environ.get("HOME")
        force_binary_rebuild = f"{home_path}/.cargo/bin/cargo build --release --bin ip_subs"
        p1 = subprocess.run(force_binary_rebuild, shell=True)
        print(p1.stdout)

        # run func_latency.py script on application ip_subs and profile process_packet() in nanoseconds
        binary_path = f"{cwd}/target/release/ip_subs"
        ld_library_path = os.environ.get("LD_LIBRARY_PATH")
        print(f"ld_library_path: {ld_library_path}")
        cmd = [
            "sudo", "-E", "env", 
            f"LD_LIBRARY_PATH={ld_library_path}", 
            "perf-env/bin/python3", 
            f"{cwd}/tests/perf/func_latency.py", 
            "ip_subs", 
            "-b", binary_path, 
            "-c", args.config,
            "-f", args.function,
        ]

        print("Running func_latency.py...")
        p2 = subprocess.Popen(cmd)

        # read generated csv to get the value at some percentile
        print("Reading ip_subs_latency_hist.csv...")
        df = pd.read_csv(f"{cwd}/tests/perf/stats/ip_subs_latency_hist.csv")
        STATS = ["avg", "p25", "p50", "p75", "p95", "p99"]
        NUM_SUBS_TO_TIMES[n] = [df.loc[0, stat] for stat in STATS]
        print('times:', NUM_SUBS_TO_TIMES[n])
        for stat in STATS:
            print(f"{stat}: {df.loc[0, stat]} nanoseconds")

        num_pkts_processed = df.loc[0, 'cnt']
        print(f"Number of subscriptions: {n}, Number of packets processed: {num_pkts_processed}")

    plot_graph(NUM_SUBS_TO_TIMES, STATS, "nanoseconds", "ip_subs", args.function)

def dump_stats():
    cwd = os.getcwd()
    dir = f"{cwd}/tests/perf/stats"
    os.makedirs(dir, exist_ok=True)

    csv_path = os.path.join(dir, f"{app}_latency_stats.csv")

    with open(csv_path, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(STATS)

        for func_id, hist in funcs_and_hists.items():
            func_name = func_id_mappings[func_id]
            row = [
                func_name,
                unit,
                hist.get_total_count(),
                f"{hist.get_mean_value():.3f}",
                hist.get_min_value(),
                hist.get_value_at_percentile(5),
                hist.get_value_at_percentile(25),
                hist.get_value_at_percentile(50),
                hist.get_value_at_percentile(75),
                hist.get_value_at_percentile(95),
                hist.get_value_at_percentile(99),
                hist.get_value_at_percentile(99.9),
                hist.get_max_value(),
                f"{hist.get_stddev():.3f}"
            ]

            writer.writerow(row)

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
    parser.add_argument("-c", "--config")
    parser.add_argument("-f", "--function")
    args = parser.parse_args()

    run_app(args)


