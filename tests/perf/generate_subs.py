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
    # key: number of subscriptions, value: runtime (usecs) at some percentile
    NUM_SUBS_TO_TIME = {}
    print("args.num_subs:", args.num_subs)

    for n in args.num_subs:
        # run the script to generate a spec.toml with n subs
        try:
            sub_gen_script = f"./target/release/benchmark_app"
            p0 = subprocess.run([sub_gen_script, n], check=True, capture_output=True, text=True)
            print(p0.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Failed to generate TOML with {n} subscriptions: {e}")
            sys.exit(1)
        
        # TODO: fix paths
        subprocess.run(["/home/dianaq/.cargo/bin/cargo", "build", "--release", "--bin", "ip_sub"], shell=True, capture_output=True, text=True)

        # run func_latency.py on application ip_sub and profile process_packet()
        # ld_library_path = os.environ["LD_LIBRARY_PATH"]
        ld_library_path = "/home/dianaq/dpdk-21.08/lib/aarch64-linux-gnu"
        cmd = f"sudo -E env LD_LIBRARY_PATH={ld_library_path} python3 tests/perf/func_latency.py ip_sub -b ./target/release/ip_sub -c {args.config} -f process_packet -u"
        subprocess.run(cmd, shell=True)

        # read generated csv to get the value at some percentile
        df = pd.read_csv(f"./tests/perf/stats/ip_sub_latency_hist.csv")
        NUM_SUBS_TO_TIME[n] = df.loc[0, 'p95']

    plot_graph(NUM_SUBS_TO_TIME, "ip_sub", "process_packet", "usecs")

def plot_graph(d, app, func, unit):
    dir = "./tests/perf/figs"
    os.makedirs(dir, exist_ok=True)

    # plot num subs vs. runtime
    plt.plot(list(d.keys()), list(d.values()))
    plt.xlabel('number of subscriptions')
    plt.ylabel(f'runtime ({unit})')
    plt.title(f"app: {app}, function: {func} (95th percentile)")
    plt.savefig(os.path.join(dir, f"{app}.png"), dpi=300, bbox_inches='tight')
    plt.clf()

def comma_sep_list(value):
    return value.split(',')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--num_subs", type=comma_sep_list)
    # parser.add_argument("-f", "--function")
    parser.add_argument("-c", "--config", default="./configs/offline.toml")
    args = parser.parse_args()

    run_app(args)


