import argparse
import time
import subprocess
import os
from bcc import BPF
from hdrh.histogram import HdrHistogram
# import matplotlib
# matplotlib.use('Agg')
# import matplotlib.pyplot as plt
import ctypes
import csv

class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("func_id", ctypes.c_uint64),
        ("latency", ctypes.c_ulonglong),
    ]

def latency_hist(args):
    setup_code = """
    #include <uapi/linux/ptrace.h>

    struct key_t {
        u64 pid;
        u64 func_id;
    };

    struct data_t {
        u32 pid;
        u64 func_id;
        u64 latency;
    };

    struct hist_key_t {
        u64 func_id;
        u64 slot;
    };

    BPF_HISTOGRAM(dist, struct hist_key_t);
    BPF_HASH(start, struct key_t, u64);
    BPF_PERF_OUTPUT(latencies);
    """

    entry_exit_code = """
    int trace_func_{id}_entry(struct pt_regs *ctx)
    {{
        struct key_t key = {{}};
        key.pid = bpf_get_current_pid_tgid();
        key.func_id = {id};

        u64 ts = bpf_ktime_get_ns();

        start.update(&key, &ts);
        return 0;
    }}

    int trace_func_{id}_exit(struct pt_regs *ctx)
    {{
        struct key_t key = {{}};
        key.pid = bpf_get_current_pid_tgid();
        key.func_id = {id};

        u64 *tsp = start.lookup(&key);
        if (tsp == 0) return 0;  

        u64 delta = bpf_ktime_get_ns() - *tsp;
        TIMING_UNIT

        struct data_t data = {{}};
        data.pid = key.pid;
        data.func_id = key.func_id;
        data.latency = delta;
        latencies.perf_submit(ctx, &data, sizeof(data));

        struct hist_key_t hkey = {{}};
        hkey.func_id = key.func_id;
        hkey.slot = bpf_log2l(delta);
        dist.increment(hkey);

        start.delete(&key);
        return 0;
    }}
    """
    probing_code = ""
    FUNC_ID_MAPPINGS = {}
    for i, func in enumerate(args.functions):
        func_id = i + 1
        FUNC_ID_MAPPINGS[func_id] = func
        probing_code += entry_exit_code.format(id=func_id)
    bpf_program = setup_code + probing_code

    if args.microseconds:
        bpf_program = bpf_program.replace('TIMING_UNIT', 'delta /= 1000;')
        unit = "usecs"
    else:
        bpf_program = bpf_program.replace('TIMING_UNIT', '')
        unit = "nsecs" 

    # path = f"/home/dianaq/Downloads/retina-fork/retina/target/debug/{args.app}"
    # path = f"./target/debug/{args.app}"
    
    funcs = []
    # get the mangled function name to pass into attach_uprobe() and attach_uretprobe()
    # TODO: what if different modules have funcs with the same name
    for func in args.functions:
        get_mangled_name_cmd = f"nm {args.binary} | grep {func} | awk '{{print $3}}'"
        p1 = subprocess.run(get_mangled_name_cmd, shell=True, capture_output=True, text=True)
        mangled_name = p1.stdout.strip()

        if not mangled_name:
            print(f"{func} is never called.")
            continue
        
        print('mangled_name:', mangled_name)
        print('address:', BPF.get_user_addresses(args.binary, mangled_name))
        funcs.append(mangled_name)

    # no functions to profile 
    if not funcs: 
        return

    b = BPF(text=bpf_program)

    for i, func_mangled_name in enumerate(funcs):
        try:
            func_id = i + 1
            entry_func = f"trace_func_{func_id}_entry"
            exit_func = f"trace_func_{func_id}_exit"
            b.attach_uprobe(name=args.binary, sym=func_mangled_name, fn_name=entry_func, pid=-1)
            b.attach_uretprobe(name=args.binary, sym=func_mangled_name, fn_name=exit_func, pid=-1) 
        except Exception as e:
            print(f"Failed to attach uprobes: {e}")

    # n_open_probes = b.num_open_uprobes()
    # print('n_open_probes:', n_open_probes)
    
    FUNCS_AND_HISTS = {}

    def handle_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Data)).contents
        if event.func_id not in FUNCS_AND_HISTS:
            if args.microseconds:
                FUNCS_AND_HISTS[event.func_id] = HdrHistogram(1, 60 * 60 * 1000 * 1000, 3)
            else: # nanoseconds 
                FUNCS_AND_HISTS[event.func_id] = HdrHistogram(1, 60 * 60 * 1000 * 1000 * 1000, 3)
        FUNCS_AND_HISTS[event.func_id].record_value(event.latency)
    b["latencies"].open_perf_buffer(handle_event)

    ld_library_path = os.environ.get("LD_LIBRARY_PATH")
    cmd = f"sudo env LD_LIBRARY_PATH={ld_library_path} RUST_LOG=error {args.binary} -c {args.config}"
    p2 = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 
    # p2 = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # stdout, stderr = p2.communicate()
    # print('STDOUT:', stdout)

    try:
        while p2.poll() is None:
            b.perf_buffer_poll(timeout=1)
    except KeyboardInterrupt:
        p2.kill()
    
    # dist = b.get_table("dist")
    # print("Latency Histogram:")
    # dist.print_log2_hist(unit)
    dump_stats(args.app, unit, FUNCS_AND_HISTS, FUNC_ID_MAPPINGS)
    
    # if args.plot:
    #     plot_latency_hist(args.app, unit, FUNCS_AND_HISTS, FUNC_ID_MAPPINGS)

def dump_stats(app, unit, funcs_and_hists, func_id_mappings):
    STATS = ["func", "unit", "cnt", "avg", "min", "p05", "p25", "p50", "p75", "p95", "p99", "p999", "max", "std"]

    dir = "./tests/perf/stats"
    os.makedirs(dir, exist_ok=True)

    # print("dump_stats app:", app)
    csv_path = os.path.join(dir, f"{app}_latency_hist.csv")

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

def plot_latency_hist(app, unit, funcs_and_hists, func_id_mappings):
    dir = "./tests/perf/figs"
    os.makedirs(dir, exist_ok=True)

    for func_id, hist in funcs_and_hists.items():
        func_name = func_id_mappings[func_id]
        latencies = raw_latencies(hist)

        plt.hist(latencies)
        plt.grid(True, ls="--")
        plt.xlabel(f'latency ({unit})')
        plt.ylabel('count')
        plt.title(f'Latency Distribution for {func_name}() for app {app}')

        plt.savefig(os.path.join(dir, f"{app}_{func_name}_latency.png"), dpi=300, bbox_inches='tight')
        plt.clf()

def raw_latencies(hist):
    latencies = []
    for item in hist.get_recorded_iterator():
        latencies.extend([item.value_iterated_to] * item.count_added_in_this_iter_step)
    return latencies

def comma_sep_list(value):
    return value.split(',')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("app")
    parser.add_argument("-b", "--binary")
    parser.add_argument("-c", "--config", default="./configs/offline.toml")
    parser.add_argument("-f", "--functions", type=comma_sep_list)
    parser.add_argument("-u", "--microseconds", action="store_true")
    # parser.add_argument("-p", "--plot", action="store_true")
    args = parser.parse_args()
            
    latency_hist(args)