# code for profiling function latency with bcc based on https://github.com/iovisor/bcc/blob/master/tools/funclatency.py

import argparse
import subprocess
import sys
import os
from bcc import BPF
from hdrh.histogram import HdrHistogram
import ctypes
import csv

CWD = os.getcwd()
LD_LIB_PATH = os.environ.get("LD_LIBRARY_PATH")

PERF_DIR = f"{CWD}/tests/perf"
PERF_STATS_DIR = f"{PERF_DIR}/stats"

STATS = ["func", "unit", "cnt", "avg", "min", "p05", "p25", "p50", "p75", "p95", "p99", "p999", "max", "std"]

class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("func_id", ctypes.c_uint64),
        ("latency", ctypes.c_ulonglong),
    ]

def profile_latency(args):
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
    for i, func in enumerate(args.function):
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
    
    funcs = []
    for func in args.function:
        get_mangled_name_cmd = f"nm {args.binary} | grep {func} | awk '{{print $3}}'"
        p1 = subprocess.run(get_mangled_name_cmd, shell=True, capture_output=True, text=True)
        mangled_name = p1.stdout.strip()

        if not mangled_name:
            print(f"{func} is never called.")
            continue

        funcs.append(mangled_name)

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

    cmd = [
        "sudo",
        "env", f"LD_LIBRARY_PATH={LD_LIB_PATH}",
        "RUST_LOG=error", args.binary, 
        "-c", args.config
    ]
    p2 = subprocess.Popen(cmd)

    try:
        while p2.poll() is None:
            b.perf_buffer_poll(timeout=1)
        p2.terminate()
        p2.wait()
    except KeyboardInterrupt:
        p2.kill()

    dump_stats(args.app, unit, FUNCS_AND_HISTS, FUNC_ID_MAPPINGS)

def dump_stats(app, unit, funcs_and_hists, func_id_mappings):
    os.makedirs(PERF_STATS_DIR, exist_ok=True)
    csv_path = os.path.join(PERF_STATS_DIR, f"{app}_latency_hist.csv")

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

def comma_sep_list(value):
    return value.split(',')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("app")
    parser.add_argument("-b", "--binary")
    parser.add_argument("-c", "--config")
    parser.add_argument("-f", "--function", type=comma_sep_list)
    parser.add_argument("-u", "--microseconds", action="store_true", default=False)
    args = parser.parse_args()
            
    profile_latency(args)