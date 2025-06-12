# Performance Testing

## Dependencies
To use bcc and eBPF, you will need to [install bcc](https://github.com/iovisor/bcc/blob/master/INSTALL.md). If using Ubuntu, we recommend following the instructions to [build from source](https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source).

If you want to run the scripts in a Python virtual environment, you can run:
```
python3 -m venv env
source env/bin/activate
python3 -m pip install -U matplotlib
pip install pandas
pip install hdrhistogram
pip install tomli-w
source env/bin/activate
```

## Number of Subscriptions vs. Function Latency
`generate_ip_subs.py` shards the IPv4 address space into `n` subnets to generate `n` Retina subscriptions, where `n` is passed in by the user. The subscriptions are written to `spec.toml`.

`func_latency.py` uses bcc to profile function latency when running an application by attaching eBPF programs to uprobes at the entry and exit point of functions. Latency is measured in nanoseconds by default.

`run_app.py` runs the `ip_subs` application and measures how the latency of a function changes as the number of subscriptions changes. It generates subscriptions using `generate_ip_subs.py`, then runs `ip_subs` with these subscriptions and measures latency using `func_latency.py`. The latencies are written to `stats/ip_subs_latency_stats.csv` and plots on the number of subscriptions vs. latency for different stats (e.g. average, 99th percentile) can be found in the `figs` directory (which gets created by the script if it doesn't already exist). You can specify which function to profile, the number of subscriptions, and the config file path.

For example, to profile the `process_packet` function in online mode when the number of subscriptions is 64 and 256, you can run:
```
sudo -E env PATH=$PATH LD_LIBRARY_PATH=$LD_LIBRARY_PATH python3 tests/perf/run_app.py -n 64,256 -f process_packet -c ./configs/online.toml
```
Note that you must use `sudo` since bcc requires root privileges to attach eBPF programs to uprobes.

### Rust Inlining
`func_latency.py` looks for a function in an application's binary to determine where to attach uprobes. The Rust compiler may inline function names, which can prevent the function from being found in the binary. You can add a `#[inline(never)]` tag to a function to prevent it from being inlined.
