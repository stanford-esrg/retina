# Work Dispatching

An introductory example that dispatches TLS and DNS transaction metric logs to worker threads using two different approaches:

- **dedicated.rs**: Separate worker threads for TLS and DNS processing
- **shared.rs**: Single worker thread pool handling both TLS and DNS processing

Both examples process the same network events but use different thread management strategies.

## Performance

### Baseline Performance
With the default configuration provided, testing on Stanford University network achieved **zero subscription loss** running at **135Gbps of traffic for 3 minutes**.

### Work Dispatching vs. Basic Callback
Testing with computationally intensive workloads (10 million cycles per callback) demonstrates the advantage of work dispatching for CPU-bound processing:

**Configuration** (8 total cores)  
- **Work dispatching**: 4 RX cores + 4 processing cores  
- **Basic callback**: All 8 RX cores (no separate processing)  

**Results** (5-minute test, 105 Gbps average traffic, 90–120 Gbps range)  
- **Work dispatching**: &lt;1% packet loss, **0% subscription loss**  
- **Basic callback**: 5–15% packet loss (9.78% average)  

## Configuration

The worker threads and message passing setup are designed to be configurable based on your system requirements.

### Dedicated Worker Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--config` | ./configs/offline.toml | Mode to run retina in (offline or online) |
| `--tls-worker-cores` | 36,37 | CPU cores dedicated to TLS processing |
| `--dns-worker-cores` | 38,39 | CPU cores dedicated to DNS processing |
| `--tls-batch-size` | 16 | Batch size for TLS event processing |
| `--dns-batch-size` | 16 | Batch size for DNS event processing |
| `--tls-channel-size` | 32768 | Channel buffer size for TLS events |
| `--dns-channel-size` | 32768 | Channel buffer size for DNS events |
| `--channel-mode` | per-core | Are channels sharded by RX core? |
| `--flush-channels` | None | If provided, directory to flush content of channels at the end of the program.  |
| `--show-stats` | false | Display performance statistics |
| `--show-args` | false | Display command-line arguments |

### Shared Worker Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--config` | ./configs/offline.toml | Mode to run retina in (offline or online) |
| `--worker-cores` | 36,37,38,39 | CPU cores for shared worker pool |
| `--batch-size` | 16 | Batch size for shared processing |
| `--tls-channel-size` | 32768 | Channel buffer size for TLS events |
| `--dns-channel-size` | 32768 | Channel buffer size for DNS events |
| `--channel-mode` | per-core | Are channels sharded by RX core? |
| `--flush-channels` | None | If provided, directory to flush content of channels at the end of the program. |
| `--show-stats` | false | Display performance statistics |
| `--show-args` | false | Display command-line arguments |

## Memory Considerations

**Important:** Message-passing channel size must be configured according to your use case and system constraints.

Total memory required = `(Queue Size) × (Number of Queues) × (Size of Event)`

Due to the bursty nature of network traffic, channel sizes are typically set high to handle traffic spikes without dropping events.

## Getting Started

1. Choose your approach based on your use case:
   - Use **dedicated.rs** when you need specialized processing with separate thread pools
   - Use **shared.rs** for simpler setup with unified processing

2. Configure worker cores and batch sizes according to your system capacity

3. Monitor memory usage and adjust channel sizes as needed for your traffic patterns