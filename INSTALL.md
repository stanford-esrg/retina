# Installation

These installation instructions are for running Retina on a bare metal Ubuntu server with a Mellanox server NIC, and have been tested on the following platforms:

| CPU                   | OS            | NIC                                      |
| --------------------- | ------------- | ---------------------------------------- |
| Intel Xeon Gold 6154R | Ubuntu 18.04  | Mellanox ConnectX-5 100G MCX516A-CCAT    |
| Intel Xeon Gold 6248R | Ubuntu 20.04  | Mellanox ConnectX-5 100G MCX516A-CCAT    |
| Intel Xeon Silver 4314| Ubuntu 20.04  | Mellanox ConnectX-5 100G MCX516A-CCA_Ax  |
| AMD EPYC 7452 32-Core | Ubuntu 20.04  | Mellanox ConnectX-5 Ex Dual Port 100 GbE |

We have also tested Retina in offline mode on both x86 and ARM-based [Ubuntu VMs](#testing-retina-offline-on-a-vm).

Retina can run on other platforms as well, detail to come.

## Hardware Recommendations
Retina should work on any commodity x86 server, but the more cores and memory the better. For real-time operation in 100G network environments, we recommend at least 64GB of memory and a 100G Mellanox ConnectX-5 or similar, but any DPDK-compatible NIC should work.

## Installing Dependencies

On Ubuntu, install dependencies with the following command:
```sh
sudo apt install build-essential meson pkg-config libnuma-dev python3-pyelftools libpcap-dev libclang-dev python3-pip
```

## Building and Installing DPDK
Retina currently requires [**DPDK 20.11 or 21.08 or 23.11 or 24.11**](https://core.dpdk.org/download/). Note that 20.11 LTS has a bug that causes inaccurate packet drop metrics on some NICs.

### System Configuration
To get high performance from DPDK applications, we recommend the following system configuration steps. More details from the DPDK docs can be found [here](https://doc.dpdk.org/guides/linux_gsg/nic_perf_intel_platform.html).


#### Allocate 1GB hugepages
Edit the GRUB boot settings `/etc/default/grub` to reserve 1GB hugepages and isolate CPU cores that will be used for Retina. For example, to reserve 64 1GB hugepages and isolate cores 1-32:
```
GRUB_CMDLINE_LINUX="default_hugepagesz=1G hugepagesz=1G hugepages=64 iommu=pt intel_iommu=on isolcpus=1-32"
```

Update the GRUB settings and reboot:
```sh
sudo update-grub
sudo reboot now
```

Mount hugepages to make them available for DPDK use:
```sh
sudo mkdir /mnt/huge
sudo mount -t hugetlbfs pagesize=1GB /mnt/huge
```

### Install MLX5 PMD Dependencies
If using a Mellanox ConnectX-5 (recommended), you will need to separately install  some dependencies that do not come with DPDK ([details](https://doc.dpdk.org/guides/nics/mlx5.html)). This can be done by installing Mellanox OFED. DPDK recommends MLNX_OFED 5.4-1.0.3.0 in combination with DPDK 21.08.

Download the MLNX_OFED from the [MLNX_OFED downloads page](https://www.mellanox.com/products/infiniband-drivers/linux/mlnx_ofed), then run the following commands to install:
```sh
tar xvf MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64.tgz
cd MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64/
sudo ./mlnxofedinstall --dpdk --upstream-libs --with-mft --with-kernel-mft
ibv_devinfo    # verify firmware is correct, set to Ethernet
sudo /etc/init.d/openibd restart
```

This may update the firmware on your NIC, a reboot should complete the update if necessary.

### Install DPDK from source
We recommend a local DPDK install from source. Download version 24.11 (or desired version) from the [DPDK downloads page](http://core.dpdk.org/download/):
```sh
wget http://fast.dpdk.org/rel/dpdk-24.11.tar.xz
tar xJf dpdk-24.11.tar.xz
```

Set environment variables (For changing the version, set `DPDK_VERSION` properly):
```sh
export DPDK_PATH=/path/to/dpdk/dpdk-24.11
export DPDK_VERSION=24.11
export LD_LIBRARY_PATH=$DPDK_PATH/lib/x86_64-linux-gnu
export PKG_CONFIG_PATH=$LD_LIBRARY_PATH/pkgconfig
```

#### Compile DPDK
From `DPDK_PATH`, run:
```sh
meson --prefix=$DPDK_PATH build
cd build
sudo ninja install
sudo ldconfig
```
More information on compiling DPDK can be found [here](https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html#).

#### Troubleshooting: Building DPDK 21.08 with Meson

Meson >= 0.60 [may fail to build](https://github.com/spdk/spdk/issues/2214) DPDK 21.08. You can insert [the fix](https://review.spdk.io/gerrit/c/spdk/dpdk/+/10044) into DPDK or build Meson < 0.60 from [source](https://github.com/mesonbuild/meson/releases). (After downloading and extracting, run `python3 setup.py build && sudo python3 setup.py install`.) 

#### (Optional) Binding network interfaces to DPDK-compatible driver
Depending on your NIC and the associated DPDK poll mode driver (PMD), you may need to bind the device/interface to a DPDK-compatible driver in order to make it work properly. **Note**: this step does *not* need to be done for the Mellanox PMD (mlx5). Details on binding and unbinding to drivers can be found [here](https://doc.dpdk.org/guides/linux_gsg/linux_drivers.html).

Example bind to a DPDK-compatible driver:
```sh
sudo modprobe vfio-pci  # Load the vfio-pci module
sudo $DPDK_PATH/usertools/dpdk-devbind.py --bind=vfio-pci <interface_name/pci_address>   # Unbinds from kernel module, binds to vfio-pci
```



## Installing Rust
```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```
More information on Rust installation can be found [here](https://www.rust-lang.org/tools/install).

## Building and Running Retina
Retina should be built and run from source. 
Clone the main git repository:

```sh
git clone git@github.com:stanford-esrg/retina.git
```

Build all applications:
```sh
cargo build --release
```

Run:
```sh
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/my_app
```

#### Troubleshooting: Bindgen

Retina uses [bindgen](https://docs.rs/bindgen/latest/bindgen/) to generate bindings to DPDK functions implemented in C.

For newer versions of DPDK, bindgen requires us to use `.clang_macro_fallback()` to access certain RSS constants. This requires clang/llvm >=13.

## Testing Retina (Offline) on a VM

We have deployed Retina in offline mode (streaming pcaps) on both ARM- and x86-based Ubuntu VMs. This can be useful for getting started, development, and functional testing. 

The main branch of Retina may specify "mlx5" as a default feature, as this is the recommended setup. Remove this in `core/Cargo.toml` if not present on the VM.  

For an x86 architecture, no other changes are needed. 

For ARM vCPU: 

- When building DPDK, add a meson [build option](https://doc.dpdk.org/guides-22.03/linux_gsg/build_dpdk.html) to configure for generic or native [SoC](https://github.com/DPDK/dpdk/blob/6f716880ee53ac1e50c9c75dc749886e3257bb8f/config/arm/meson.build#L373-L414):

```sh
meson setup configure -Dplatform=generic
```

- Let `LD_LIBRARY_PATH` point to `aarch64-linux-gnu`:
```sh
export LD_LIBRARY_PATH=$DPDK_PATH/lib/aarch64-linux-gnu
```

#### Troubleshooting: Mempool Capacity
When running applications using the provided offline config file, a mempool creation error may occur:
```sh
Error: Mempool mempool_0 creation failed
```
This can be resolved by reducing the mempool capacity in the config file.
