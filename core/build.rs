use bindgen::Builder;
use std::env;
use std::path::Path;
use std::process::exit;
use std::process::Command;

fn main() {
    // modified from https://github.com/deeptir18/cornflakes/blob/master/cornflakes-libos/build.rs

    println!("cargo:rerun-if-env-changed=DPDK_PATH");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/dpdk/inline.c");
    let cargo_manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let cargo_dir = Path::new(&cargo_manifest_dir);

    let out_dir_s = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir_s);
    let dpdk_path_s = env::var("DPDK_PATH").unwrap();
    let dpdk_path = Path::new(&dpdk_path_s);
    let pkg_config_path = dpdk_path.join("lib/x86_64-linux-gnu/pkgconfig");
    let cflags_bytes = Command::new("pkg-config")
        .env("PKG_CONFIG_PATH", &pkg_config_path)
        .args(["--cflags", "libdpdk"])
        .output()
        .unwrap_or_else(|e| panic!("Failed pkg-config cflags: {:?}", e))
        .stdout;
    let cflags = String::from_utf8(cflags_bytes).unwrap();

    let mut header_locations = vec![];

    for flag in cflags.split(' ') {
        if let Some(stripped) = flag.strip_prefix("-I") {
            let header_location = stripped.trim();
            header_locations.push(header_location);
        }
    }

    let ldflags_bytes = Command::new("pkg-config")
        .env("PKG_CONFIG_PATH", &pkg_config_path)
        .args(["--libs", "libdpdk"])
        .output()
        .unwrap_or_else(|e| panic!("Failed pkg-config ldflags: {:?}", e))
        .stdout;

    if ldflags_bytes.is_empty() {
        println!("Could not get DPDK's LDFLAGS. Is DPDK_PATH set correctly?");
        exit(1);
    };

    let ldflags = String::from_utf8(ldflags_bytes).unwrap();

    let mut library_location = None;
    let mut lib_names = vec![];

    for flag in ldflags.split(' ') {
        if let Some(stripped) = flag.strip_prefix("-L") {
            library_location = Some(stripped);
        } else if let Some(stripped) = flag.strip_prefix("-l") {
            lib_names.push(stripped);
        }
    }

    // Link in `librte_net_mlx5` and its dependencies if desired.
    #[cfg(feature = "mlx5")]
    {
        lib_names.extend(&[
            "rte_net_mlx5",
            "rte_bus_pci",
            "rte_bus_vdev",
            "rte_common_mlx5",
        ]);
    }

    // Step 1: Now that we've compiled and installed DPDK, point cargo to the libraries.
    println!(
        "cargo:rustc-link-search=native={}",
        library_location.unwrap()
    );
    for lib_name in &lib_names {
        println!("cargo:rustc-link-lib={}", lib_name);
    }

    // Step 2: Generate bindings for the DPDK headers.
    let mut builder = Builder::default();
    for header_location in &header_locations {
        builder = builder.clang_arg(&format!("-I{}", header_location));
    }

    let headers_file = Path::new(&cargo_dir)
        .join("src")
        .join("dpdk")
        .join("dpdk_headers.h");
    let bindings = builder
        .header(headers_file.to_str().unwrap())
        // mark as opaque per bindgen bug on packed+aligned structs:
        // https://github.com/rust-lang/rust-bindgen/issues/1538
        .opaque_type(r"rte_arp_ipv4|rte_arp_hdr")
        .opaque_type(r"(rte_ecpri|rte_l2tpv2)_.*")
        .allowlist_type(r"(rte|eth|pcap)_.*")
        .allowlist_function(r"(_rte|rte|eth|numa|pcap)_.*")
        .allowlist_var(r"(RTE|DEV|ETH|MEMPOOL|PKT|rte)_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate_comments(false)
        .generate()
        .unwrap_or_else(|e| panic!("Failed to generate bindings: {:?}", e));
    let bindings_out = out_dir.join("dpdk.rs");
    bindings
        .write_to_file(bindings_out)
        .expect("Failed to write bindings");

    // Step 3: Compile a stub file so Rust can access `inline` functions in the headers
    // that aren't compiled into the libraries.
    let mut builder = cc::Build::new();
    builder.opt_level(3);
    builder.pic(true);
    builder.flag("-march=native");

    let inlined_file = Path::new(&cargo_dir)
        .join("src")
        .join("dpdk")
        .join("inlined.c");
    builder.file(inlined_file.to_str().unwrap());
    for header_location in &header_locations {
        builder.include(header_location);
    }
    builder.compile("inlined");
}
