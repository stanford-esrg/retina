use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::Pid;
use nix::Error;

/// Pins the current thread to a specific CPU core.
///
/// This function used the `sched_setaffinity` system call to restrict the current thread to
/// execute only on the specified CPU core.
///
/// **Note:** This does *not* prevent other threads or processes from being scheduled on the same
/// core. It only restricts where the current thread may run. To achieve true core exclusivity,
/// other threads must be restricted seperately.
///
/// # Arguments
///
/// * `core` - The CPU core number (0-indexed) to pin the thread to.
///
/// # Returns
///
/// * `Ok(())` - Thread successfully pinned to core.
/// * `Err(Error)` - System called failed (invalid core, permissions, etc.)
///
/// # Platform Support
///
/// This function is Linux-specific and uses the `nix` crate's scheduler bindings.
/// On systems without CPU affinity support, this function will return an error.

pub fn pin_thread_to_core(core: u32) -> Result<(), Error> {
    let mut cpu_set = CpuSet::new();
    cpu_set.set(core as usize)?;
    sched_setaffinity(Pid::from_raw(0), &cpu_set)?;
    Ok(())
}
