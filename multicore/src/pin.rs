use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::Pid;
use nix::Error;

// Pin current thread to specific CPU core 
pub fn pin_thread_to_core(core: u32) -> Result<(), Error> {
    let mut cpu_set = CpuSet::new();
    cpu_set.set(core as usize)?;
    sched_setaffinity(Pid::from_raw(0), &cpu_set)?;
    Ok(())
}
