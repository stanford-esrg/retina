use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::Pid;
use nix::Error;

pub fn pin_thread_to_core(core: usize) -> Result<(), Error> {
    let mut cpu_set = CpuSet::new();
    cpu_set.set(core)?;
    sched_setaffinity(Pid::from_raw(0), &cpu_set)?;
    Ok(())
}
