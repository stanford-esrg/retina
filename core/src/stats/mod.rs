use std::cell::Cell;

#[cfg(feature = "prometheus")]
mod prometheus;

#[cfg(feature = "prometheus")]
pub use prometheus::*;

thread_local! {
    pub(crate) static IGNORED_BY_PACKET_FILTER_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static IGNORED_BY_PACKET_FILTER_BYTE: Cell<u64> = const { Cell::new(0) };
    pub(crate) static DROPPED_MIDDLE_OF_CONNECTION_TCP_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static DROPPED_MIDDLE_OF_CONNECTION_TCP_BYTE: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TOTAL_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TOTAL_BYTE: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TCP_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TCP_BYTE: Cell<u64> = const { Cell::new(0) };
    pub(crate) static UDP_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static UDP_BYTE: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TCP_NEW_CONNECTIONS: Cell<u64> = const { Cell::new(0) };
    pub(crate) static UDP_NEW_CONNECTIONS: Cell<u64> = const { Cell::new(0) };
    pub(crate) static IDLE_CYCLES: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TOTAL_CYCLES: Cell<u64> = const { Cell::new(0) };

    #[cfg(feature = "prometheus")]
    pub(crate) static PROMETHEUS: std::cell::OnceCell<prometheus::PerCorePrometheusStats> = const { std::cell::OnceCell::new() };
}

pub(crate) trait StatExt: Sized {
    fn inc(&'static self) {
        self.inc_by(1);
    }
    fn inc_by(&'static self, val: u64);
}

impl StatExt for std::thread::LocalKey<Cell<u64>> {
    fn inc_by(&'static self, val: u64) {
        self.set(self.get() + val);
    }
}
