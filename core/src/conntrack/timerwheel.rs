use crate::conntrack::{Conn, ConnId};
use crate::subscription::{Subscription, Trackable};

use crossbeam_channel::{tick, Receiver};
use hashlink::linked_hash_map::LinkedHashMap;
use hashlink::linked_hash_map::RawEntryMut;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Tracks inactive connection expiration.
pub(super) struct TimerWheel {
    /// Period to check for inactive connections (in milliseconds).
    period: usize,
    /// Start time of the `TimerWheel`.
    start_ts: Instant,
    /// Timeout ticker, fires every `period` milliseconds.
    ticker: Receiver<Instant>,
    /// Index of the next bucket to expire.
    next_bucket: usize,
    /// List of timers.
    timers: Vec<VecDeque<ConnId>>,
}

impl TimerWheel {
    /// Creates a new `TimerWheel` with a maximum timeout of `max_timeout` and a timeout check
    /// period of `timeout_resolution`.
    pub(super) fn new(max_timeout: usize, timeout_resolution: usize) -> Self {
        if timeout_resolution > max_timeout {
            panic!("Timeout check period must be smaller than maximum inactivity timeout")
        }
        let start_ts = Instant::now();
        let ticker = tick(Duration::from_millis(timeout_resolution as u64));
        TimerWheel {
            period: timeout_resolution,
            start_ts,
            ticker,
            next_bucket: 0,
            timers: vec![VecDeque::new(); max_timeout / timeout_resolution],
        }
    }

    /// Insert a new connection ID into the timerwheel.
    #[inline]
    pub(super) fn insert(
        &mut self,
        conn_id: &ConnId,
        last_seen_ts: Instant,
        inactivity_window: usize,
    ) {
        let current_time = (last_seen_ts - self.start_ts).as_millis() as usize;
        let timer_index = ((current_time + inactivity_window) / self.period) % self.timers.len();
        log::debug!("Inserting into index: {}, {:?}", timer_index, current_time);
        self.timers[timer_index].push_back(conn_id.to_owned());
    }

    /// Checks for and remove inactive connections.
    #[inline]
    pub(super) fn check_inactive<T: Trackable>(
        &mut self,
        table: &mut LinkedHashMap<ConnId, Conn<T>>,
        subscription: &Subscription<T::Subscribed>,
    ) {
        let table_len = table.len();
        if let Ok(now) = self.ticker.try_recv() {
            let nb_removed = self.remove_inactive(now, table, subscription);
            log::debug!(
                "expired: {} ({})",
                nb_removed,
                nb_removed as f64 / table_len as f64
            );
            log::debug!("new table size: {}", table.len());
        }
    }

    /// Removes connections that have been inactive for at least their inactivity window time
    /// period.
    ///
    /// Returns the number of connections removed.
    #[inline]
    pub(super) fn remove_inactive<T: Trackable>(
        &mut self,
        now: Instant,
        table: &mut LinkedHashMap<ConnId, Conn<T>>,
        subscription: &Subscription<T::Subscribed>,
    ) -> usize {
        let period = self.period;
        let nb_buckets = self.timers.len();
        let mut not_expired: Vec<(usize, ConnId)> = vec![];
        let check_time = (now - self.start_ts).as_millis() as usize / period * period;

        let mut cnt_exp = 0;
        let last_expire_bucket = check_time / period;
        log::debug!(
            "check time: {}, next: {}, last: {}",
            check_time,
            self.next_bucket,
            last_expire_bucket
        );

        for expire_bucket in self.next_bucket..last_expire_bucket {
            log::debug!(
                "bucket: {}, index: {}",
                expire_bucket,
                expire_bucket % nb_buckets
            );
            let list = &mut self.timers[expire_bucket % nb_buckets];

            for conn_id in list.drain(..) {
                if let RawEntryMut::Occupied(mut occupied) =
                    table.raw_entry_mut().from_key(&conn_id)
                {
                    let conn = occupied.get_mut();
                    let last_seen_time = (conn.last_seen_ts - self.start_ts).as_millis() as usize;
                    log::debug!("Last seen time: {}", last_seen_time);
                    let expire_time = last_seen_time + conn.inactivity_window;
                    if expire_time < check_time {
                        cnt_exp += 1;
                        conn.terminate(subscription);
                        occupied.remove();
                    } else {
                        let timer_index = (expire_time / period) % nb_buckets;
                        not_expired.push((timer_index, conn_id));
                    }
                }
            }
            for (timer_index, conn_id) in not_expired.drain(..) {
                self.timers[timer_index].push_back(conn_id);
            }
        }
        self.next_bucket = last_expire_bucket;
        cnt_exp
    }
}
