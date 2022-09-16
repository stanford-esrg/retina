use anyhow::{bail, Result};
use csv::Writer;
use hdrhistogram::Histogram;
use indexmap::IndexMap;
use prettytable::{format, Cell, Row, Table};
use serde::Serialize;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref STATS: Vec<&'static str> =  vec!["name", "cnt", "rec", "avg", "min", "p05", "p25", "p50", "p75", "p95", "p99", "p999", "max"];
}

#[derive(Debug)]
pub(crate) struct Timers(IndexMap<String, Mutex<CycleTimer>>);

impl Timers {
    pub(crate) fn new() -> Self {
        #[allow(dead_code)]
        fn init_hist(timers: &mut IndexMap<String, Mutex<CycleTimer>>, name: &str) {
            let timer = Mutex::new(CycleTimer::new_hist().unwrap());
            timers.insert(name.to_string(), timer);
        }
        #[allow(dead_code)]
        fn init_vec(timers: &mut IndexMap<String, Mutex<CycleTimer>>, name: &str) {
            let timer = Mutex::new(CycleTimer::new_vec().unwrap());
            timers.insert(name.to_string(), timer);
        }
        let mut timers = IndexMap::new();
        init_hist(&mut timers, "process");
        init_hist(&mut timers, "packet_filter");
        init_hist(&mut timers, "conn_track");
        init_hist(&mut timers, "reassembly");
        init_hist(&mut timers, "flush");
        init_hist(&mut timers, "applayer_parse");
        init_hist(&mut timers, "stream_filter");
        init_hist(&mut timers, "builder");
        init_hist(&mut timers, "callback");
        init_hist(&mut timers, "remove_inactive");
        Timers(timers)
    }

    pub(crate) fn record(&self, which: &str, value: u64, sample: u64) {
        if let Some(timer) = self.0.get(which) {
            timer
                .lock()
                .unwrap()
                .record(value, sample)
                .unwrap_or_else(|_| panic!("Failed to record {} in {}", value, which));
        } else {
            log::error!("No cycle timer found for: {}", which);
        }
    }

    pub(crate) fn display_stats(&self) {
        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
        let title = STATS.iter().map(|n| Cell::new(n)).collect::<Vec<_>>();
        table.set_titles(Row::new(title));

        for (name, timer) in self.0.iter() {
            let timer = &*timer.lock().unwrap();
            let mut stats = vec![name.to_owned()];
            stats.extend(timer.stats());

            let cells = stats.iter().map(|s| Cell::new(s)).collect();
            table.add_row(Row::new(cells));
        }
        table.printstd();
    }

    pub(crate) fn dump_stats(&self) {
        let hists = HistDumper::from(self);
        let csv_fname = Path::new("cycle_hist.csv").to_path_buf();
        hists
            .dump_csv(csv_fname)
            .expect("Unable to dump to cycle hist data");

        let vecs = VecDumper::from(self);
        let json_fname = Path::new("cycle_vec.json").to_path_buf();
        vecs.dump_json(json_fname)
            .expect("Unable to dump to cycle vec data");
    }
}

#[derive(Debug)]
struct HistDumper(IndexMap<String, Vec<String>>);

impl HistDumper {
    fn dump_csv(&self, path: PathBuf) -> Result<()> {
        let mut wtr = Writer::from_path(&path)?;
        wtr.write_record(STATS.iter())?;
        for (name, stats) in self.0.iter() {
            wtr.write_field(name)?;
            wtr.write_record(stats)?;
        }
        wtr.flush()?;
        Ok(())
    }
}

impl From<&Timers> for HistDumper {
    fn from(timers: &Timers) -> Self {
        let mut map = IndexMap::new();
        for (name, timer) in timers.0.iter() {
            let timer = &*timer.lock().unwrap();
            if let CycleTimer::Histogram(_h) = timer {
                map.insert(name.clone(), timer.stats());
            }
        }
        HistDumper(map)
    }
}

#[derive(Debug, Serialize)]
struct VecDumper(HashMap<String, Vec<u64>>);

impl VecDumper {
    fn dump_json(&self, path: PathBuf) -> Result<()> {
        let file = std::fs::File::create(path)?;
        serde_json::to_writer(&file, self)?;
        Ok(())
    }
}

impl From<&Timers> for VecDumper {
    fn from(timers: &Timers) -> Self {
        let mut map = HashMap::new();
        for (name, timer) in timers.0.iter() {
            if let CycleTimer::Vector(v) = &*timer.lock().unwrap() {
                map.insert(name.clone(), v.data.to_vec());
            }
        }
        VecDumper(map)
    }
}

#[derive(Debug)]
pub(crate) struct CycleHistogram {
    data: Histogram<u64>,
    cnt: u64,
}

#[derive(Debug)]
pub(crate) struct CycleVector {
    data: Vec<u64>,
    cnt: u64,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum CycleTimer {
    Histogram(CycleHistogram),
    Vector(CycleVector),
}

impl CycleTimer {
    pub(crate) fn new_hist() -> Result<Self> {
        Ok(CycleTimer::Histogram(CycleHistogram {
            data: Histogram::new(3)?,
            cnt: 0,
        }))
    }

    pub(crate) fn new_vec() -> Result<Self> {
        Ok(CycleTimer::Vector(CycleVector {
            data: Vec::new(),
            cnt: 0,
        }))
    }

    /// Record `value` into histogram
    pub(crate) fn record(&mut self, value: u64, sample: u64) -> Result<()> {
        match self {
            CycleTimer::Histogram(h) => {
                if h.cnt % sample == 0 {
                    h.data.record(value)?;
                }
                h.cnt += 1;
                Ok(())
            }
            CycleTimer::Vector(v) => {
                if v.cnt % sample == 0 {
                    v.data.push(value);
                }
                v.cnt += 1;
                Ok(())
            }
        }
    }

    /// Returns name, cnt, avg, min, max, and percentiles in a Vec<String>
    pub(crate) fn stats(&self) -> Vec<String> {
        match self {
            CycleTimer::Histogram(h) => {
                vec![
                    format!("{}", h.cnt),
                    format!("{}", h.data.len()),
                    format!("{:.3}", h.data.mean()),
                    format!("{}", h.data.min()),
                    format!("{}", h.data.value_at_quantile(0.05)),
                    format!("{}", h.data.value_at_quantile(0.25)),
                    format!("{}", h.data.value_at_quantile(0.5)),
                    format!("{}", h.data.value_at_quantile(0.75)),
                    format!("{}", h.data.value_at_quantile(0.95)),
                    format!("{}", h.data.value_at_quantile(0.99)),
                    format!("{}", h.data.value_at_quantile(0.999)),
                    format!("{}", h.data.max()),
                ]
            }
            CycleTimer::Vector(v) => {
                vec![
                    format!("{}", v.cnt),
                    format!("{}", v.data.len()),
                    format!("{:.3}", mean(&v.data)),
                    format!("{}", v.data.iter().min().unwrap_or(&0)),
                    String::new(), // TODO
                    String::new(),
                    format!("{}", median(&v.data).unwrap_or(0)),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    format!("{}", v.data.iter().max().unwrap_or(&0)),
                ]
            }
        }
    }
}

fn mean(v: &[u64]) -> f64 {
    let sum: u64 = v.iter().sum();
    sum as f64 / v.len() as f64
}

fn median(v: &[u64]) -> Result<u64> {
    if v.is_empty() {
        bail!("Empty vector");
    }
    let mut s = v.to_vec();
    s.sort();
    let mid = s.len() / 2;
    if s.len() % 2 == 0 {
        Ok(mean(&[s[mid - 1], s[mid]]) as u64)
    } else {
        Ok(s[mid])
    }
}
