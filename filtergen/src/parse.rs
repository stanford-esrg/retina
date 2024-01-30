use retina_core::filter::*;
use std::collections::{HashSet, HashMap};
use std::str::FromStr;

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SubscriptionSpec {
    pub filter: String,
    pub datatype: String, 
    pub callback: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ConfigRaw {
    #[serde(default = "default_filter")]
    packet_continue: HashMap<String, Vec<String>>,

    #[serde(default = "default_filter")]
    packet_filter: HashMap<String, Vec<String>>,
    #[serde(default = "default_filter")]
    connection_filter: HashMap<String, Vec<String>>,
    #[serde(default = "default_filter")]
    session_filter: HashMap<String, Vec<String>>,

    #[serde(default = "default_deliver")]
    packet_deliver: Vec<SubscriptionSpec>,
    #[serde(default = "default_deliver")]
    connection_deliver: Vec<SubscriptionSpec>,
    #[serde(default = "default_deliver")]
    session_deliver:  Vec<SubscriptionSpec>,

    #[serde(default = "default_subscribed")]
    subscriptions: Vec<String>
}

impl ConfigRaw {
    pub(crate) fn packet_continue(&mut self) -> HashMap<Packet, Vec<String>> {
        let pkt_continue = std::mem::take(&mut self.packet_continue);
        pkt_continue
            .into_iter()
            .map( |(actions, filters)| {
                (
                    Packet::from_str(&actions)
                                    .expect(&format!("Cannot parse {} to Packet (action)", &actions)),
                    filters
                )
            } ).collect()
    }

    fn filter(inp: HashMap<String, Vec<String>>) -> HashMap<Actions, Vec<String>> {
        inp.into_iter()
            .map( |(actions, filters)| {
                (   
                    Actions::from_str(&actions).expect(&format!("Cannot parse {} to Actions", &actions)),
                    filters
                )
            } ).collect()
    }

    fn packet_filter(&mut self) -> HashMap<Actions, Vec<String>> {
        ConfigRaw::filter(std::mem::take(&mut self.packet_filter))
    }

    fn connection_filter(&mut self) -> HashMap<Actions, Vec<String>> {
        ConfigRaw::filter(std::mem::take(&mut self.connection_filter))
    }

    fn session_filter(&mut self) -> HashMap<Actions, Vec<String>> {
        ConfigRaw::filter(std::mem::take(&mut self.session_filter))
    }

    fn packet_deliver(&mut self) -> Vec<SubscriptionSpec> {
        std::mem::take(&mut self.packet_deliver)
    }

    fn connection_deliver(&mut self) -> Vec<SubscriptionSpec> {
        std::mem::take(&mut self.connection_deliver)
    }

    fn session_deliver(&mut self) -> Vec<SubscriptionSpec> {
        std::mem::take(&mut self.session_deliver)
    }

}

fn default_filter() -> HashMap<String, Vec<String>> {
    HashMap::new()
}

fn default_deliver() -> Vec<SubscriptionSpec> {
    Vec::new()
}

fn default_subscribed() -> Vec<String> {
    vec![]
}

pub(crate) struct ConfigBuilder {

    pub(crate) packet_continue: HashMap<Packet, Vec<String>>,

    pub(crate) packet_filter: HashMap<Actions, Vec<String>>,
    pub(crate) connection_filter: HashMap<Actions, Vec<String>>,
    pub(crate) session_filter: HashMap<Actions, Vec<String>>,

    pub(crate) packet_deliver: HashMap<usize, String>, 
    pub(crate) connection_deliver: HashMap<usize, String>, 
    pub(crate) session_deliver: HashMap<usize, String>, 

    pub(crate) datatypes: HashSet<String>,

    count: usize,
    raw: ConfigRaw,

    // subscribable types
}

impl ConfigBuilder {

    fn new(mut config: ConfigRaw) -> Self {
        Self {
            packet_continue: config.packet_continue(),
            packet_filter: config.packet_filter(),
            connection_filter: config.connection_filter(),
            session_filter: config.session_filter(),

            packet_deliver: HashMap::new(),
            connection_deliver: HashMap::new(),
            session_deliver: HashMap::new(),

            datatypes: HashSet::new(),

            count: 0,
            raw: config,
        }
    }

    pub(crate) fn from_file(filepath_in: &str) -> Self {

        let config_str = std::fs::read_to_string(filepath_in)
                              .expect(&format!("ERROR: File read failed {}", filepath_in));

        let config_raw: ConfigRaw = toml::from_str(&config_str)
                                        .expect(&format!("ERROR: Config file invalid {}", filepath_in));

        let mut config = ConfigBuilder::new(config_raw);

        config.build();
        config
    }

    fn build(&mut self) {
        // Deliver methods
        let packet_deliver_raw = self.raw.packet_deliver();
        self.packet_deliver = self.get_deliver(packet_deliver_raw);
        let connection_deliver_raw = self.raw.connection_deliver();
        self.connection_deliver = self.get_deliver(connection_deliver_raw);
        let session_deliver_raw = self.raw.session_deliver();
        self.session_deliver = self.get_deliver(session_deliver_raw);
        
        // Types
        
    }

    fn get_deliver(&mut self, inp: Vec<SubscriptionSpec>) -> HashMap<usize, String> {
        let mut out = HashMap::new();

        let mut deliver = crate::utils::DELIVER.lock().unwrap();

        for spec in inp {
            out.insert(self.count, spec.filter.clone());
            self.datatypes.insert(spec.datatype.clone());
            deliver.insert(self.count, spec);
            self.count += 1;
        }
        out
    }
   
}