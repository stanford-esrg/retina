use std::collections::{HashSet, HashMap};
use serde::{Serialize, Deserialize};
use retina_core::filter::actions::Actions;
use std::str::FromStr;
use super::utils::SubscriptionSpec;

// TEMPORARY - FOR TESTING PURPOSES
#[derive(Serialize, Deserialize)]
pub struct ConfigRaw {
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
    pub fn packet_continue(&mut self) -> HashMap<Actions, Vec<String>> {
        let pkt_continue = std::mem::take(&mut self.packet_continue);
        pkt_continue
            .into_iter()
            .map( |(actions, filters)| {
                (
                    Actions::from_str(&actions)
                                    .expect(&format!("Cannot parse {} to Packet (action)", &actions)),
                    filters
                )
            } ).collect()
    }

    pub fn filter(inp: HashMap<String, Vec<String>>) -> HashMap<Actions, Vec<String>> {
        inp.into_iter()
            .map( |(actions, filters)| {
                (   
                    Actions::from_str(&actions).expect(&format!("Cannot parse {} to Actions", &actions)),
                    filters
                )
            } ).collect()
    }

    pub fn packet_filter(&mut self) -> HashMap<Actions, Vec<String>> {
        ConfigRaw::filter(std::mem::take(&mut self.packet_filter))
    }

    pub fn connection_filter(&mut self) -> HashMap<Actions, Vec<String>> {
        ConfigRaw::filter(std::mem::take(&mut self.connection_filter))
    }

    pub fn session_filter(&mut self) -> HashMap<Actions, Vec<String>> {
        ConfigRaw::filter(std::mem::take(&mut self.session_filter))
    }

    pub fn packet_deliver(&mut self) -> Vec<SubscriptionSpec> {
        std::mem::take(&mut self.packet_deliver)
    }

    pub fn connection_deliver(&mut self) -> Vec<SubscriptionSpec> {
        std::mem::take(&mut self.connection_deliver)
    }

    pub fn session_deliver(&mut self) -> Vec<SubscriptionSpec> {
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

    pub(crate) packet_continue: HashMap<Actions, Vec<String>>,

    pub(crate) packet_filter: HashMap<Actions, Vec<String>>,
    pub(crate) connection_filter: HashMap<Actions, Vec<String>>,
    pub(crate) session_filter: HashMap<Actions, Vec<String>>,

    pub(crate) packet_deliver: HashMap<usize, SubscriptionSpec>, 
    pub(crate) connection_deliver: HashMap<usize, SubscriptionSpec>, 
    pub(crate) session_deliver: HashMap<usize, SubscriptionSpec>, 

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
        
    }

    fn get_deliver(&mut self, inp: Vec<SubscriptionSpec>) -> HashMap<usize, SubscriptionSpec> {
        let mut out = HashMap::new();

        let mut deliver = crate::utils::DELIVER.lock().unwrap();

        for spec in inp {
            // Assign each subscription a ID
            out.insert(self.count, spec.clone());
            // Track the datatypes
            self.datatypes.insert(spec.datatype.clone());
            // Track for future delivery filter
            deliver.insert(self.count, spec);
            // Track number of subscriptions
            self.count += 1;
        }
        out
    }
   
}