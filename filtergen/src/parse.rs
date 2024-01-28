use retina_core::filter::*;
use std::collections::HashMap;
use std::str::FromStr;

use serde::{Serialize, Deserialize};


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
    packet_deliver: HashMap<String, String>,
    #[serde(default = "default_deliver")]
    connection_deliver: HashMap<String, String>,
    #[serde(default = "default_deliver")]
    session_deliver:  HashMap<String, String>,
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

    fn deliver(inp: HashMap<String, String>) -> HashMap<usize, String> {
        inp.into_iter()
        .map( |(id, filters)| {
            (   
                usize::from_str(&id).expect(&format!("Cannot parse {} to usize", &id)),
                filters
            )
        } ).collect()
    }

    fn packet_deliver(&mut self) -> HashMap<usize, String> {
        ConfigRaw::deliver(std::mem::take(&mut self.packet_deliver))
    }

    fn connection_deliver(&mut self) -> HashMap<usize, String> {
        ConfigRaw::deliver(std::mem::take(&mut self.connection_deliver))
    }

    fn session_deliver(&mut self) -> HashMap<usize, String> {
        ConfigRaw::deliver(std::mem::take(&mut self.session_deliver))
    }

}

fn default_filter() -> HashMap<String, Vec<String>> {
    HashMap::new()
}

fn default_deliver() -> HashMap<String, String> {
    HashMap::new()
}

pub(crate) struct ConfigBuilder {
    pub(crate) packet_continue: HashMap<Packet, Vec<String>>,

    pub(crate) packet_filter: HashMap<Actions, Vec<String>>,
    pub(crate) connection_filter: HashMap<Actions, Vec<String>>,
    pub(crate) session_filter: HashMap<Actions, Vec<String>>,

    pub(crate) packet_deliver: HashMap<usize, String>, 
    pub(crate) connection_deliver: HashMap<usize, String>, 
    pub(crate) session_deliver: HashMap<usize, String>, 

    // subscribable types
}

impl ConfigBuilder {


    pub(crate) fn from_file(filepath_in: &str) -> Self {

        let config_str = std::fs::read_to_string(filepath_in)
                              .expect(&format!("ERROR: File read failed {}", filepath_in));

        let mut config: ConfigRaw = toml::from_str(&config_str)
                                    .expect(&format!("ERROR: Config file invalid {}", filepath_in));

        Self {
            packet_continue: config.packet_continue(),
            packet_filter: config.packet_filter(),
            connection_filter: config.connection_filter(),
            session_filter: config.session_filter(),
            packet_deliver: config.packet_deliver(), 
            connection_deliver: config.connection_deliver(), 
            session_deliver: config.session_deliver(), 
        }
    }
   
}