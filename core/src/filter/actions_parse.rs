use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use super::actions::*;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SubscriptionSpec {
    pub filter: String,
    pub datatype: String, 
    pub callback: String,
}

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
