use retina_core::filter::*;
use std::collections::{HashSet, HashMap};

pub(crate) struct ConfigBuilder {

    pub(crate) packet_continue: HashMap<Actions, Vec<String>>,

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