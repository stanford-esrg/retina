use retina_core::filter::{SubscriptionSpec, datatypes::Streaming, Level};
use retina_datatypes::DATATYPES;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

// Specify subscription specs from a file
#[derive(Serialize, Deserialize)]
pub(crate) struct ConfigRaw {
    pub(crate) subscriptions: Vec<SubscriptionRaw>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct SubscriptionRaw {
    pub(crate) filter: String,
    #[serde_as(as = "serde_with::OneOrMany<_>")]
    pub(crate) datatypes: Vec<String>,
    pub(crate) callback: String,
    pub(crate) streaming: Option<Streaming>,
}

#[derive(Debug, Clone)]
pub(crate) struct SubscriptionConfig {
    pub(crate) subscriptions: Vec<SubscriptionSpec>,
}

impl SubscriptionConfig {

    pub(crate) fn from_raw(config: &ConfigRaw) -> Self {
        let mut subscriptions = vec![];
        for s in &config.subscriptions {
            assert!(!s.datatypes.is_empty());
            let mut spec = SubscriptionSpec::new(s.filter.clone(), s.callback.clone());
            if let Some(streaming) = s.streaming {
                spec.level = Level::Streaming(streaming);
            }
            for datatype_str in &s.datatypes {
                Self::validate_datatype(datatype_str.as_str());
                let datatype = DATATYPES.get(datatype_str.as_str()).unwrap().clone();
                spec.add_datatype(datatype);
            }
            spec.validate_spec();
            subscriptions.push(spec);
        }
        Self { subscriptions }
    }

    pub(crate) fn from_file(filepath_in: &str) -> Self {
        let config_str = std::fs::read_to_string(filepath_in)
            .unwrap_or_else(|err| panic!("ERROR: File read failed {}: {:?}", filepath_in, err));

        let config: ConfigRaw = toml::from_str(&config_str)
            .unwrap_or_else(|err| panic!("ERROR: Config file invalid {}: {:?}", filepath_in, err));
        Self::from_raw(&config)
    }

    fn validate_datatype(datatype: &str) {
        if !DATATYPES.contains_key(datatype) {
            let valid_types: Vec<&str> = DATATYPES.keys().copied().collect();
            panic!(
                "Invalid datatype: {};\nDid you mean:\n {}",
                datatype,
                valid_types.join(",\n")
            );
        }
    }
}
