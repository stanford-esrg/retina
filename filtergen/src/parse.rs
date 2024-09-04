use serde::{Serialize, Deserialize};
use retina_core::filter::DataType;
use retina_datatypes::DATATYPES;

// Specify subscription specs from a file
#[derive(Serialize, Deserialize)]
pub(crate) struct ConfigRaw {
    pub(crate) subscriptions:  Vec<SubscriptionRaw>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct SubscriptionRaw {
    pub(crate) filter: String,
    pub(crate) datatype: String,
    pub(crate) callback: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SubscriptionSpec {
    pub(crate) datatype: DataType,
    pub(crate) filter: String,
    pub(crate) callback: String,
    pub(crate) datatype_str: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SubscriptionConfig {
    pub(crate) subscriptions: Vec<SubscriptionSpec>,
}

impl SubscriptionConfig {
    pub(crate) fn from_file(filepath_in: &str) -> Self {
        let config_str = std::fs::read_to_string(filepath_in)
                              .expect(&format!("ERROR: File read failed {}", filepath_in));

        let config: ConfigRaw = toml::from_str(&config_str)
                                        .expect(&format!("ERROR: Config file invalid {}", filepath_in));

        let mut subscriptions = vec![];
        for s in config.subscriptions {
            let datatype = s.datatype.as_str();
            if !DATATYPES.contains_key(datatype) {
                let valid_types: Vec<&str> = DATATYPES.keys()
                                                    .map(|s| *s )
                                                    .collect();

                panic!("Invalid datatype: {};\nDid you mean:\n {}",
                datatype, valid_types.join(",\n"));
            }
            subscriptions.push(
                SubscriptionSpec {
                    datatype: DATATYPES.get(datatype).unwrap().clone(),
                    filter: s.filter.clone(),
                    callback: s.callback.clone(),
                    datatype_str: datatype.into(),
                }
            );
        }

        Self {
            subscriptions
        }

    }
}