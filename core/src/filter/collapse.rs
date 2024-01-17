#[derive(Debug, Clone)]
pub struct SubscriptionLevel {
    subscription_level: Terminate,
    parse_session_proto: bool,
    parse_session_data: bool,
}

impl PartialEq for SubscriptionLevel {
    fn eq(&self, other: &Self) -> bool {
        matches!(self.subscription_level, other.subscription_level) && 
                matches!(self.filter_level, other.filter_level)
    }
}

impl SubscriptionLevel {
    fn new(subscription_level: Terminate) -> Self {
        Self {
            subscription_level,
            parse_session_proto: false,
            parse_session_data: false,
        }
    }

    fn filter_parse_protocol(&mut self) {
        self.parse_session_proto = true;
    }

    fn filter_parse_session(&mut self) {
        self.parse_session_proto = true;
        self.parse_session_data = true;
    }
    
    fn packet_action(&self, terminal: bool) -> ActionData {
        let mut actions = ActionData::new();
        match self.subscription_level {
            Level::Packet => {
                if terminal {
                    actions.set(ActionData::FrameDeliver);
                } else {
                    actions.set(ActionData::FrameTrack);
                }
            },
            Level::Connection => {
                // Packet filter stage applied to a tracked connection
                actions.set(ActionData::ConnDataTrack);
                if self.parse_session_proto {
                    actions.set(ActionData::ConnParse);
                }
            },
            Level::Session => {
                actions.set(ActionData::ConnParse);
            }
        }
        if !terminal {
            actions.set(Actions::ConnFilter);
        }
        return actions;
    }

    fn conn_action(&self, terminal: bool) {
        let mut actions = ActionData::new();
        match self.subscription_level {
            Level::Packet => {
                if terminal {
                    actions.set(ActionData::FrameDrain);
                } else {
                    actions.set(ActionData::FrameTrack);
                }
            },
            Level::Connection => {
                // Packet filter stage applied to a tracked connection
                actions.set(ActionData::ConnDataTrack);
                if self.parse_session_data {
                    actions.set(ActionData::SessionParse);
                }
            },
            Level::Session => {
                actions.set(ActionData::SessionParse);
            }
        }
        if !terminal {
            actions.set(Actions::ConnFilter);
        }
        return actions;
    }

    fn session_action(&self) {
        let mut actions = ActionData::new();
        match self.subscription_level {
            Level::Packet => {
                actions.set(ActionData::FrameDrain);
            },
            Level::Connection => {
                actions.set(ActionData::ConnDataTrack);
            },
            Level::Session => {
                actions.set(ActionData::SessionDeliver);
            }
        }
        if !terminal {
            actions.set(Actions::ConnFilter);
        }
        return actions;
    }
}