use super::StaticData;
use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::lcore::CoreId;

impl StaticData for FiveTuple {
    fn new(five_tuple: &FiveTuple, _core_id: &CoreId) -> FiveTuple {
        five_tuple.clone()
    }
}

impl StaticData for CoreId {
    fn new(_five_tuple: &FiveTuple, core_id: &CoreId) -> CoreId {
        core_id.clone()
    }
}
