# How to use the multiple subscription interface

The current interface reads from (1) a user-defined input file to build multiple subscriptions in the framework, and (2) a `main.rs` file to execute the user program (define callbacks and invoke the runtime). 

The `main` file is the program built by `cargo` (same as current Retina interface). The subscription builder **must be specified in the `IN_FILE` environment variable** prior to compiling. 

## Defining subscriptions

Each subscription is defined as a (data type to be delivered, filter to be applied, callback) tuple. 

The high-level format of a configuration file, right now, is a yaml with the following required keys: 
- `subscribed`: a map that defines subscribed data types.
- `filters`: a map that defines filters.
- `callbacks`: a map that defines the names of the callbacks. 
- `num_subscriptions`: the total number of subscriptions defined. (Temporary; makes parsing easier.)

Each entry in the above keys is assigned one or more subscription indices, indicating the subscription(s) it should be included within. 

### Defining Data Types 

To define a `subscribed` data type, the following data is required: 
- The name of the data type. 
    - This is the name of both the data to be delivered and the enum variant. See `use` below. 
    - For example, defining `TlsConnSubscription` in the configuration file is equivalent to defining, in Rust code, `struct TlsConnSubscription` and enum variant `TlsConnSubscription(TlsConnSubscription)`.
    - This is written as the `key` for the data type. 
- `idx`: The list of subscription indexes this data type should be delivered for.
    - For example, defining `[0, 1]` here would cause this data type to be delivered for subscriptions `[0, 1]`. These subscriptions will be defined by this data type, as well as the callback(s) and filter(s) associated with `[0, 1]` respectively. 
    - This makes it easier to deliver the same data for, e.g., two different filters, while being able to discern which filter was matched.
- `fields`: The list of struct fields to be included in the data type. 
    - For now, these are hard coded and non-customizable: see `data types` below. 
    - For example, specifying `connection` in the struct `TlsConnSubscription` will create an accessible struct field in `TlsConnSubscription` named `connection` of type `Connection`.
    - This will also populate the data that is `tracked` by the framework during packet processing. For example, specifying `tls` will cause Retina to cache and/or deliver Tls sessions that match relevant filters. 

Data types currently supported as struct fields: 
- Application-layer protocols:
  - HTTP: `http`. Delivered data type: `Http`.
  - TLS: `tls`. Delivered data type: `Tls`.
- Connection: 
  - Five tuple: `five_tuple`. Delivered data type: `FiveTuple`.
  - All connection data: `connection`. Delivered data type: `Connection` (from `subscription` mod).

Note: right now, "or" conditions in the data types don't reliably work -- i.e., you cannot include `http` and `tls` in the same subscription. (This is a bug.) If you need to do this, use multiple filters to approximate it. 

### Defining filters

Each `filter` is a raw string, in the same format as original Retina filters, followed by the index(es) it applies to.

### Defining callbacks

Each is the name of the callback, followed by a list of one or more indexes to apply to. 

Each callback must be defined in the program's `main` file. 

### Number of subscriptions

**Don't forget to update this when adding subscriptions.** 

It defines the size of the array needed to store intermediate matches. This could be derived from the rest of the yaml file, but since this is a temporary interface anyway, it doesn't need to be. 

## Writing the `main` file

Examples of the backwards-compatible interface are in the `examples` directory. An example of the "new" interface is in `examples/basic`. It differs from the original retina in the following ways: 
- Use the macro `retina_main`. 
- To the runtime, pass in `filter` (as before), along with `callbacks()`. `Callbacks()` will return your vector of callbacks, as defined in the config file. 
- The enum `Subscribed` will be delivered to callbacks. Data types in enum variants can be extracted. For example: 

```rust
fn callback(data: Subscribed) { // Input is enum variant.
    // Match on data based on what you expect to be delivered.
    // Struct/data type and enum variant are both named as 
    // specified in input file.
    if let Subscribed::TlsSubscription(tls) = data {
        // `tls` is type TlsSubscription.
        println!("CB 1: {:?}", tls);
    }
}
```

# Compilation

## Compile-time outputs

During compilation, you will see two outputs of the tree. The first is a collapsed filter, which can be pushed down to RX Cores (HW filter). *I have not tested the hardware, since I don't have a server.* 

```
Collapsed Filter:
`- ethernet (0) : 
   |- ipv4 (1) : 
   |  `- tcp (2) p:  0
   |     |- http (3) c:  0*
   |     `- tls (4) c:  0*
   `- ipv6 (5) : 
      `- tcp (6) p:  0
         `- tls (7) c:  0
            `- tls.sni matches ^.*\.com$ (8) s:  0*
```

The second is the "complete" filter, applied if a boolean hardware filter matches (when applicable). This tracks the filter IDs for each applied. `*` represents a terminal match. 

```
Complete Filter:
`- ethernet (0) : 
   |- ipv4 (1) : 
   |  `- tcp (2) p:  0 1 2
   |     |- tls (3) c:  1* 0
   |     |  `- tls.sni matches ^.*\.com$ (4) s:  0*
   |     `- http (9) c:  2*
   `- ipv6 (5) : 
      `- tcp (6) p:  0
         `- tls (7) c:  0
            `- tls.sni matches ^.*\.com$ (8) s:  0*
```

Finally, the filter outputs its required protocols for parsing. Note that anything here will be augmented by the requirements of the data types defined in the subscription. 

```
Protocols for parsers:
- http or tls
```

## Generated Code

An explanation and example of the code generated by the user configuration is below. To see the specifics of a program, run `cargo expand` in (1) the user program crate (e.g., `examples/basic`), for filter code, and (2) the core library, for subscription/data tracking code. 

Annotated code below is drawn from this sample yaml file: 

```yaml
subscribed:
  # Name of the data type. 
  TlsConnSubscription: 
    # This data should be delivered for subscription idx 0
    idx: [0]
    # Fields to be delivered: Tls, Five_Tuple, and connection data
    fields: 
      tls: default
      five_tuple: 
      connection:
  TlsSubscription:
    idx: [1]
    fields: 
      tls: default
      five_tuple:
  HttpSubscription:
    idx: [2]
    fields: 
      http: default
      five_tuple:
      connection:
# Filters to be applied. 
# The subscriptions they correspond to. 
filters:
  "tls.sni ~ '^.*\\.com$'": [0]
  "tls and ipv4": [1]
  "ipv4 and http": [2]
# Callbacks defined in `main.rs` file, mapped to subscription IDs.
callbacks:
  callback2: [0, 1, 2]
# Don't forget to update this. 
num_subscriptions: 3
```

### Filter code.

The filter logic takes the following format: 
- It stores *bitmasks* corresponding to the data type(s) matched, terminally and non-terminally
- It stores *nodes* on the ptree, like the original retina, that represent non-terminal match arms
- All of this is in a `FilterResultData` struct, which can be referenced in the core `filter` module.

Below is an annotated example of generated code. 

```rust
// Filter function: 
fn filter() -> retina_core::filter::FilterFactory {
    #[inline]
    // The packet filter function, applied to an `mbuf`
    fn packet_filter(mbuf: &retina_core::Mbuf) -> retina_core::filter::FilterResultData {
        let mut result = retina_core::filter::FilterResultData::new();
        if let Ok(ethernet)
            = &retina_core::protocols::packet::Packet::parse_to::<
                retina_core::protocols::packet::ethernet::Ethernet,
            >(mbuf) {
            if let Ok(ipv4)
                = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::ipv4::Ipv4,
                >(ethernet) {
                if let Ok(tcp)
                    = &retina_core::protocols::packet::Packet::parse_to::<
                        retina_core::protocols::packet::tcp::Tcp,
                    >(ipv4) {
                    /* Bitmask for the filter IDs that are non-terminally matched.
                    * A bitmask of `7` (0b111) here indicates that filters 0, 1, and 2
                    * are non-terminally matched at this node at the end of the 
                    * packet filter function. */
                    result.nonterminal_matches |= 7;
                    /* This is an array to force storage on stack. 
                     * Each non-terminal match node need only be stored once, 
                     * i.e., emulating a set. */
                    result.nonterminal_nodes[1] = 2;
                }
            } else if let Ok(ipv6)
                = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::ipv6::Ipv6,
                >(ethernet) {
                if let Ok(tcp)
                    = &retina_core::protocols::packet::Packet::parse_to::<
                        retina_core::protocols::packet::tcp::Tcp,
                    >(ipv6) {
                    /* Similarly, here, filter `0` is non-terminally matched 
                     * at node 6. */
                    result.nonterminal_matches |= 1;
                    result.nonterminal_nodes[0] = 6;
                }
            }
        }
        return result;
    }
    /* As in the original Retina, the connection filter takes in data from the 
     * packet filter to indicate match arm on the ptree. */
    #[inline]
    fn connection_filter(
        pkt_results: &retina_core::filter::FilterResultData,
        conn: &retina_core::protocols::stream::ConnData,
    ) -> retina_core::filter::FilterResultData {
        let mut result = retina_core::filter::FilterResultData::new();
        for node in &pkt_results.nonterminal_nodes {
            /* Note: this can and should be modified such that the 
             * stored node values are contiguous, instead of stored 
             * at random points in the array. */
            if *node == std::usize::MAX {
                continue;
            }
            match node {
                2 => {
                    if match conn.service() {
                        retina_core::protocols::stream::ConnParser::Tls { .. } => true,
                        _ => false,
                    } {
                        /* Our first terminal match, stored in the bitmask. 
                         * Note that the original Retina will re-calculate this as a terminal 
                         * match, later, in the `session_filter` function. Because filter results
                         * are now cached in the subscription tracker, this is no longer needed. 
                         * If a filter ID was terminally matched in the connection filter, there is
                         * no need to recalculate it in the session filter. */
                        result.terminal_matches |= 2;
                        /* Again, we have some non-terminal matches. */
                        result.nonterminal_matches |= 1;
                        result.nonterminal_nodes[0] = 3;
                    }
                    if match conn.service() {
                        retina_core::protocols::stream::ConnParser::Http { .. } => true,
                        _ => false,
                    } {
                        result.terminal_matches |= 4;
                    }
                }
                6 => {
                    if match conn.service() {
                        retina_core::protocols::stream::ConnParser::Tls { .. } => true,
                        _ => false,
                    } {
                        result.nonterminal_matches |= 1;
                        result.nonterminal_nodes[0] = 7;
                    }
                }
                _ => {}
            }
        }
        result
    }
    /* Again, results from the connection filter are passed in. */
    #[inline]
    fn session_filter(
        session: &retina_core::protocols::stream::Session,
        conn_results: &retina_core::filter::FilterResultData,
    ) -> retina_core::filter::FilterResultData {
        let mut result = retina_core::filter::FilterResultData::new();
        for node in &conn_results.nonterminal_nodes {
            if *node == std::usize::MAX {
                continue;
            }
            match node {
                3 => {
                    if let retina_core::protocols::stream::SessionData::Tls(tls)
                        = &session.data
                    {
                        if RE0.is_match(&tls.sni()[..]) {
                            result.terminal_matches |= 1;
                        }
                    }
                }
                7 => {
                    if let retina_core::protocols::stream::SessionData::Tls(tls)
                        = &session.data
                    {
                        if RE1.is_match(&tls.sni()[..]) {
                            result.terminal_matches |= 1;
                        }
                    }
                }
                _ => {}
            }
        }
        result
    }
    retina_core::filter::FilterFactory::new(
        // Will be "collapsed" down to HW, if applicable
        "(tls.sni ~ '^.*\\.com$') or (tls and ipv4) or (ipv4 and http)",
        // Parsers needed
        "http or tls",
        // Filter functions
        packet_filter,
        connection_filter,
        session_filter,
    )

    // Omitted: main, statics, etc.
}
``` 


### Subscription and Tracking Code

The `subscriptiongen` crate provides the macro that is applied to the `custom_data` module in `core/subscription/custom.rs`. An annotated example is below. A few notes:

- Multiple subscriptions do not introduce additional copying to the subscription. 
    - This means **non-copy data fields in a struct will be stored in an `Rc`**: `http`, `tls`, and `connection`. 

- The "subscription" is contained within a single wrapper, as is the data "tracking". This means that filters are applied to all subscriptions collectively (see above), and data is tracked, as subscriptions are matched, in one place. 

Example output from the above file: 

```rust
pub mod custom {
    // Note: all custom code generation can be disabled by setting this feature. 
    #[cfg(not(feature = "no_custom"))]
    use retina_subscriptiongen::subscription_type;
    pub mod custom_data {
        /* Imports. Note that these currently aren't customized, and they should be! */
        use std::rc::Rc;
        use crate::conntrack::conn_id::FiveTuple;
        use crate::conntrack::pdu::{L4Context, L4Pdu};
        use crate::conntrack::ConnTracker;
        use crate::filter::{FilterResult, FilterResultData};
        use crate::memory::mbuf::Mbuf;
        use crate::protocols::stream::{ConnParser, Session, SessionData, ConnData};
        use crate::conntrack::conn::conn_info::ConnState;
        use crate::subscription::{Trackable, MatchData, Subscription, Subscribable};
        #[allow(unused_imports)]
        use crate::protocols::stream::tls::{parser::TlsParser, Tls};
        #[allow(unused_imports)]
        use crate::protocols::stream::http::{parser::HttpParser, Http};
        #[allow(unused_imports)]
        use crate::subscription::{Connection, connection::TrackedConnection};

        /* The generated `Subscribed` enum. 
         * Each variant and struct type is named according to the user input file. */
        pub enum Subscribed {
            TlsConnSubscription(TlsConnSubscription),
            TlsSubscription(TlsSubscription),
            HttpSubscription(HttpSubscription),
        }

        /* `Debug` is derived for each of these data types. 
         * Derivations will be expanded, but are **omitted** here. */
        
        /* The generated structs based on user configuration. 
         * Non-copy data are in an Rc. 
         * Again, `Debug` derivations are omitted. */ 

        pub struct TlsConnSubscription {
           /* KNOWN ISSUE: As noted above, data like `Tls` should be 
            * an option to enable an "or" type for session data.
            * Delivering this data requires the Tls session to exist. */
            pub tls: Rc<Tls>,
            pub five_tuple: FiveTuple,
            pub connection: Rc<Connection>,
        }
        
        pub struct TlsSubscription {
            pub tls: Rc<Tls>,
            pub five_tuple: FiveTuple,
        }
        
        pub struct HttpSubscription {
            pub five_tuple: FiveTuple,
            pub http: Rc<Http>,
            pub connection: Rc<Connection>,
        }
        
        /* The "wrapper" for all subscribable types. */
        pub struct SubscribableWrapper;
        impl Subscribable for SubscribableWrapper {
            /* Two associated types: 
             * - The "tracker" 
             * - The data (here, an enum) that will ultimately be delivered 
             *   to the user callback. */
            type Tracked = TrackedWrapper;
            type SubscribedData = Subscribed;

            /* Parsers required by the data types. 
             * The parsers at runtime will be built from 
             * (1) what the filter requires, and (2) what 
             * the subscribed data (here) requires. */
            fn parsers() -> Vec<ConnParser> {
                <[_]>::into_vec(
                    #[rustc_box]
                    ::alloc::boxed::Box::new([
                        ConnParser::Http(HttpParser::default()),
                        ConnParser::Tls(TlsParser::default()),
                    ]),
                )
            }

            /* Entry point for processing a packet. 
             * If any filter is matched, continue. */
            fn process_packet(
                mbuf: Mbuf,
                subscription: &Subscription<Self>,
                conn_tracker: &mut ConnTracker<Self::Tracked>,
            ) {
                let result = subscription.filter_packet(&mbuf);
                if result.terminal_matches != 0 || result.nonterminal_matches != 0 {
                    if let Ok(ctxt) = L4Context::new(&mbuf) {
                        conn_tracker.process(mbuf, ctxt, subscription, result);
                    }
                } else {
                    drop(mbuf);
                }
            }
        }

        /* ALL data tracking. 
         * - MatchData is a new type defined in subscription/mod.rs. 
         *   It tracks the FilterResults so far, such that all filtering 
         *   is contained in this module (i.e., not spread between here and
         *   the connection tracking infrastructure)/
         * - `http` is a vector; a connection can have one or more HTTP sessions. 
         * - `tls` is an option; a connection can have zero or more TLS sessions. 
         * - `five_tuple` is a single field.
         * - The `connection` type relies on the code in `subscription/connection`. */
        pub struct TrackedWrapper {
            match_data: MatchData,
            http: Vec<Rc<Http>>,
            tls: Option<Rc<Tls>>,
            five_tuple: FiveTuple,
            connection: TrackedConnection,
        }

        impl Trackable for TrackedWrapper {
            // Tied to the subscribable type.
            type Subscribed = SubscribableWrapper;

            /* The first packet result, calculated by the subscribable wrapper, 
             * is passed in when we begin tracking a new connection. */
            fn new(five_tuple: FiveTuple, result: FilterResultData) -> Self {
                Self {
                    match_data: MatchData::new(result),
                    http: Vec::new(),
                    tls: None,
                    five_tuple: five_tuple,
                    connection: TrackedConnection::new(
                        five_tuple,
                        // This is dummy data, s.t. we can reuse TrackedConnection code. 
                        FilterResultData::new(),
                    ),
                }
            }

            /* This is called on pre- and post-match. 
             * The decision regarding what to do with data (e.g., if there were frames here) 
             * is made based on the match state. */
            fn update(
                &mut self,
                pdu: L4Pdu,
                session_id: Option<usize>,
                subscription: &Subscription<Self::Subscribed>,
            ) {
                /* This is a bitmask representing the subscription(s) that 
                 * have requested connection data. If any of them are still 
                 * active -- terminally or non-terminally matching -- we 
                 * update the connection. */
                if self.match_data.matching_by_bitmask(5) {
                    self.connection.update_data(pdu)
                }
            }

            /* For connection-level data, we deliver all of it on termination. */
            fn on_terminate(
                &mut self,
                subscription: &Subscription<Self::Subscribed>,
            ) {
                /* Collect the connection data from the tracker once. */
                let connection = Rc::new(self.connection.to_connection());

                /* Deliver to callbacks based on data that exists and 
                 * based on the matched filter. */

                if self.match_data.matched_term_by_idx(0) {
                    if let Some(data) = &self.tls {
                        subscription
                            .invoke_idx(
                                Subscribed::TlsConnSubscription(TlsConnSubscription {
                                    tls: data.clone(),
                                    five_tuple: self.five_tuple,
                                    connection: connection.clone(),
                                }),
                                0,
                            );
                    }
                }
                if self.match_data.matched_term_by_idx(2) {
                    if let Some(data) = self.http.last() {
                        subscription
                            .invoke_idx(
                                Subscribed::HttpSubscription(HttpSubscription {
                                    five_tuple: self.five_tuple,
                                    http: data.clone(),
                                    connection: connection.clone(),
                                }),
                                2,
                            );
                    }
                }
            }

            /* This is invoked when a filter is matched. 
             * - Any packet-level matches would be delivered here. 
             * - Any session-level matches would be delivered here. 
             * - The type then tells the connection tracker whether to 
             *   track or drop the connection. Note that the tracker will 
             *   make this decision based on (1) the filter (e.g., if tracking 
             *   HTTP, the connection will continue to be tracked in case 
             *   there are more sessions), and (2) the value returned here. */
            fn deliver_session_on_match(
                &mut self,
                session: Session,
                subscription: &Subscription<Self::Subscribed>,
            ) -> ConnState {
                if let SessionData::Http(http) = session.data {
                    self.http.push(Rc::new(*http));
                } else if let SessionData::Tls(tls) = session.data {
                    self.tls = Some(Rc::new(*tls));
                }
                if self.match_data.matched_term_by_idx(1) {
                    if let Some(data) = &self.tls {
                        subscription
                            .invoke_idx(
                                Subscribed::TlsSubscription(TlsSubscription {
                                    tls: data.clone(),
                                    five_tuple: self.five_tuple,
                                }),
                                1,
                            );
                    }
                }
                if self.match_data.matching_by_bitmask(5) {
                    /* Connection-level subscriptions are being terminally 
                     * or non-terminally matched. */
                    return ConnState::Tracking;
                }
                ConnState::Remove
            }

            /* Filter functions to store data in the tracking wrapper.
             * The packet data is just passed in, as it will be applied and 
             * referenced by the conn_tracker and/or when initializing a new 
             * connection for tracking. */
             
            fn filter_packet(&mut self, pkt_filter_result: FilterResultData) {
                self.match_data.filter_packet(pkt_filter_result);
            }
            fn filter_conn(
                &mut self,
                conn: &ConnData,
                subscription: &Subscription<Self::Subscribed>,
            ) -> FilterResult {
                return self.match_data.filter_conn(conn, subscription);
            }
            fn filter_session(
                &mut self,
                session: &Session,
                subscription: &Subscription<Self::Subscribed>,
            ) -> bool {
                return self.match_data.filter_session(session, subscription);
            }
        }
    }
}
```