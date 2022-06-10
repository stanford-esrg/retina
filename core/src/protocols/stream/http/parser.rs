// modified from https://github.com/rusticata/rusticata/blob/master/src/http.rs
//! HTTP transaction parser.
//!
//! The HTTP transaction parser uses the [httparse](https://docs.rs/httparse/latest/httparse/) crate to parse HTTP request/responses. It handles HTTP pipelining, but does not currently support defragmenting message bodies.
//!

use super::transaction::{HttpRequest, HttpResponse};
use super::Http;
use crate::conntrack::conn::conn_info::ConnState;
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::{ConnParsable, ParseResult, ProbeResult, Session, SessionData};

use httparse::{Request, EMPTY_HEADER};
use std::collections::HashMap;

#[derive(Default, Debug)]
pub struct HttpParser {
    /// Pending requests: maps session ID to HTTP transaction.
    pending: HashMap<usize, Http>,
    /// Current outstanding request ID (transaction depth).
    current_trans: usize,
    /// The current deepest transaction (total transactions ever seen).
    cnt: usize,
}

impl HttpParser {
    /// Process data segments from client to server
    pub(crate) fn process_ctos(&mut self, data: &[u8]) -> ParseResult {
        if let Ok(request) = HttpRequest::parse_from(data) {
            let session_id = self.cnt;
            let http = Http {
                request,
                response: HttpResponse::default(),
                trans_depth: session_id,
            };
            self.cnt += 1;
            self.pending.insert(session_id, http);
            ParseResult::Continue(session_id)
        } else {
            // request continuation data or parse error.
            // TODO: parse request continuation data
            ParseResult::Skipped
        }
    }

    /// Process data segments from server to client
    pub(crate) fn process_stoc(&mut self, data: &[u8], pdu: &L4Pdu) -> ParseResult {
        if let Ok(response) = HttpResponse::parse_from(data) {
            if let Some(http) = self.pending.get_mut(&self.current_trans) {
                http.response = response;
                // TODO: Handle response continuation data instead of returning
                // ParseResult::Done immediately on Response start-line
                ParseResult::Done(self.current_trans)
            } else {
                log::warn!("HTTP response without oustanding request: {:?}", pdu.ctxt);
                ParseResult::Skipped
            }
        } else {
            // response continuation data or parse error.
            // TODO: parse response continuation data
            ParseResult::Skipped
        }
    }
}

impl ConnParsable for HttpParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            if pdu.dir {
                self.process_ctos(data)
            } else {
                self.process_stoc(data, pdu)
            }
        } else {
            log::warn!("Malformed packet on parse");
            ParseResult::Skipped
        }
    }

    fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        // adapted from [the Rusticata HTTP parser](https://github.com/rusticata/rusticata/blob/master/src/http.rs)

        // number of headers to parse at once
        const NUM_OF_HEADERS: usize = 4;

        if pdu.length() < 6 {
            return ProbeResult::Unsure;
        }
        let offset = pdu.offset();
        let length = pdu.length();
        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            // check if first characters match start of "request-line"
            match &data[..4] {
                b"OPTI" | b"GET " | b"HEAD" | b"POST" | b"PUT " | b"PATC" | b"COPY" | b"MOVE"
                | b"DELE" | b"LINK" | b"UNLI" | b"TRAC" | b"WRAP" => (),
                _ => return ProbeResult::NotForUs,
            }
            // try parsing request
            let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
            let mut req = Request::new(&mut headers[..]);
            let status = req.parse(data);
            if let Err(e) = status {
                if e != httparse::Error::TooManyHeaders {
                    log::trace!(
                        "data could be HTTP, but got error {:?} while parsing",
                        status
                    );
                    return ProbeResult::Unsure;
                }
            }
            ProbeResult::Certain
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }

    fn remove_session(&mut self, session_id: usize) -> Option<Session> {
        // Increment to next outstanding transaction in request order
        self.current_trans = session_id + 1;
        self.pending.remove(&session_id).map(|http| Session {
            data: SessionData::Http(Box::new(http)),
            id: session_id,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.pending
            .drain()
            .map(|(session_id, http)| Session {
                data: SessionData::Http(Box::new(http)),
                id: session_id,
            })
            .collect()
    }

    fn session_match_state(&self) -> ConnState {
        ConnState::Parsing
    }

    fn session_nomatch_state(&self) -> ConnState {
        ConnState::Parsing
    }
}
