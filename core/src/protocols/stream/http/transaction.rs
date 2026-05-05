//! HTTP transaction components.
//!
//! ## Remarks
//! Retina currently only parses HTTP headers, and does not yet parse request/response bodies. This
//! is an upcoming feature.

use anyhow::{bail, Result};
use httparse::{Request, Response, EMPTY_HEADER};
use serde::Serialize;

/// An HTTP Request
#[derive(Debug, Default, Serialize)]
pub struct HttpRequest {
    pub method: Option<String>,
    pub uri: Option<String>,
    pub version: Option<String>,
    pub user_agent: Option<String>,
    pub cookie: Option<String>,
    pub host: Option<String>,
    pub content_length: Option<usize>,
    pub content_type: Option<String>,
    pub transfer_encoding: Option<String>,
    // /// `false` if request body needs continuation pub is_complete: bool, /// Actual length in
    // bytes of body data transferred from the client. pub body_len: usize,
}

impl HttpRequest {
    pub(crate) fn parse_from(data: &[u8]) -> Result<Self> {
        let mut request = HttpRequest::default();

        const NUM_OF_HEADERS: usize = 20;
        let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
        let mut req = Request::new(&mut headers[..]);
        let status = req.parse(data);
        if status.is_err() {
            bail!("error");
        }

        if let Some(method) = req.method {
            request.method = Some(method.to_owned());
        }
        if let Some(uri) = req.path {
            request.uri = Some(uri.to_owned());
        }
        if let Some(version) = req.version {
            request.version = Some(format!("HTTP/1.{}", version));
        }
        for hdr in &headers {
            let name = hdr.name.to_lowercase();
            match name.as_ref() {
                "user-agent" => {
                    let s = String::from_utf8_lossy(hdr.value).into_owned();
                    request.user_agent = Some(s);
                }
                "cookie" => {
                    let s = String::from_utf8_lossy(hdr.value).into_owned();
                    request.cookie = Some(s);
                }
                "host" => {
                    let s = String::from_utf8_lossy(hdr.value);
                    request.host = Some(s.to_string());
                }
                "content-length" => {
                    if let Ok(s) = std::str::from_utf8(hdr.value) {
                        if let Ok(length) = str::parse::<usize>(s) {
                            request.content_length = Some(length);
                        }
                    }
                }
                "content-type" => {
                    let s = String::from_utf8_lossy(hdr.value).into_owned();
                    request.content_type = Some(s);
                }
                "transfer-encoding" => {
                    let s = String::from_utf8_lossy(hdr.value).to_lowercase();
                    request.transfer_encoding = Some(s);
                    // if &s == "chunked" {if let Ok(httparse::Status::Complete(sz)) = status {start
                    //     = sz;} else {log::warn!("Parsing response failed"); return
                    //     ParseResult::Error;
                    //     }
                    //     return request.get_chunk_loop(start, data, false);
                    // }
                }
                _ => (),
            }
        }
        Ok(request)
    }
}

/// An HTTP Response
#[derive(Debug, Default, Serialize)]
pub struct HttpResponse {
    pub version: Option<String>,
    pub status_code: Option<u16>,
    pub status_msg: Option<String>,
    pub content_length: Option<usize>,
    pub content_type: Option<String>,
    pub transfer_encoding: Option<String>,
    // /// `false` if response body needs continuation pub is_complete: bool, /// Actual length in
    // bytes of body data transferred from the server. pub body_len: usize, pub chunk_length:
    // Option<usize>, pub in_next_frame: bool,
}

impl HttpResponse {
    pub(crate) fn parse_from(data: &[u8]) -> Result<Self> {
        let mut response = HttpResponse::default();

        const NUM_OF_HEADERS: usize = 20;
        let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
        let mut resp = Response::new(&mut headers[..]);
        let status = resp.parse(data);
        if status.is_err() {
            bail!("error");
        }

        if let Some(version) = resp.version {
            response.version = Some(format!("HTTP/1.{}", version));
        }
        if let Some(code) = resp.code {
            response.status_code = Some(code);
        }
        if let Some(reason) = resp.reason {
            response.status_msg = Some(reason.to_owned());
        }

        for hdr in &headers {
            let name = hdr.name.to_lowercase();
            match name.as_ref() {
                "content-length" => {
                    if let Ok(s) = std::str::from_utf8(hdr.value) {
                        if let Ok(length) = str::parse::<usize>(s) {
                            // if let Ok(httparse::Status::Complete(sz)) = status {response.body =
                            //     data[sz..].to_vec();
                            // }
                            response.content_length = Some(length);
                            // if length > response.body.len() {need_more = true;
                            // }
                            // continue;
                        }
                    }
                }
                "content-type" => {
                    let s = String::from_utf8_lossy(hdr.value).into_owned();
                    response.content_type = Some(s);
                }
                "transfer-encoding" => {
                    let s = String::from_utf8_lossy(hdr.value).to_lowercase();
                    response.transfer_encoding = Some(s);
                    // if &s == "chunked" {if let Ok(httparse::Status::Complete(sz)) = status {start
                    //     = sz;} else {log::warn!("Parsing response failed"); return
                    //     ParseResult::Error;
                    //     }
                    //     return response.get_chunk_loop(start, data, false);
                    // }
                }
                _ => (),
            }
        }
        Ok(response)
    }
}
