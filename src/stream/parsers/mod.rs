//! Stream protocol parsers.

mod http;
mod tls;

pub use http::HttpStreamParser;
pub use tls::TlsStreamParser;
