// Thin HTTP client over the `/v1` wire protocol. Auth is one header: a bearer
// token or a session cookie, never both. A bad credential must reach the
// server as a bad credential — we never silently drop it.

use crate::error::{Error, Result};
use serde_json::Value;
use std::time::Duration;

const USER_AGENT: &str = concat!("xen/", env!("CARGO_PKG_VERSION"));
const TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Client {
    agent: ureq::Agent,
    base: String,
    token: Option<String>,
    session: Option<String>,
}

impl Client {
    pub fn new(base: &str, token: Option<String>, session: Option<String>) -> Self {
        let agent = ureq::AgentBuilder::new().timeout(TIMEOUT).build();
        Self {
            agent,
            base: base.trim_end_matches('/').to_string(),
            token,
            session,
        }
    }

    /// Token if we have one, otherwise the session. Resource routes accept
    /// either; this is the usual caller.
    pub fn with_any(base: &str, token: Option<String>, session: Option<String>) -> Result<Self> {
        Ok(Self::new(base, token, session))
    }

    /// Session only. Token minting and invites refuse a bearer token, so a
    /// stored integration token must not be sent on those routes.
    pub fn with_session(base: &str, session: Option<String>) -> Result<Self> {
        let session = session.ok_or_else(|| {
            Error::usage("this command needs a login session — run `xen login` first")
        })?;
        Ok(Self::new(base, None, Some(session)))
    }

    pub fn health(&self) -> Result<String> {
        let url = format!("{}/healthz", self.base);
        match self.agent.get(&url).set("User-Agent", USER_AGENT).call() {
            Ok(resp) => resp
                .into_string()
                .map(|s| s.trim().to_string())
                .map_err(|e| Error::io("read /healthz", e)),
            Err(ureq::Error::Status(status, resp)) => {
                Err(Error::from_status(status, read_body(resp)))
            }
            Err(ureq::Error::Transport(err)) => Err(Error::transport(&self.base, err)),
        }
    }

    pub fn get(&self, path: &str) -> Result<Value> {
        self.send("GET", path, None).map(|r| r.body)
    }

    pub fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let url = format!("{}{path}", self.base);
        let req = self.authorize(self.agent.request("GET", &url));
        match req.call() {
            Ok(resp) => {
                let mut buf = Vec::new();
                resp.into_reader()
                    .read_to_end(&mut buf)
                    .map_err(|e| Error::io("read body", e))?;
                Ok(buf)
            }
            Err(ureq::Error::Status(status, resp)) => {
                Err(Error::from_status(status, read_body(resp)))
            }
            Err(ureq::Error::Transport(err)) => Err(Error::transport(&self.base, err)),
        }
    }

    pub fn post(&self, path: &str, body: &Value) -> Result<Response> {
        self.send("POST", path, Some(body))
    }

    pub fn patch(&self, path: &str, body: &Value) -> Result<Value> {
        self.send("PATCH", path, Some(body)).map(|r| r.body)
    }

    pub fn delete(&self, path: &str) -> Result<()> {
        self.send("DELETE", path, None).map(|_| ())
    }

    pub fn put_bytes(&self, path: &str, bytes: &[u8]) -> Result<u16> {
        let url = format!("{}{path}", self.base);
        let req = self
            .authorize(self.agent.request("PUT", &url))
            .set("Content-Type", "application/octet-stream");
        match req.send_bytes(bytes) {
            Ok(resp) => Ok(resp.status()),
            Err(ureq::Error::Status(status, resp)) => {
                Err(Error::from_status(status, read_body(resp)))
            }
            Err(ureq::Error::Transport(err)) => Err(Error::transport(&self.base, err)),
        }
    }

    fn send(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Response> {
        let url = format!("{}{path}", self.base);
        let req = self.authorize(self.agent.request(method, &url));
        let result = match body {
            Some(value) => req.send_json(value),
            None => req.call(),
        };
        match result {
            Ok(resp) => Ok(finish(resp)),
            Err(ureq::Error::Status(status, resp)) => {
                Err(Error::from_status(status, read_body(resp)))
            }
            Err(ureq::Error::Transport(err)) => Err(Error::transport(&self.base, err)),
        }
    }

    fn authorize(&self, req: ureq::Request) -> ureq::Request {
        let req = req
            .set("User-Agent", USER_AGENT)
            .set("Accept", "application/json");
        if let Some(token) = &self.token {
            req.set("Authorization", &format!("Bearer {token}"))
        } else if let Some(session) = &self.session {
            req.set("Cookie", &format!("xenon_session={session}"))
        } else {
            req
        }
    }
}

pub struct Response {
    pub status: u16,
    pub body: Value,
    pub session: Option<String>,
}

fn finish(resp: ureq::Response) -> Response {
    let status = resp.status();
    let session = resp.header("set-cookie").and_then(parse_session_cookie);
    let body = read_body(resp);
    Response {
        status,
        body,
        session,
    }
}

fn read_body(resp: ureq::Response) -> Value {
    let text = resp.into_string().unwrap_or_default();
    if text.trim().is_empty() {
        return Value::Null;
    }
    serde_json::from_str(&text).unwrap_or(Value::String(text))
}

fn parse_session_cookie(set_cookie: &str) -> Option<String> {
    for part in set_cookie.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("xenon_session=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Encode a bundle-relative file path so slashes stay as path segments.
pub fn encode_file_path(path: &str) -> String {
    path.split('/')
        .map(encode_segment)
        .collect::<Vec<_>>()
        .join("/")
}

pub fn encode_segment(raw: &str) -> String {
    let mut out = String::new();
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_paths_keep_slashes_and_escape_spaces() {
        assert_eq!(encode_file_path("notes/a file.md"), "notes/a%20file.md");
    }

    #[test]
    fn empty_session_cookie_is_ignored() {
        assert!(parse_session_cookie("xenon_session=; Path=/; Max-Age=0").is_none());
        assert_eq!(
            parse_session_cookie("xenon_session=abc123; Path=/; HttpOnly").as_deref(),
            Some("abc123")
        );
    }
}
