// Failures the CLI prints and exits on. HTTP errors keep the server's machine
// code so a script can branch without scraping prose.

use serde_json::{json, Value};
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Usage(String),
    Http {
        status: u16,
        code: String,
        message: String,
        detail: Option<Value>,
    },
    Transport(String),
    Io(String),
}

impl Error {
    pub fn usage(message: impl Into<String>) -> Self {
        Self::Usage(message.into())
    }

    pub fn io(context: &str, err: impl fmt::Display) -> Self {
        Self::Io(format!("{context}: {err}"))
    }

    pub fn transport(url: &str, err: impl fmt::Display) -> Self {
        Self::Transport(format!(
            "cannot reach {url} ({err}) — is xenon running, and is XENON_URL right?"
        ))
    }

    pub fn from_status(status: u16, body: Value) -> Self {
        let code = body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("http_error")
            .to_string();
        let message = body
            .get("message")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("HTTP {status}"));
        Self::Http {
            status,
            code,
            message,
            detail: body.get("detail").cloned(),
        }
    }

    pub fn to_json(&self) -> String {
        let value = match self {
            Self::Usage(message) => json!({ "error": "usage", "message": message }),
            Self::Http {
                status,
                code,
                message,
                detail,
            } => {
                let mut obj = json!({
                    "error": code,
                    "message": message,
                    "status": status,
                });
                if let Some(detail) = detail {
                    obj["detail"] = detail.clone();
                }
                obj
            }
            Self::Transport(message) | Self::Io(message) => {
                json!({ "error": "client", "message": message })
            }
        };
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) | Self::Transport(message) | Self::Io(message) => {
                write!(f, "error: {message}")
            }
            Self::Http {
                status,
                code,
                message,
                detail,
            } => {
                write!(f, "error: {code} (HTTP {status})\n{message}")?;
                if let Some(detail) = detail {
                    write!(f, "\n{detail}")?;
                }
                Ok(())
            }
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::usage(format!("invalid JSON: {err}"))
    }
}
