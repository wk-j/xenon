// Persistent client settings. Lives next to the server's data directory so
// there is one path to remember, but in its own file so wiping the database
// does not log the CLI out and a leaked cli.toml is not the server's session
// secret.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const DATA_SUBDIR: &str = ".config/xenon";
const FILE_NAME: &str = "cli.toml";
pub const DEFAULT_URL: &str = "http://127.0.0.1:8787";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct File {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

impl File {
    fn normalize(mut self) -> Self {
        self.url = nonempty(self.url);
        self.token = nonempty(self.token);
        self.session = nonempty(self.session);
        self
    }
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub path: PathBuf,
    pub file: File,
    pub url: String,
    pub token: Option<String>,
    pub session: Option<String>,
    pub json: bool,
}

impl Settings {
    pub fn load(
        path: Option<PathBuf>,
        url: Option<String>,
        token: Option<String>,
        session: Option<String>,
        json: bool,
    ) -> Result<Self> {
        let path = match path {
            Some(p) => p,
            None => default_path()?,
        };
        let file = if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| Error::io(&format!("read {}", path.display()), e))?;
            toml::from_str::<File>(&raw)
                .map_err(|e| Error::usage(format!("{} is not valid TOML: {e}", path.display())))?
                .normalize()
        } else {
            File::default()
        };

        let url = nonempty(url)
            .or_else(|| file.url.clone())
            .unwrap_or_else(|| DEFAULT_URL.to_string());
        let url = url.trim_end_matches('/').to_string();

        Ok(Self {
            token: nonempty(token).or_else(|| file.token.clone()),
            session: nonempty(session).or_else(|| file.session.clone()),
            path,
            file,
            url,
            json,
        })
    }

    pub fn save(&self) -> Result<()> {
        write_atomic(&self.path, &self.file)
    }

    pub fn persist_url(&mut self) {
        self.file.url = Some(self.url.clone());
    }

    pub fn persist_session(&mut self, session: String) {
        self.file.session = Some(session.clone());
        self.session = Some(session);
        self.persist_url();
    }

    pub fn persist_token(&mut self, token: String) {
        self.file.token = Some(token.clone());
        self.token = Some(token);
        self.persist_url();
    }

    pub fn clear_session(&mut self) {
        self.file.session = None;
        self.session = None;
    }

    pub fn clear_token(&mut self) {
        self.file.token = None;
        self.token = None;
    }
}

pub fn default_path() -> Result<PathBuf> {
    match std::env::var("HOME") {
        Ok(home) if !home.trim().is_empty() => {
            Ok(PathBuf::from(home).join(DATA_SUBDIR).join(FILE_NAME))
        }
        _ => Err(Error::usage(
            "HOME is not set, so the config path cannot be resolved — pass --config",
        )),
    }
}

fn write_atomic(path: &Path, file: &File) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::io(&format!("create {}", dir.display()), e))?;
    }
    let body =
        toml::to_string_pretty(file).map_err(|e| Error::usage(format!("serialize config: {e}")))?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, body).map_err(|e| Error::io(&format!("write {}", tmp.display()), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::io(&format!("chmod {}", tmp.display()), e))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| Error::io(&format!("replace {}", path.display()), e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_strings_in_the_file_are_treated_as_unset() {
        let parsed: File = toml::from_str("url = \"\"\ntoken = \"  \"\n").unwrap();
        let file = parsed.normalize();
        assert!(file.url.is_none());
        assert!(file.token.is_none());
    }
}
