// Xenon — environment configuration.
//
// Everything is an env var so the service configures identically from a shell,
// a systemd unit, and a container. There is deliberately no admin token and no
// seeded admin password: the first account to register becomes the admin, so
// there is no long-lived credential sitting in a compose file or shell history.

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub data_dir: PathBuf,
    /// Used to derive nothing today, but required at boot so an operator cannot
    /// accidentally run a public instance whose future signed values are
    /// predictable. Session ids are CSPRNG values stored hashed.
    pub session_secret: String,
    pub max_blob_bytes: u64,
    /// When false (the default), only the first-ever registration and
    /// invite-code registrations are accepted.
    pub allow_signup: bool,
    /// Set XENON_INSECURE_COOKIES=1 for local HTTP development. In production
    /// the cookie is always `Secure`.
    pub insecure_cookies: bool,
}

const DEFAULT_MAX_BLOB_MB: u64 = 64;

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let port = env_parse("XENON_PORT", 8787u16)?;
        let data_dir =
            PathBuf::from(std::env::var("XENON_DATA_DIR").unwrap_or_else(|_| "./data".to_string()));

        let session_secret = std::env::var("XENON_SESSION_SECRET").unwrap_or_default();
        if session_secret.len() < 32 {
            return Err(
                "XENON_SESSION_SECRET must be set to at least 32 characters (try: openssl rand -hex 32)"
                    .to_string(),
            );
        }

        let max_blob_mb = env_parse("XENON_MAX_BLOB_MB", DEFAULT_MAX_BLOB_MB)?;
        if max_blob_mb == 0 {
            return Err("XENON_MAX_BLOB_MB must be greater than zero".to_string());
        }

        Ok(Self {
            port,
            data_dir,
            session_secret,
            max_blob_bytes: max_blob_mb * 1024 * 1024,
            allow_signup: env_flag("XENON_ALLOW_SIGNUP"),
            insecure_cookies: env_flag("XENON_INSECURE_COOKIES"),
        })
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("xenon.db")
    }

    pub fn blob_dir(&self) -> PathBuf {
        self.data_dir.join("blobs")
    }

    /// Test-only constructor. Public because the integration suite is a
    /// separate crate and cannot reach a `#[cfg(test)]` item.
    #[doc(hidden)]
    pub fn for_test(data_dir: PathBuf) -> Self {
        Self {
            port: 0,
            data_dir,
            session_secret: "x".repeat(32),
            max_blob_bytes: 1024 * 1024,
            allow_signup: false,
            insecure_cookies: true,
        }
    }
}

fn env_flag(key: &str) -> bool {
    matches!(
        std::env::var(key).unwrap_or_default().as_str(),
        "1" | "true" | "yes"
    )
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> Result<T, String> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) if raw.trim().is_empty() => Ok(default),
        Ok(raw) => raw
            .trim()
            .parse::<T>()
            .map_err(|_| format!("{key} is not a valid value: {raw}")),
    }
}
