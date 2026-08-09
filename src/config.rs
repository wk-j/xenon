// Xenon — environment configuration.
//
// Everything is an env var so the service configures identically from a shell,
// a systemd unit, and a container. There is deliberately no admin token and no
// seeded admin password: the first account to register becomes the admin, so
// there is no long-lived credential sitting in a compose file or shell history.

use std::path::PathBuf;

/// Where state lives when `XENON_DATA_DIR` says nothing: the database, the blob
/// store, the price table, the session secret.
///
/// Deliberately **not** `./data`. A relative default ties a running instance to
/// whichever directory it was launched from, so `cargo run` from the repo and
/// `xenon` from anywhere else are two different servers with two different sets
/// of accounts — and a `git clean` or a moved checkout takes published work with
/// it. Anchoring on the home directory makes the instance a property of the
/// user, not of a checkout.
///
/// `~/.config/xenon` regardless of platform, matching how the sibling Krypton
/// app resolves `~/.config/krypton` rather than the platform-specific location.
/// One path to remember across both, and one path to back up.
const DATA_SUBDIR: &str = ".config/xenon";

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
    /// How long the activity log keeps a row, in days. `0` keeps everything.
    pub activity_retention_days: i64,
}

const DEFAULT_MAX_BLOB_MB: u64 = 64;
/// GitHub's events API keeps 30 days. A fleet log is read in weeks rather than
/// days, and 90 days of these rows is kilobytes.
const DEFAULT_ACTIVITY_RETENTION_DAYS: i64 = 90;

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let port = env_parse("XENON_PORT", 8787u16)?;
        let data_dir = match std::env::var("XENON_DATA_DIR") {
            Ok(raw) if !raw.trim().is_empty() => PathBuf::from(raw),
            _ => default_data_dir()?,
        };

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

        let activity_retention_days = env_parse(
            "XENON_ACTIVITY_RETENTION_DAYS",
            DEFAULT_ACTIVITY_RETENTION_DAYS,
        )?;
        if activity_retention_days < 0 {
            return Err(
                "XENON_ACTIVITY_RETENTION_DAYS must be 0 or more (0 keeps everything)".to_string(),
            );
        }

        Ok(Self {
            port,
            data_dir,
            session_secret,
            max_blob_bytes: max_blob_mb * 1024 * 1024,
            allow_signup: env_flag("XENON_ALLOW_SIGNUP"),
            insecure_cookies: env_flag("XENON_INSECURE_COOKIES"),
            activity_retention_days,
        })
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("xenon.db")
    }

    pub fn blob_dir(&self) -> PathBuf {
        self.data_dir.join("blobs")
    }

    /// The model rate table (spec 214). Lives in the data directory, not in the
    /// binary, so an operator can correct a price the day it changes without
    /// waiting for a release — which is the entire argument for pricing here
    /// rather than in the client.
    pub fn prices_path(&self) -> PathBuf {
        std::env::var("XENON_PRICES_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| self.data_dir.join("prices.json"))
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
            activity_retention_days: DEFAULT_ACTIVITY_RETENTION_DAYS,
        }
    }
}

/// `~/.config/xenon`, or an error naming the way out. A missing `HOME` is
/// normal in a container, where the Dockerfile sets `XENON_DATA_DIR=/data`
/// anyway — so say that rather than silently landing state somewhere the
/// operator did not choose.
fn default_data_dir() -> Result<PathBuf, String> {
    match std::env::var("HOME") {
        Ok(home) if !home.trim().is_empty() => Ok(PathBuf::from(home).join(DATA_SUBDIR)),
        _ => Err("HOME is not set, so the data directory cannot be resolved — set XENON_DATA_DIR to an absolute path".to_string()),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads `HOME` rather than setting it: mutating the environment races
    /// every other test in the process.
    #[test]
    fn the_default_data_dir_is_absolute_and_under_the_home_directory() {
        let home = std::env::var("HOME").expect("tests run with HOME set");
        let dir = default_data_dir().expect("HOME is set, so this resolves");

        assert!(dir.is_absolute(), "{} must be absolute", dir.display());
        assert!(
            dir.starts_with(&home),
            "{} must live under {home}",
            dir.display()
        );
        assert!(
            dir.ends_with("xenon"),
            "{} must be xenon's own directory, not the whole config dir",
            dir.display()
        );
    }
}
