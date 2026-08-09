// Xenon — shared application state.

use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::atomic::AtomicI64;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::blob::BlobStore;
use crate::config::Config;
use crate::error::{AppError, AppResult};

pub struct AppState {
    pub config: Config,
    db: Mutex<Connection>,
    pub blobs: BlobStore,
    /// Login attempt timestamps keyed by `<ip>|<email>`, for rate limiting.
    pub login_attempts: Mutex<HashMap<String, Vec<i64>>>,
    /// When the activity log was last pruned. Retention is enforced from the
    /// write path at most once an hour rather than by a background task: one
    /// fewer moving part, and a server that never writes never needs to prune.
    pub last_activity_prune: AtomicI64,
}

impl AppState {
    pub fn new(config: Config, db: Connection) -> AppResult<Arc<Self>> {
        let blobs = BlobStore::new(config.blob_dir())?;
        Ok(Arc::new(Self {
            config,
            db: Mutex::new(db),
            blobs,
            login_attempts: Mutex::new(HashMap::new()),
            last_activity_prune: AtomicI64::new(0),
        }))
    }

    /// A poisoned mutex means a previous handler panicked mid-query. The
    /// connection itself is still usable, so recover rather than cascading the
    /// panic into every subsequent request.
    pub fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn tx<T>(&self, f: impl FnOnce(&rusqlite::Transaction) -> AppResult<T>) -> AppResult<T> {
        let mut conn = self.db();
        let tx = conn.transaction().map_err(AppError::from)?;
        let out = f(&tx)?;
        tx.commit().map_err(AppError::from)?;
        Ok(out)
    }
}
