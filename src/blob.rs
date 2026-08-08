// Xenon — content-addressed blob store.
//
// Files are stored once per distinct sha256 under `blobs/<aa>/<bb>/<sha256>`,
// fanned out two levels so no single directory accumulates every blob. Because
// the name *is* the digest, storing is idempotent and deduplication across
// revisions, resources, projects, and users is automatic: re-pushing a review
// whose `response.md` changed transfers only that one file.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{AppError, AppResult};
use crate::util::{is_valid_digest, sha256_hex};

pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn new(root: PathBuf) -> AppResult<Self> {
        std::fs::create_dir_all(&root)
            .map_err(|e| AppError::internal(format!("create blob dir {}: {e}", root.display())))?;
        std::fs::create_dir_all(root.join("tmp"))
            .map_err(|e| AppError::internal(format!("create blob tmp dir: {e}")))?;
        Ok(Self { root })
    }

    pub fn path_for(&self, sha256: &str) -> PathBuf {
        self.root
            .join(&sha256[0..2])
            .join(&sha256[2..4])
            .join(sha256)
    }

    pub fn exists(&self, sha256: &str) -> bool {
        is_valid_digest(sha256) && self.path_for(sha256).is_file()
    }

    /// Verifies that `bytes` actually hashes to `sha256` before storing.
    ///
    /// This is the one place the client's claim is checked. Trusting it would
    /// let a caller poison a digest that another user's revision already
    /// references — content addressing is only a guarantee if it is enforced.
    pub fn put(&self, sha256: &str, bytes: &[u8]) -> AppResult<()> {
        if !is_valid_digest(sha256) {
            return Err(AppError::bad_request(
                "invalid_digest",
                "digest must be 64 lowercase hex characters",
            ));
        }
        let actual = sha256_hex(bytes);
        if actual != sha256 {
            return Err(AppError::bad_request(
                "digest_mismatch",
                format!("body hashes to {actual}, not the claimed {sha256}"),
            ));
        }
        if self.exists(sha256) {
            return Ok(());
        }

        let final_path = self.path_for(sha256);
        if let Some(parent) = final_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write to a temp file and rename, so a crash or a concurrent upload of
        // the same digest can never leave a truncated blob at the final path.
        let tmp_path = self
            .root
            .join("tmp")
            .join(format!("{sha256}.{}", std::process::id()));
        {
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        match std::fs::rename(&tmp_path, &final_path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                Err(AppError::internal(format!("store blob {sha256}: {e}")))
            }
        }
    }

    pub fn read(&self, sha256: &str) -> AppResult<Vec<u8>> {
        if !is_valid_digest(sha256) {
            return Err(AppError::bad_request("invalid_digest", "malformed digest"));
        }
        std::fs::read(self.path_for(sha256))
            .map_err(|_| AppError::not_found(format!("blob {sha256} is not stored")))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::new(dir.path().join("blobs")).unwrap();
        (dir, store)
    }

    #[test]
    fn put_then_read_round_trips() {
        let (_dir, store) = store();
        let body = b"# review\n";
        let digest = sha256_hex(body);
        assert!(!store.exists(&digest));
        store.put(&digest, body).unwrap();
        assert!(store.exists(&digest));
        assert_eq!(store.read(&digest).unwrap(), body);
    }

    #[test]
    fn put_rejects_a_lying_digest() {
        let (_dir, store) = store();
        let claimed = sha256_hex(b"innocent");
        let err = store.put(&claimed, b"malicious").unwrap_err();
        assert_eq!(err.code, "digest_mismatch");
        assert!(
            !store.exists(&claimed),
            "nothing may be stored under a mismatched digest"
        );
    }

    #[test]
    fn put_is_idempotent() {
        let (_dir, store) = store();
        let body = b"same bytes";
        let digest = sha256_hex(body);
        store.put(&digest, body).unwrap();
        store.put(&digest, body).unwrap();
        assert_eq!(store.read(&digest).unwrap(), body);
    }

    #[test]
    fn fanout_keeps_two_levels_of_directories() {
        let (_dir, store) = store();
        let body = b"x";
        let digest = sha256_hex(body);
        store.put(&digest, body).unwrap();
        let expected = store
            .root()
            .join(&digest[0..2])
            .join(&digest[2..4])
            .join(&digest);
        assert!(
            expected.is_file(),
            "blob should live at the fanned-out path"
        );
    }

    #[test]
    fn malformed_digests_are_rejected_everywhere() {
        let (_dir, store) = store();
        assert_eq!(store.put("nope", b"x").unwrap_err().code, "invalid_digest");
        assert_eq!(store.read("nope").unwrap_err().code, "invalid_digest");
        assert!(!store.exists("nope"));
        // An uppercase digest would address a different path on a
        // case-insensitive filesystem; reject rather than normalise.
        assert!(!store.exists(&sha256_hex(b"x").to_uppercase()));
    }

    #[test]
    fn leaves_no_temp_files_behind() {
        let (_dir, store) = store();
        let body = b"tidy";
        store.put(&sha256_hex(body), body).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(store.root().join("tmp"))
            .unwrap()
            .flatten()
            .collect();
        assert!(
            leftovers.is_empty(),
            "tmp dir should be empty after a successful put"
        );
    }
}
