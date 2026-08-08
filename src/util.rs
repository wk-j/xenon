// Xenon — small shared helpers: time, randomness, encoding, hashing.

use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};

/// Unix seconds. Xenon stores every timestamp as an integer so SQLite can sort
/// and range-filter them without a date extension.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `len` random bytes from the OS CSPRNG.
pub fn random_bytes(len: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).map_err(|e| format!("csprng unavailable: {e}"))?;
    Ok(buf)
}

/// Lowercase unpadded base32 of `bytes`, truncated to `chars`.
///
/// Base32 keeps ids and secrets case-insensitively typeable and free of the
/// `+`/`/` characters that would need escaping in a URL or a shell.
pub fn random_base32(chars: usize) -> Result<String, String> {
    // 5 bits per character, rounded up to whole bytes.
    let bytes = random_bytes(chars.div_ceil(8) * 5)?;
    let mut encoded = BASE32_NOPAD.encode(&bytes).to_lowercase();
    encoded.truncate(chars);
    Ok(encoded)
}

/// A new opaque row id, e.g. `usr_4k2j...`. The prefix makes ids
/// self-describing in logs and URLs without carrying any authority.
pub fn new_id(prefix: &str) -> Result<String, String> {
    Ok(format!("{prefix}{}", random_base32(20)?))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Length-independent equality for secrets. Returns false on a length mismatch
/// without comparing further, which only leaks the length — never the content.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Project slugs address a single URL path segment, so they may not contain a
/// slash. Krypton derives `<owner>.<repo>` from the git remote for this reason;
/// resource slugs (which do contain slashes, e.g. an analysis bundle's
/// `wk-j/krypton/12`) travel in a JSON body or a trailing wildcard instead.
pub fn is_valid_project_slug(slug: &str) -> bool {
    is_valid_slug(slug) && !slug.contains('/')
}

/// A lowercase, filesystem- and URL-safe identifier. Used for resource slugs.
pub fn is_valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 128
        && !slug.starts_with('/')
        && !slug.ends_with('/')
        && !slug.contains("//")
        && !slug.contains("..")
        && slug
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
}

/// A 64-char lowercase hex sha256 digest.
pub fn is_valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Relative path inside a resource bundle. Rejects anything that could escape
/// the bundle or collide with the blob store's own layout.
pub fn is_valid_file_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && !path.starts_with('/')
        && !path.contains("..")
        && !path.contains('\\')
        && !path.contains('\0')
        && !path
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_is_requested_length_and_random() {
        let a = random_base32(32).unwrap();
        let b = random_base32(32).unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
        assert_ne!(a, b);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_eq!(random_base32(12).unwrap().len(), 12);
    }

    #[test]
    fn constant_time_eq_matches_only_identical_strings() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn slug_rejects_traversal_and_empty_segments() {
        assert!(is_valid_slug("wk-j/krypton"));
        assert!(is_valid_slug("local/krypton-0f765408"));
        assert!(!is_valid_slug("../etc"));
        assert!(!is_valid_slug("/leading"));
        assert!(!is_valid_slug("trailing/"));
        assert!(!is_valid_slug("double//slash"));
        assert!(!is_valid_slug(""));
        assert!(!is_valid_slug("has space"));
    }

    #[test]
    fn project_slug_must_be_a_single_path_segment() {
        assert!(is_valid_project_slug("wk-j.krypton"));
        assert!(is_valid_project_slug("krypton"));
        assert!(
            !is_valid_project_slug("wk-j/krypton"),
            "a slash would span two path segments"
        );
        assert!(!is_valid_project_slug("../etc"));
    }

    #[test]
    fn file_path_rejects_traversal_and_absolute_paths() {
        assert!(is_valid_file_path("review.md"));
        assert!(is_valid_file_path("assets/diagram.png"));
        assert!(!is_valid_file_path("/etc/passwd"));
        assert!(!is_valid_file_path("../escape.md"));
        assert!(!is_valid_file_path("assets//x.png"));
        assert!(!is_valid_file_path("assets/./x.png"));
        assert!(!is_valid_file_path(""));
    }

    #[test]
    fn digest_validation_requires_lowercase_hex_64() {
        assert!(is_valid_digest(&"a".repeat(64)));
        assert!(!is_valid_digest(&"A".repeat(64)));
        assert!(!is_valid_digest(&"a".repeat(63)));
        assert!(!is_valid_digest(&"z".repeat(64)));
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
