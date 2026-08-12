// Collect local files and run the three-step ingest (or the single-shot
// inline route when the whole resource fits in 1 MB).

use crate::client::Client;
use crate::error::{Error, Result};
use data_encoding::BASE64;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const KINDS: [&str; 5] = ["artifact", "review", "analysis", "doc", "attention"];
const MAX_INLINE_BYTES: usize = 1024 * 1024;

pub struct LocalFile {
    pub path: String,
    pub bytes: Vec<u8>,
    pub content_type: String,
}

pub struct Request<'a> {
    pub project: &'a str,
    pub kind: &'a str,
    pub slug: &'a str,
    pub title: &'a str,
    pub meta: Value,
    pub origin: Value,
    pub files: &'a [LocalFile],
    pub force_inline: bool,
    pub skip_scan: bool,
}

pub fn collect(
    files: &[PathBuf],
    dirs: &[PathBuf],
    stdin: bool,
    as_path: Option<&str>,
) -> Result<Vec<LocalFile>> {
    let mut out = Vec::new();
    for path in files {
        let remote = remote_path(path)?;
        let bytes =
            std::fs::read(path).map_err(|e| Error::io(&format!("read {}", path.display()), e))?;
        out.push(LocalFile {
            content_type: content_type_for(&remote),
            path: remote,
            bytes,
        });
    }
    for dir in dirs {
        if !dir.is_dir() {
            return Err(Error::usage(format!(
                "{} is not a directory",
                dir.display()
            )));
        }
        walk(dir, dir, &mut out)?;
    }
    if stdin {
        let remote = as_path.ok_or_else(|| {
            Error::usage("--stdin needs --as <bundle-path> so the file has a name")
        })?;
        validate_remote_path(remote)?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes)?;
        out.push(LocalFile {
            content_type: content_type_for(remote),
            path: remote.to_string(),
            bytes,
        });
    } else if as_path.is_some() {
        return Err(Error::usage("--as is only used with --stdin"));
    }
    let mut seen = std::collections::HashSet::new();
    for file in &out {
        if !seen.insert(file.path.as_str()) {
            return Err(Error::usage(format!(
                "{} appears twice in the files to publish",
                file.path
            )));
        }
    }
    Ok(out)
}

pub fn push(client: &Client, req: Request<'_>) -> Result<Value> {
    if !KINDS.contains(&req.kind) {
        return Err(Error::usage(format!(
            "kind must be one of {}",
            KINDS.join(", ")
        )));
    }
    if !req.skip_scan {
        scan(req.files, &req.meta)?;
    }

    let total: usize = req.files.iter().map(|f| f.bytes.len()).sum();
    let use_inline = req.force_inline || total <= MAX_INLINE_BYTES;
    if req.force_inline && total > MAX_INLINE_BYTES {
        return Err(Error::usage(format!(
            "inline upload is capped at {MAX_INLINE_BYTES} bytes; drop --inline"
        )));
    }

    if use_inline {
        return push_inline(client, &req);
    }
    push_three_step(client, &req)
}

fn push_inline(client: &Client, req: &Request<'_>) -> Result<Value> {
    let contents: Vec<Value> = req
        .files
        .iter()
        .map(|file| {
            json!({
                "path": file.path,
                "content_base64": BASE64.encode(&file.bytes),
                "content_type": file.content_type,
            })
        })
        .collect();
    let body = json!({
        "kind": req.kind,
        "slug": req.slug,
        "title": req.title,
        "meta": req.meta,
        "origin": req.origin,
        "contents": contents,
    });
    let res = client.post(
        &format!(
            "/v1/projects/{}/resources:inline",
            crate::client::encode_segment(req.project)
        ),
        &body,
    )?;
    Ok(annotate(res.body, res.status == 200, 0))
}

fn push_three_step(client: &Client, req: &Request<'_>) -> Result<Value> {
    let manifest_files: Vec<Value> = req
        .files
        .iter()
        .map(|file| {
            json!({
                "path": file.path,
                "sha256": sha256_hex(&file.bytes),
                "size": file.bytes.len(),
                "content_type": file.content_type,
            })
        })
        .collect();
    let body = json!({
        "kind": req.kind,
        "slug": req.slug,
        "title": req.title,
        "meta": req.meta,
        "origin": req.origin,
        "files": manifest_files,
    });
    let ack = client.post(
        &format!(
            "/v1/projects/{}/resources",
            crate::client::encode_segment(req.project)
        ),
        &body,
    )?;
    if ack.body.get("unchanged").and_then(Value::as_bool) == Some(true) {
        return Ok(annotate(ack.body, true, 0));
    }
    let revision_id = ack
        .body
        .get("revision_id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::usage("server opened no revision"))?
        .to_string();
    let missing = ack
        .body
        .get("missing")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut uploaded = 0usize;
    for digest in &missing {
        let digest = digest
            .as_str()
            .ok_or_else(|| Error::usage("server returned a non-string digest"))?;
        let file = req
            .files
            .iter()
            .find(|f| sha256_hex(&f.bytes) == digest)
            .ok_or_else(|| Error::usage(format!("server asked for unknown digest {digest}")))?;
        client.put_bytes(&format!("/v1/blobs/{digest}"), &file.bytes)?;
        uploaded += 1;
    }

    let committed = client.post(&format!("/v1/revisions/{revision_id}/commit"), &json!({}))?;
    Ok(annotate(committed.body, false, uploaded))
}

fn annotate(mut body: Value, unchanged: bool, uploaded: usize) -> Value {
    if let Value::Object(map) = &mut body {
        map.insert("uploaded".into(), json!(uploaded));
        map.entry("unchanged".to_string())
            .or_insert(json!(unchanged));
    }
    body
}

fn scan(files: &[LocalFile], meta: &Value) -> Result<()> {
    for file in files {
        if let Ok(text) = std::str::from_utf8(&file.bytes) {
            if let Some(hit) = scan_for_secrets(text) {
                return Err(Error::usage(format!(
                    "{} {hit} — review it, then re-run with --force",
                    file.path
                )));
            }
        }
    }
    if !meta.is_null() {
        if let Some(hit) = scan_for_secrets(&meta.to_string()) {
            return Err(Error::usage(format!(
                "meta {hit} — review it, then re-run with --force"
            )));
        }
    }
    Ok(())
}

/// Same shapes Krypton refuses to publish: a CLI that can push anything must
/// not become the easy way to leak a token that was sitting in a bundle.
fn scan_for_secrets(text: &str) -> Option<String> {
    for (number, line) in text.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        let hit = if line.contains("AKIA")
            && line.chars().filter(|c| c.is_ascii_uppercase()).count() >= 16
        {
            Some("looks like an AWS access key id")
        } else if lower.contains("-----begin") && lower.contains("private key") {
            Some("looks like a private key block")
        } else if has_prefixed_secret(line, &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"], 36) {
            Some("looks like a GitHub token")
        } else if has_prefixed_secret(line, &["xen_"], 20) {
            Some("looks like a Xenon API token")
        } else if has_prefixed_secret(line, &["sk-ant-", "sk-"], 24) {
            Some("looks like an API key")
        } else {
            None
        };
        if let Some(what) = hit {
            return Some(format!("line {}: {what}", number + 1));
        }
    }
    None
}

fn has_prefixed_secret(line: &str, prefixes: &[&str], min_len: usize) -> bool {
    for prefix in prefixes {
        let mut rest = line;
        while let Some(at) = rest.find(prefix) {
            let tail = &rest[at + prefix.len()..];
            let run = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .count();
            if prefix.len() + run >= min_len {
                return true;
            }
            rest = &rest[at + prefix.len()..];
        }
    }
    false
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<LocalFile>) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| Error::io(&format!("read {}", dir.display()), e))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let ft = entry
            .file_type()
            .map_err(|e| Error::io(&format!("stat {}", path.display()), e))?;
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            walk(&path, root, out)?;
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        validate_remote_path(&rel)?;
        let bytes =
            std::fs::read(&path).map_err(|e| Error::io(&format!("read {}", path.display()), e))?;
        out.push(LocalFile {
            content_type: content_type_for(&rel),
            path: rel,
            bytes,
        });
    }
    Ok(())
}

fn remote_path(path: &Path) -> Result<String> {
    if path.is_absolute() {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| Error::usage(format!("{} has no file name", path.display())))?;
        validate_remote_path(name)?;
        return Ok(name.to_string());
    }
    let remote = path.to_string_lossy().replace('\\', "/");
    let remote = remote.trim_start_matches("./");
    validate_remote_path(remote)?;
    Ok(remote.to_string())
}

fn validate_remote_path(path: &str) -> Result<()> {
    if path.is_empty() || path.starts_with('/') || path.contains('\0') {
        return Err(Error::usage(format!("{path} is not a valid bundle path")));
    }
    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(Error::usage(format!("{path} is not a valid bundle path")));
        }
    }
    Ok(())
}

pub fn content_type_for(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    let kind = if lower.ends_with(".md") {
        "text/markdown; charset=utf-8"
    } else if lower.ends_with(".html") || lower.ends_with(".htm") {
        "text/html; charset=utf-8"
    } else if lower.ends_with(".json") {
        "application/json"
    } else if lower.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if lower.ends_with(".js") || lower.ends_with(".mjs") {
        "text/javascript; charset=utf-8"
    } else if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower.ends_with(".gif") {
        "image/gif"
    } else if lower.ends_with(".svg") {
        "image/svg+xml"
    } else if lower.ends_with(".webp") {
        "image/webp"
    } else if lower.ends_with(".txt") || lower.ends_with(".log") {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    };
    kind.to_string()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn default_origin() -> Value {
    json!({
        "hostname": hostname(),
        "cli": "xen",
        "version": env!("CARGO_PKG_VERSION"),
    })
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn parse_json_object(raw: Option<&str>, fallback: Value) -> Result<Value> {
    match raw {
        None => Ok(fallback),
        Some(s) => {
            let value: Value = serde_json::from_str(s)?;
            if !value.is_object() && !value.is_null() {
                return Err(Error::usage("meta/origin must be a JSON object"));
            }
            Ok(value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_files_publish_under_their_basename() {
        let path = PathBuf::from("/tmp/notes/review.md");
        assert_eq!(remote_path(&path).unwrap(), "review.md");
    }

    #[test]
    fn parent_segments_are_rejected() {
        assert!(validate_remote_path("../secret").is_err());
        assert!(validate_remote_path("ok/../no").is_err());
        assert!(validate_remote_path("ok/file.md").is_ok());
    }

    #[test]
    fn xenon_tokens_are_caught_in_a_bundle() {
        let hit = scan_for_secrets("token = xen_abcdefghij_0123456789abcdef");
        assert!(hit.unwrap().contains("Xenon API token"));
    }
}
