// Xenon — the `/v1` ingest and read API.
//
// Upload is a three-step negotiation, borrowed from the OCI registry protocol
// and inverted so it costs one round trip instead of N:
//
//   1. POST a manifest  → the server answers with the digests it is MISSING
//   2. PUT those blobs  → only the bytes it does not already hold
//   3. POST commit      → the revision seals and becomes the resource's head
//
// A revision is invisible until `sealed_at` is set, so an interrupted or
// unauthorized push never exposes a half-uploaded resource.

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use axum::{Json, Router};
use data_encoding::BASE64;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::account::{assert_token_project, resolve_or_create_project};
use crate::auth::{self, Actor};
use crate::error::{AppError, AppResult};
use crate::event;
use crate::state::AppState;
use crate::util::{
    is_valid_digest, is_valid_file_path, is_valid_project_slug, is_valid_slug, new_id, now,
};

/// Resource kinds Krypton can publish. Anything else is rejected at the edge so
/// a typo cannot create a phantom kind that no browse surface renders.
pub const RESOURCE_KINDS: [&str; 5] = ["artifact", "review", "analysis", "doc", "attention"];

const MAX_FILES_PER_RESOURCE: usize = 512;
const MAX_TITLE_LEN: usize = 300;
const MAX_META_BYTES: usize = 256 * 1024;
const MAX_CONTENT_TYPE_LEN: usize = 128;
/// Cap for the single-shot inline route, which buffers base64 in memory.
pub const MAX_INLINE_BYTES: usize = 1024 * 1024;

pub fn routes(max_blob_bytes: usize) -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/projects", get(list_projects))
        .route("/v1/projects/{project}", patch(update_project))
        .route(
            "/v1/projects/{project}/resources",
            post(create_revision).get(list_resources),
        )
        .route(
            "/v1/projects/{project}/resources:inline",
            post(create_inline),
        )
        .route(
            "/v1/blobs/{sha256}",
            put(put_blob).layer(DefaultBodyLimit::max(max_blob_bytes)),
        )
        .route("/v1/revisions/{revision}/commit", post(commit_revision))
        .route("/v1/revisions/{revision}/files/{*path}", get(get_file))
        .route("/v1/resources/{id}", get(get_resource))
        .route("/v1/resources/{id}/revisions", get(list_revisions))
        .route("/v1/activity", get(list_activity))
}

// ------------------------------------------------------------------ payloads

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FileEntry {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    #[serde(default = "default_content_type")]
    pub content_type: String,
}

fn default_content_type() -> String {
    "application/octet-stream".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ResourceManifest {
    pub kind: String,
    pub slug: String,
    pub title: String,
    #[serde(default)]
    pub origin: serde_json::Value,
    #[serde(default)]
    pub meta: serde_json::Value,
    #[serde(default)]
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Serialize)]
pub struct ManifestAck {
    pub resource_id: String,
    pub revision_id: Option<String>,
    pub missing: Vec<String>,
    /// True when the head revision already holds exactly these files and meta.
    /// The client stops here without transferring a byte.
    pub unchanged: bool,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct InlineFile {
    pub path: String,
    /// Standard base64 of the file body.
    pub content_base64: String,
    #[serde(default = "default_content_type")]
    pub content_type: String,
}

#[derive(Debug, Deserialize)]
pub struct InlineRequest {
    #[serde(flatten)]
    pub manifest: InlineManifest,
    #[serde(default)]
    pub contents: Vec<InlineFile>,
}

#[derive(Debug, Deserialize)]
pub struct InlineManifest {
    pub kind: String,
    pub slug: String,
    pub title: String,
    #[serde(default)]
    pub origin: serde_json::Value,
    #[serde(default)]
    pub meta: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct CommitResponse {
    pub resource_id: String,
    pub revision_id: String,
    pub seq: i64,
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct ResourceSummary {
    pub id: String,
    pub kind: String,
    pub slug: String,
    pub title: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub revisions: i64,
}

#[derive(Debug, Serialize)]
pub struct ResourceDetail {
    #[serde(flatten)]
    pub summary: ResourceSummary,
    pub project: String,
    /// Who published the head revision, whichever revision is being read.
    pub last_author: Option<Author>,
    pub revision: Option<RevisionDetail>,
}

#[derive(Debug, Serialize)]
pub struct RevisionDetail {
    pub id: String,
    pub seq: i64,
    pub created_at: i64,
    pub sealed_at: Option<i64>,
    pub meta: serde_json::Value,
    pub origin: serde_json::Value,
    /// Who the server authenticated for this upload. `None` only when the
    /// account has since been deleted.
    pub author: Option<Author>,
    pub files: Vec<FileEntry>,
}

/// The verified half of an upload's identity. `origin` beside it is the
/// unverified half — whatever the client said about itself — and the two are
/// never merged.
///
/// Joined live rather than frozen into the row, which is the opposite of the
/// activity log: an event records what happened at a moment, while an item's
/// author is a pointer to an account that can be renamed. A rename should
/// follow the person's items and leave the history of what they did alone.
#[derive(Debug, Clone, Serialize)]
pub struct Author {
    pub name: String,
    /// How the human named the machine that pushed ("krypton on this laptop").
    /// `None` for a session-authenticated push and for pre-v3 rows.
    pub token_label: Option<String>,
    pub token_revoked: bool,
}

/// Resolve a revision's author. A missing user row is not an error: the item
/// still exists and still has a history, it just lost the name behind it.
pub fn load_author(
    conn: &Connection,
    author_id: Option<&str>,
    token_id: Option<&str>,
) -> AppResult<Option<Author>> {
    let Some(author_id) = author_id else {
        return Ok(None);
    };
    let name: Option<String> = conn
        .query_row(
            "SELECT display_name FROM user WHERE id = ?1",
            [author_id],
            |r| r.get(0),
        )
        .optional()?;
    let Some(name) = name else {
        return Ok(None);
    };

    // A revoked token still names itself: it says who pushed this *then*, and
    // hiding it would be deleting the part of the story that matters most.
    let token: Option<(String, Option<i64>)> = match token_id {
        None => None,
        Some(id) => conn
            .query_row(
                "SELECT label, revoked_at FROM token WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?,
    };

    Ok(Some(Author {
        name,
        token_label: token.as_ref().map(|(label, _)| label.clone()),
        token_revoked: token.is_some_and(|(_, revoked)| revoked.is_some()),
    }))
}

#[derive(Debug, Deserialize)]
pub struct ListResourcesQuery {
    pub kind: Option<String>,
    pub since: Option<i64>,
    pub limit: Option<i64>,
}

// -------------------------------------------------------------------- ingest

async fn create_revision(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(manifest): Json<ResourceManifest>,
) -> AppResult<(StatusCode, Json<ManifestAck>)> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;
    actor.require_scope(auth::SCOPE_RESOURCE_WRITE)?;

    let ack = open_revision(&state, &conn, &actor, &project, manifest)?;
    Ok((
        if ack.unchanged {
            StatusCode::OK
        } else {
            StatusCode::ACCEPTED
        },
        Json(ack),
    ))
}

/// Single-shot upload for small resources — an `attention` record carries no
/// files at all, and there is no point spending three round trips on it.
async fn create_inline(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(req): Json<InlineRequest>,
) -> AppResult<(StatusCode, Json<CommitResponse>)> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;
    actor.require_scope(auth::SCOPE_RESOURCE_WRITE)?;

    // Decode and hash first: nothing is written until every body is valid.
    let mut decoded: Vec<(InlineFile, Vec<u8>)> = Vec::new();
    let mut total = 0usize;
    for file in req.contents {
        let bytes = BASE64.decode(file.content_base64.as_bytes()).map_err(|_| {
            AppError::bad_request(
                "invalid_base64",
                format!("{} is not valid base64", file.path),
            )
        })?;
        total += bytes.len();
        if total > MAX_INLINE_BYTES {
            return Err(AppError::too_large(format!(
                "inline upload exceeds {MAX_INLINE_BYTES} bytes; use the manifest + blob flow"
            )));
        }
        decoded.push((file, bytes));
    }

    let files = decoded
        .iter()
        .map(|(file, bytes)| FileEntry {
            path: file.path.clone(),
            sha256: crate::util::sha256_hex(bytes),
            size: bytes.len() as u64,
            content_type: file.content_type.clone(),
        })
        .collect::<Vec<_>>();

    let manifest = ResourceManifest {
        kind: req.manifest.kind,
        slug: req.manifest.slug,
        title: req.manifest.title,
        origin: req.manifest.origin,
        meta: req.manifest.meta,
        files: files.clone(),
    };

    let ack = open_revision(&state, &conn, &actor, &project, manifest)?;
    let revision_id = match (&ack.revision_id, ack.unchanged) {
        // Nothing changed — report the existing head rather than sealing a
        // duplicate revision, so re-running a push is genuinely a no-op.
        (_, true) => {
            let (seq, id) = head_revision_of(&conn, &ack.resource_id)?;
            return Ok((
                StatusCode::OK,
                Json(CommitResponse {
                    resource_id: ack.resource_id,
                    revision_id: id,
                    seq,
                    url: ack.url,
                }),
            ));
        }
        (Some(id), false) => id.clone(),
        (None, false) => return Err(AppError::internal("manifest produced no revision")),
    };

    for (entry, (_, bytes)) in files.iter().zip(decoded.iter()) {
        store_blob(&state, &conn, &entry.sha256, bytes)?;
    }

    let committed = seal_revision(&state, &conn, &actor, &revision_id)?;
    Ok((StatusCode::CREATED, Json(committed)))
}

async fn put_blob(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(sha256): Path<String>,
    body: axum::body::Bytes,
) -> AppResult<StatusCode> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;
    actor.require_scope(auth::SCOPE_RESOURCE_WRITE)?;

    if body.len() as u64 > state.config.max_blob_bytes {
        return Err(AppError::too_large(format!(
            "blob exceeds the {} byte limit",
            state.config.max_blob_bytes
        )));
    }
    let existed = state.blobs.exists(&sha256);
    store_blob(&state, &conn, &sha256, &body)?;
    Ok(if existed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    })
}

async fn commit_revision(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(revision): Path<String>,
) -> AppResult<Json<CommitResponse>> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;
    actor.require_scope(auth::SCOPE_RESOURCE_WRITE)?;
    Ok(Json(seal_revision(&state, &conn, &actor, &revision)?))
}

// ---------------------------------------------------------------- ingest core

fn open_revision(
    state: &AppState,
    conn: &Connection,
    actor: &Actor,
    project_slug: &str,
    manifest: ResourceManifest,
) -> AppResult<ManifestAck> {
    validate_manifest(&manifest)?;
    if !is_valid_project_slug(project_slug) {
        return Err(AppError::bad_request(
            "invalid_project",
            "project must be a single path segment of letters, digits, '-', '_' or '.'",
        ));
    }
    let project_id = resolve_or_create_project(conn, actor, project_slug)?;

    let existing: Option<(String, Option<String>)> = conn
        .query_row(
            "SELECT id, head_revision FROM resource
             WHERE project_id = ?1 AND kind = ?2 AND slug = ?3",
            params![project_id, manifest.kind, manifest.slug],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;

    let meta_json = serde_json::to_string(&manifest.meta).map_err(|e| {
        AppError::bad_request("invalid_meta", format!("meta is not encodable: {e}"))
    })?;
    let origin_json =
        serde_json::to_string(&manifest.origin).unwrap_or_else(|_| "null".to_string());

    let (resource_id, head) = match existing {
        Some((id, head)) => {
            conn.execute(
                "UPDATE resource SET title = ?1, updated_at = ?2 WHERE id = ?3",
                params![manifest.title, now(), id],
            )?;
            (id, head)
        }
        None => {
            let id = new_id("res_").map_err(AppError::internal)?;
            conn.execute(
                "INSERT INTO resource (id, project_id, kind, slug, title, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                params![
                    id,
                    project_id,
                    manifest.kind,
                    manifest.slug,
                    manifest.title,
                    now()
                ],
            )?;
            (id, None)
        }
    };

    let url = resource_url(conn, &resource_id)?;

    // Short-circuit when the head revision already holds exactly this content.
    if let Some(head_id) = &head {
        if revision_matches(conn, head_id, &manifest.files, &meta_json)? {
            return Ok(ManifestAck {
                resource_id,
                revision_id: None,
                missing: Vec::new(),
                unchanged: true,
                url,
            });
        }
    }

    let seq: i64 = conn.query_row(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM revision WHERE resource_id = ?1",
        [&resource_id],
        |r| r.get(0),
    )?;
    let revision_id = new_id("rev_").map_err(AppError::internal)?;
    // Authorship is written here, where the row is created, rather than at seal
    // time: a revision that never seals still says who started it, which is the
    // first thing worth knowing about an upload that is stuck.
    conn.execute(
        "INSERT INTO revision
           (id, resource_id, seq, meta, origin, created_at, author_id, author_token_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            revision_id,
            resource_id,
            seq,
            meta_json,
            origin_json,
            now(),
            actor.user_id,
            actor.token_id(),
        ],
    )?;

    let mut missing = Vec::new();
    for file in &manifest.files {
        conn.execute(
            "INSERT INTO rev_file (revision_id, path, sha256, size, content_type)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                revision_id,
                file.path,
                file.sha256,
                file.size as i64,
                file.content_type
            ],
        )?;
        if !state.blobs.exists(&file.sha256) && !missing.contains(&file.sha256) {
            missing.push(file.sha256.clone());
        }
    }

    Ok(ManifestAck {
        resource_id,
        revision_id: Some(revision_id),
        missing,
        unchanged: false,
        url,
    })
}

fn seal_revision(
    state: &AppState,
    conn: &Connection,
    actor: &Actor,
    revision_id: &str,
) -> AppResult<CommitResponse> {
    let row: Option<(String, i64, Option<i64>, String, String)> = conn
        .query_row(
            "SELECT r.resource_id, r.seq, r.sealed_at, res.project_id, p.owner_id
             FROM revision r
             JOIN resource res ON res.id = r.resource_id
             JOIN project p ON p.id = res.project_id
             WHERE r.id = ?1",
            [revision_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;

    let Some((resource_id, seq, sealed_at, project_id, owner_id)) = row else {
        return Err(AppError::not_found("no such revision"));
    };
    if owner_id != actor.user_id {
        return Err(AppError::not_found("no such revision"));
    }
    assert_token_project(actor, &project_id)?;

    if sealed_at.is_some() {
        return Err(AppError::conflict(
            "already_committed",
            "this revision is already sealed",
        ));
    }

    // Every referenced blob must actually be on disk. Without this a client
    // could commit a manifest whose bytes never arrived, and the resource would
    // render as a set of broken files.
    let mut stmt = conn.prepare("SELECT DISTINCT sha256 FROM rev_file WHERE revision_id = ?1")?;
    let digests = stmt
        .query_map([revision_id], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let missing: Vec<String> = digests
        .into_iter()
        .filter(|d| !state.blobs.exists(d))
        .collect();
    if !missing.is_empty() {
        return Err(AppError::conflict(
            "missing_blobs",
            format!("{} blob(s) have not been uploaded", missing.len()),
        )
        .with_detail(serde_json::json!({ "missing": missing })));
    }

    let sealed = now();
    conn.execute(
        "UPDATE revision SET sealed_at = ?1 WHERE id = ?2",
        params![sealed, revision_id],
    )?;
    conn.execute(
        "UPDATE resource SET head_revision = ?1, updated_at = ?2 WHERE id = ?3",
        params![revision_id, sealed, resource_id],
    )?;

    // Sealing is the only moment a revision becomes visible, and both ingest
    // paths end here — so this one call site covers every publish there is.
    // `seq` tells first sight from a revision without a second query.
    let (kind, slug, title): (String, String, String) = conn.query_row(
        "SELECT kind, slug, title FROM resource WHERE id = ?1",
        [&resource_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let project_slug: String = conn.query_row(
        "SELECT slug FROM project WHERE id = ?1",
        [&project_id],
        |r| r.get(0),
    )?;
    let mut detail = serde_json::json!({ "kind": kind, "slug": slug, "seq": seq });
    if let Some(token_id) = actor.token_id() {
        // A lane pushes under its own token; the row is attributed to the human
        // who minted it, and says which token did the pushing.
        detail["token_id"] = serde_json::Value::String(token_id.to_string());
    }
    event::record_and_prune(
        state,
        conn,
        event::New::project_scoped(
            if seq <= 1 {
                event::RESOURCE_PUBLISH
            } else {
                event::RESOURCE_REVISE
            },
            &event::actor_name(conn, &actor.user_id),
            &title,
        )
        .by(actor)
        .in_project(&project_id, &project_slug)
        .about_resource(&resource_id)
        .detail(detail),
    )?;

    Ok(CommitResponse {
        resource_id: resource_id.clone(),
        revision_id: revision_id.to_string(),
        seq,
        url: resource_url(conn, &resource_id)?,
    })
}

fn store_blob(state: &AppState, conn: &Connection, sha256: &str, bytes: &[u8]) -> AppResult<()> {
    state.blobs.put(sha256, bytes)?;
    conn.execute(
        "INSERT OR IGNORE INTO blob (sha256, size, created_at) VALUES (?1, ?2, ?3)",
        params![sha256, bytes.len() as i64, now()],
    )?;
    Ok(())
}

/// True when `revision_id` holds exactly this path→digest set and this meta.
fn revision_matches(
    conn: &Connection,
    revision_id: &str,
    files: &[FileEntry],
    meta_json: &str,
) -> AppResult<bool> {
    let stored_meta: String = conn.query_row(
        "SELECT meta FROM revision WHERE id = ?1",
        [revision_id],
        |r| r.get(0),
    )?;
    if stored_meta != meta_json {
        return Ok(false);
    }

    let mut stmt =
        conn.prepare("SELECT path, sha256 FROM rev_file WHERE revision_id = ?1 ORDER BY path")?;
    let stored = stmt
        .query_map([revision_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut incoming: Vec<(String, String)> = files
        .iter()
        .map(|f| (f.path.clone(), f.sha256.clone()))
        .collect();
    incoming.sort();
    Ok(stored == incoming)
}

fn head_revision_of(conn: &Connection, resource_id: &str) -> AppResult<(i64, String)> {
    conn.query_row(
        "SELECT r.seq, r.id FROM revision r
         JOIN resource res ON res.head_revision = r.id
         WHERE res.id = ?1",
        [resource_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()?
    .ok_or_else(|| AppError::not_found("resource has no committed revision"))
}

fn validate_manifest(manifest: &ResourceManifest) -> AppResult<()> {
    if !RESOURCE_KINDS.contains(&manifest.kind.as_str()) {
        return Err(AppError::bad_request(
            "invalid_kind",
            format!("kind must be one of {}", RESOURCE_KINDS.join(", ")),
        ));
    }
    if !is_valid_slug(&manifest.slug) {
        return Err(AppError::bad_request(
            "invalid_slug",
            "malformed resource slug",
        ));
    }
    let title = manifest.title.trim();
    if title.is_empty() || title.chars().count() > MAX_TITLE_LEN {
        return Err(AppError::bad_request(
            "invalid_title",
            format!("title must be 1..={MAX_TITLE_LEN} characters"),
        ));
    }
    if manifest.files.len() > MAX_FILES_PER_RESOURCE {
        return Err(AppError::too_large(format!(
            "a resource may hold at most {MAX_FILES_PER_RESOURCE} files"
        )));
    }
    if serde_json::to_string(&manifest.meta)
        .map(|s| s.len())
        .unwrap_or(usize::MAX)
        > MAX_META_BYTES
    {
        return Err(AppError::too_large(format!(
            "meta exceeds {MAX_META_BYTES} bytes"
        )));
    }

    let mut seen = std::collections::HashSet::new();
    for file in &manifest.files {
        if !is_valid_file_path(&file.path) {
            return Err(AppError::bad_request(
                "invalid_file_path",
                format!("{} is not a valid bundle-relative path", file.path),
            ));
        }
        if !seen.insert(file.path.as_str()) {
            return Err(AppError::bad_request(
                "duplicate_file_path",
                format!("{} appears twice in the manifest", file.path),
            ));
        }
        if !is_valid_digest(&file.sha256) {
            return Err(AppError::bad_request(
                "invalid_digest",
                format!("{} has a malformed sha256", file.path),
            ));
        }
        if file.content_type.len() > MAX_CONTENT_TYPE_LEN
            || file.content_type.chars().any(|c| c.is_control())
        {
            return Err(AppError::bad_request(
                "invalid_content_type",
                format!("{} has an unusable content type", file.path),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------- read

async fn list_projects(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<serde_json::Value>>> {
    let conn = state.db();
    // Public is "any account on this instance", not the open internet. No
    // credential is therefore not a reader.
    let actor = auth::require_actor(&conn, &headers)?;

    // A signed-in caller sees every public project plus the ones they own.
    let mut stmt = conn.prepare(
        "SELECT p.slug, p.is_public, p.created_at, p.github_repo,
                (SELECT count(*) FROM resource r WHERE r.project_id = p.id)
         FROM project p
         WHERE p.is_public = 1 OR p.owner_id = ?1
         ORDER BY p.slug",
    )?;
    let owner = actor.user_id.clone();
    let rows = stmt
        .query_map([owner], |r| {
            Ok(serde_json::json!({
                "slug": r.get::<_, String>(0)?,
                "is_public": r.get::<_, i64>(1)? != 0,
                "created_at": r.get::<_, i64>(2)?,
                "github_repo": r.get::<_, Option<String>>(3)?,
                "resources": r.get::<_, i64>(4)?,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
pub struct UpdateProjectRequest {
    /// Set to `"owner/repo"` (or a github.com URL) to link, to `null` or `""`
    /// to unlink. Absent leaves it alone, so the route can grow more settings
    /// without every caller resending this one — hence the double Option.
    #[serde(default, deserialize_with = "double_option")]
    github_repo: Option<Option<String>>,
}

/// Distinguishes `{"github_repo": null}` (present, clear it) from `{}` (absent,
/// leave it) — serde flattens both to `None` without this.
fn double_option<'de, D>(d: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(d).map(Some)
}

/// `PATCH /v1/projects/{project}` — project settings. Today that is only the
/// GitHub repository the project's rendered pages link issue references to.
async fn update_project(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(req): Json<UpdateProjectRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;

    // Owner-only, and a non-owner is told "not found" rather than "forbidden"
    // so project names stay unenumerable (same stance as ingest).
    let project_id: String = conn
        .query_row(
            "SELECT id FROM project WHERE slug = ?1 AND owner_id = ?2",
            params![project, actor.user_id],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| AppError::not_found(format!("no project {project}")))?;
    actor.require_scope(auth::SCOPE_PROJECT_ADMIN)?;
    assert_token_project(&actor, &project_id)?;

    if let Some(value) = req.github_repo {
        let normalized = match value.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            None => None,
            Some(raw) => Some(crate::util::normalize_github_repo(raw).ok_or_else(|| {
                AppError::bad_request(
                    "invalid_github_repo",
                    "expected owner/repo or a https://github.com/owner/repo URL",
                )
            })?),
        };
        conn.execute(
            "UPDATE project SET github_repo = ?1 WHERE id = ?2",
            params![normalized, project_id],
        )?;
    }

    let (is_public, github_repo): (i64, Option<String>) = conn.query_row(
        "SELECT is_public, github_repo FROM project WHERE id = ?1",
        [&project_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(Json(serde_json::json!({
        "slug": project,
        "is_public": is_public != 0,
        "github_repo": github_repo,
    })))
}

#[derive(Deserialize)]
pub struct ActivityQuery {
    project: Option<String>,
    kind: Option<String>,
    /// Opaque keyset cursor from a previous response's `next_cursor`. Not a
    /// timestamp: a second holds several events, so seconds cannot page.
    cursor: Option<i64>,
    limit: Option<i64>,
}

/// The activity feed as JSON (spec `docs/03-activity-feed.md`). Same visibility
/// rules and same cursor as the `/activity` page, which reads through this
/// module rather than duplicating the query.
async fn list_activity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ActivityQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;

    if let Some(kind) = &query.kind {
        if !event::KINDS.contains(&kind.as_str()) {
            return Err(AppError::bad_request("invalid_kind", "unknown event kind"));
        }
    }

    let limit = query.limit.unwrap_or(event::DEFAULT_LIMIT);
    let events = event::query(
        &conn,
        Some(&actor),
        &event::Query {
            project: query.project.as_deref(),
            kind: query.kind.as_deref(),
            cursor: query.cursor,
            limit,
        },
    )?;

    // A full page means there may be more; a short one is the end. The cursor
    // is the last row's `seq`, so the caller never has to compute it.
    let next_cursor = (events.len() as i64 >= limit.clamp(1, event::MAX_LIMIT))
        .then(|| events.last().map(|e| e.seq))
        .flatten();

    Ok(Json(
        serde_json::json!({ "events": events, "next_cursor": next_cursor }),
    ))
}

async fn list_resources(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Query(query): Query<ListResourcesQuery>,
) -> AppResult<Json<Vec<ResourceSummary>>> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;
    let project_id = readable_project(&conn, Some(&actor), &project)?;

    if let Some(kind) = &query.kind {
        if !RESOURCE_KINDS.contains(&kind.as_str()) {
            return Err(AppError::bad_request(
                "invalid_kind",
                "unknown resource kind",
            ));
        }
    }
    let limit = query.limit.unwrap_or(200).clamp(1, 1000);

    let mut stmt = conn.prepare(
        "SELECT id, kind, slug, title, created_at, updated_at,
                (SELECT count(*) FROM revision v WHERE v.resource_id = resource.id
                                                   AND v.sealed_at IS NOT NULL)
         FROM resource
         WHERE project_id = ?1
           AND head_revision IS NOT NULL
           AND (?2 IS NULL OR kind = ?2)
           AND (?3 IS NULL OR updated_at >= ?3)
         ORDER BY updated_at DESC
         LIMIT ?4",
    )?;
    let rows = stmt
        .query_map(params![project_id, query.kind, query.since, limit], |r| {
            Ok(ResourceSummary {
                id: r.get(0)?,
                kind: r.get(1)?,
                slug: r.get(2)?,
                title: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
                revisions: r.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(rows))
}

#[derive(Debug, Deserialize)]
pub struct GetResourceQuery {
    /// Pin to a specific sealed revision. Omitted means the head.
    pub seq: Option<i64>,
}

async fn get_resource(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<GetResourceQuery>,
) -> AppResult<Json<ResourceDetail>> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;
    // `seq` used to be hardcoded to None here, so `?seq=1` was accepted and
    // silently ignored — a caller asking for an old revision got the newest one
    // and had no way to tell. The browse UI never hit it because it pins through
    // the `/@N` path segment instead.
    Ok(Json(load_resource_detail(
        &conn,
        Some(&actor),
        &id,
        query.seq,
    )?))
}

async fn list_revisions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<serde_json::Value>>> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;
    let (_, project_id) = resource_row(&conn, &id)?;
    assert_project_readable(&conn, Some(&actor), &project_id)?;

    // This list is exactly the "who changed this, when" view, so it carries the
    // author per row. The join is done per row rather than in SQL because the
    // token half needs its own lookup and a resource has a handful of revisions,
    // not thousands.
    let mut stmt = conn.prepare(
        "SELECT id, seq, created_at, sealed_at, origin, author_id, author_token_id
         FROM revision
         WHERE resource_id = ?1 AND sealed_at IS NOT NULL ORDER BY seq DESC",
    )?;
    let raw = stmt
        .query_map([&id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<String>>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut rows = Vec::with_capacity(raw.len());
    for (rev_id, seq, created_at, sealed_at, origin, author_id, token_id) in raw {
        rows.push(serde_json::json!({
            "id": rev_id,
            "seq": seq,
            "created_at": created_at,
            "sealed_at": sealed_at,
            "origin": serde_json::from_str::<serde_json::Value>(&origin)
                .unwrap_or(serde_json::Value::Null),
            "author": load_author(&conn, author_id.as_deref(), token_id.as_deref())?,
        }));
    }
    Ok(Json(rows))
}

async fn get_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((revision, path)): Path<(String, String)>,
) -> AppResult<Response> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;

    let row: Option<(String, String, String)> = conn
        .query_row(
            "SELECT f.sha256, f.content_type, res.project_id
             FROM rev_file f
             JOIN revision v ON v.id = f.revision_id
             JOIN resource res ON res.id = v.resource_id
             WHERE f.revision_id = ?1 AND f.path = ?2 AND v.sealed_at IS NOT NULL",
            params![revision, path],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((sha256, content_type, project_id)) = row else {
        return Err(AppError::not_found("no such file in that revision"));
    };
    assert_project_readable(&conn, Some(&actor), &project_id)?;
    drop(conn);

    let bytes = state.blobs.read(&sha256)?;

    // An HTML artifact is a complete page in its own right — its own header, its
    // own styling, its own scripts — so it is served as a top-level document and
    // opened in its own tab, NOT embedded in a frame. Wrapping a whole page
    // inside another page bought nothing but chrome inside chrome, a height it
    // could not report, and nested scrollbars.
    //
    // Isolation comes from the CSP `sandbox` directive instead, which applies
    // iframe-sandbox semantics to this response. Without `allow-same-origin` the
    // document loads into an OPAQUE origin: its scripts run (so the artifact
    // works as authored) but they cannot read this origin's cookies or storage,
    // which is the only thing the frame was ever protecting. Same guarantee,
    // none of the layout damage.
    let csp = if content_type.contains("html") || path.ends_with(".html") {
        "sandbox allow-scripts; base-uri 'none'; form-action 'none'"
    } else {
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
    };
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            // Uploaded bytes are untrusted content authored by an agent. Never
            // let the browser sniff a type, reach this origin, or leak the
            // referrer onward.
            (header::CACHE_CONTROL, "no-store".to_string()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (header::REFERRER_POLICY, "no-referrer".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp.to_string()),
        ],
        bytes,
    )
        .into_response())
}

// ------------------------------------------------------------- read helpers

pub fn resource_row(conn: &Connection, id: &str) -> AppResult<(String, String)> {
    conn.query_row(
        "SELECT id, project_id FROM resource WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()?
    .ok_or_else(|| AppError::not_found("no such resource"))
}

/// Resolves a project slug the caller is allowed to read, or 404s. A caller who
/// may not read a project is told it does not exist rather than that it is
/// forbidden, so project names are not enumerable.
pub fn readable_project(conn: &Connection, actor: Option<&Actor>, slug: &str) -> AppResult<String> {
    let row: Option<(String, i64, String)> = conn
        .query_row(
            "SELECT id, is_public, owner_id FROM project WHERE slug = ?1",
            [slug],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((id, is_public, owner_id)) = row else {
        return Err(AppError::not_found(format!("no project {slug}")));
    };
    check_read(actor, is_public != 0, &owner_id, &id)?;
    Ok(id)
}

pub fn assert_project_readable(
    conn: &Connection,
    actor: Option<&Actor>,
    project_id: &str,
) -> AppResult<()> {
    let (is_public, owner_id): (i64, String) = conn.query_row(
        "SELECT is_public, owner_id FROM project WHERE id = ?1",
        [project_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    check_read(actor, is_public != 0, &owner_id, project_id)
}

fn check_read(
    actor: Option<&Actor>,
    is_public: bool,
    owner_id: &str,
    project_id: &str,
) -> AppResult<()> {
    let Some(actor) = actor else {
        return Err(AppError::not_found("no such project"));
    };
    // Public means every account on this instance may read it. A visitor
    // with no credential is not an account, so they never take this path
    // (handlers refuse them first). The scope check is what stops a
    // write-only token from becoming a reader just because the project
    // was made public.
    if is_public {
        actor.require_scope(auth::SCOPE_RESOURCE_READ)?;
        return Ok(());
    }
    // A session-authenticated admin is looking after the instance, so a
    // private project they do not own is still a project they may open.
    // A token never gets this: the same user minting a Krypton token must
    // not quietly inherit a roster of everyone else's private work.
    if actor.is_admin && actor.is_session() {
        return Ok(());
    }
    if actor.user_id != owner_id {
        return Err(AppError::not_found("no such project"));
    }
    actor.require_scope(auth::SCOPE_RESOURCE_READ)?;
    assert_token_project(actor, project_id)
}

pub fn load_resource_detail(
    conn: &Connection,
    actor: Option<&Actor>,
    resource_id: &str,
    seq: Option<i64>,
) -> AppResult<ResourceDetail> {
    struct Row {
        id: String,
        kind: String,
        slug: String,
        title: String,
        created_at: i64,
        updated_at: i64,
        project: String,
        head: Option<String>,
    }

    let row = conn
        .query_row(
            "SELECT r.id, r.kind, r.slug, r.title, r.created_at, r.updated_at,
                    p.slug, r.head_revision
             FROM resource r JOIN project p ON p.id = r.project_id
             WHERE r.id = ?1",
            [resource_id],
            |r| {
                Ok(Row {
                    id: r.get(0)?,
                    kind: r.get(1)?,
                    slug: r.get(2)?,
                    title: r.get(3)?,
                    created_at: r.get(4)?,
                    updated_at: r.get(5)?,
                    project: r.get(6)?,
                    head: r.get(7)?,
                })
            },
        )
        .optional()?;
    let Some(Row {
        id,
        kind,
        slug,
        title,
        created_at,
        updated_at,
        project,
        head,
    }) = row
    else {
        return Err(AppError::not_found("no such resource"));
    };
    let (_, project_id) = resource_row(conn, &id)?;
    assert_project_readable(conn, actor, &project_id)?;

    // Who last touched the resource, whichever revision is being read. A caller
    // pinned to revision 1 still wants to know that revision 4 exists and who
    // made it, without fetching it.
    let last_author = match &head {
        None => None,
        Some(head_id) => {
            let (author_id, token_id): (Option<String>, Option<String>) = conn.query_row(
                "SELECT author_id, author_token_id FROM revision WHERE id = ?1",
                [head_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            load_author(conn, author_id.as_deref(), token_id.as_deref())?
        }
    };

    let revision_id = match seq {
        None => head,
        Some(seq) => conn
            .query_row(
                "SELECT id FROM revision
                 WHERE resource_id = ?1 AND seq = ?2 AND sealed_at IS NOT NULL",
                params![id, seq],
                |r| r.get::<_, String>(0),
            )
            .optional()?,
    };

    let revisions: i64 = conn.query_row(
        "SELECT count(*) FROM revision WHERE resource_id = ?1 AND sealed_at IS NOT NULL",
        [&id],
        |r| r.get(0),
    )?;

    let revision = match revision_id {
        None => None,
        Some(rev_id) => Some(load_revision(conn, &rev_id)?),
    };

    Ok(ResourceDetail {
        summary: ResourceSummary {
            id,
            kind,
            slug,
            title,
            created_at,
            updated_at,
            revisions,
        },
        project,
        last_author,
        revision,
    })
}

pub fn load_revision(conn: &Connection, revision_id: &str) -> AppResult<RevisionDetail> {
    #[allow(clippy::type_complexity)]
    let (seq, created_at, sealed_at, meta, origin, author_id, token_id): (
        i64,
        i64,
        Option<i64>,
        String,
        String,
        Option<String>,
        Option<String>,
    ) = conn
        .query_row(
            "SELECT seq, created_at, sealed_at, meta, origin, author_id, author_token_id
             FROM revision WHERE id = ?1",
            [revision_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| AppError::not_found("no such revision"))?;
    let author = load_author(conn, author_id.as_deref(), token_id.as_deref())?;

    let mut stmt = conn.prepare(
        "SELECT path, sha256, size, content_type FROM rev_file
         WHERE revision_id = ?1 ORDER BY path",
    )?;
    let files = stmt
        .query_map([revision_id], |r| {
            Ok(FileEntry {
                path: r.get(0)?,
                sha256: r.get(1)?,
                size: r.get::<_, i64>(2)? as u64,
                content_type: r.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(RevisionDetail {
        id: revision_id.to_string(),
        seq,
        created_at,
        sealed_at,
        meta: serde_json::from_str(&meta).unwrap_or(serde_json::Value::Null),
        origin: serde_json::from_str(&origin).unwrap_or(serde_json::Value::Null),
        author,
        files,
    })
}

fn resource_url(conn: &Connection, resource_id: &str) -> AppResult<String> {
    let (project, kind, slug): (String, String, String) = conn.query_row(
        "SELECT p.slug, r.kind, r.slug FROM resource r JOIN project p ON p.id = r.project_id
         WHERE r.id = ?1",
        [resource_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    Ok(format!("/r/{project}/{kind}/{slug}"))
}
