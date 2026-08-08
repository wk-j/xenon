// Xenon — the browser surface.
//
// Styling follows Krypton's DESIGN.binance.md so a resource looks identical
// whether it is read locally through Krypton's loopback surfaces or here, on
// the server. House rules that apply: data is mono / prose is sans, no nested
// cards, no left-accent rails, and paths keep their own case.

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rusqlite::OptionalExtension;
use serde::Deserialize;
use std::sync::Arc;

use crate::api::{load_resource_detail, readable_project, RESOURCE_KINDS};
use crate::assets;
use crate::auth::{self, Actor};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

// ─── templates ──────────────────────────────────────────────────────────────
//
// HTML lives in `templates/*.html`, not in this file. askama compiles each one
// into a checked Rust struct, so a typo in a field name is a build error rather
// than a blank spot in a rendered page, and every `{{ … }}` is escaped by
// default. `escape()` survives only for the few places that still hand-build a
// string.

#[derive(askama::Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    crumbs: Vec<Crumb>,
    signed_in: bool,
    projects: Vec<ProjectCard>,
}

/// One step of the breadcrumb. `href` is `None` for the current page — a link
/// to yourself looks live and goes nowhere.
#[derive(askama::Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    page_js_url: String,
    crumbs: Vec<Crumb>,
}

#[derive(askama::Template)]
#[template(path = "register.html")]
struct RegisterTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    page_js_url: String,
    crumbs: Vec<Crumb>,
}

#[derive(askama::Template)]
#[template(path = "tokens.html")]
struct TokensTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    page_js_url: String,
    crumbs: Vec<Crumb>,
}

struct Crumb {
    label: String,
    href: Option<String>,
}

#[derive(askama::Template)]
#[template(path = "project.html")]
struct ProjectTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    crumbs: Vec<Crumb>,
    project: String,
    kinds: &'static [&'static str],
    kind_filter: Option<String>,
    resources: Vec<ResourceCard>,
}

struct ResourceCard {
    kind: String,
    slug: String,
    title: String,
    revisions: i64,
    updated_at: i64,
}

#[derive(askama::Template)]
#[template(path = "resource.html")]
struct ResourceTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    crumbs: Vec<Crumb>,
    project: String,
    kind: String,
    slug: String,
    seq: i64,
    revisions: i64,
    pinned: bool,
    files: Vec<FileTab>,
    content: String,
}

struct FileTab {
    path: String,
    href: String,
    selected: bool,
}

struct ProjectCard {
    slug: String,
    is_public: bool,
    resource_count: i64,
}

/// The two asset URLs every page needs. Kept in one place so a template cannot
/// be added without them.
fn chrome(title: &str) -> (String, String, String) {
    (
        title.to_string(),
        assets::url("app.css"),
        assets::url("app.js"),
    )
}

fn render<T: askama::Template>(t: &T) -> AppResult<Html<String>> {
    t.render()
        .map(Html)
        .map_err(|e| AppError::internal(format!("render template: {e}")))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(index))
        .route("/login", get(login_page))
        .route("/register", get(register_page))
        .route("/settings/tokens", get(tokens_page))
        .route("/p/{project}", get(project_page))
        .route("/r/{project}/{kind}/{*slug}", get(resource_page))
}

pub fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn actor_of(state: &AppState, headers: &axum::http::HeaderMap) -> Option<Actor> {
    let conn = state.db();
    auth::authenticate(&conn, headers).ok().flatten()
}

// ------------------------------------------------------------------- pages

async fn index(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> AppResult<Html<String>> {
    let actor = actor_of(&state, &headers);
    let conn = state.db();
    let mut stmt = conn.prepare(
        "SELECT p.slug, p.is_public, (SELECT count(*) FROM resource r WHERE r.project_id = p.id)
         FROM project p WHERE p.is_public = 1 OR p.owner_id = ?1 ORDER BY p.slug",
    )?;
    let owner = actor
        .as_ref()
        .map(|a| a.user_id.clone())
        .unwrap_or_default();
    let rows = stmt
        .query_map([owner], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)? != 0,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let (title, css_url, app_js_url) = chrome("projects");
    render(&IndexTemplate {
        title,
        css_url,
        app_js_url,
        crumbs: Vec::new(),
        signed_in: actor.is_some(),
        projects: rows
            .into_iter()
            .map(|(slug, is_public, resource_count)| ProjectCard {
                slug,
                is_public,
                resource_count,
            })
            .collect(),
    })
}

#[derive(Deserialize)]
pub struct ProjectQuery {
    kind: Option<String>,
}

async fn project_page(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(project): Path<String>,
    Query(query): Query<ProjectQuery>,
) -> AppResult<Html<String>> {
    let actor = actor_of(&state, &headers);
    let conn = state.db();
    let project_id = readable_project(&conn, actor.as_ref(), &project)?;

    let kind_filter = query.kind.as_deref().filter(|k| RESOURCE_KINDS.contains(k));
    let mut stmt = conn.prepare(
        "SELECT kind, slug, title, updated_at,
                (SELECT count(*) FROM revision v
                 WHERE v.resource_id = resource.id AND v.sealed_at IS NOT NULL)
         FROM resource WHERE project_id = ?1 AND head_revision IS NOT NULL
           AND (?2 IS NULL OR kind = ?2)
         ORDER BY updated_at DESC LIMIT 500",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![project_id, kind_filter], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let (title, css_url, app_js_url) = chrome(&project);
    render(&ProjectTemplate {
        title,
        css_url,
        app_js_url,
        crumbs: vec![
            Crumb {
                label: "projects".to_string(),
                href: Some("/".to_string()),
            },
            Crumb {
                label: project.clone(),
                href: None,
            },
        ],
        project: project.clone(),
        kinds: &RESOURCE_KINDS,
        kind_filter: kind_filter.map(|k| k.to_string()),
        resources: rows
            .into_iter()
            .map(|(kind, slug, title, updated_at, revisions)| ResourceCard {
                kind,
                slug,
                title,
                revisions,
                updated_at,
            })
            .collect(),
    })
}

#[derive(Deserialize)]
pub struct ResourceQuery {
    file: Option<String>,
}

async fn resource_page(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((project, kind, raw_slug)): Path<(String, String, String)>,
    Query(query): Query<ResourceQuery>,
) -> AppResult<Html<String>> {
    // `/r/<project>/<kind>/<slug>` and `/r/<project>/<kind>/<slug>/@<seq>` —
    // the pinned-revision permalink is a trailing segment so the slug itself
    // may still contain slashes (an analysis bundle is `owner/repo/number`).
    let (slug, seq) = match raw_slug.rsplit_once("/@") {
        Some((head, tail)) => match tail.parse::<i64>() {
            Ok(seq) => (head.to_string(), Some(seq)),
            Err(_) => (raw_slug.clone(), None),
        },
        None => (raw_slug.clone(), None),
    };

    let actor = actor_of(&state, &headers);
    let conn = state.db();
    let project_id = readable_project(&conn, actor.as_ref(), &project)?;

    let resource_id: String = conn
        .query_row(
            "SELECT id FROM resource WHERE project_id = ?1 AND kind = ?2 AND slug = ?3",
            rusqlite::params![project_id, kind, slug],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| AppError::not_found("no such resource"))?;

    let detail = load_resource_detail(&conn, actor.as_ref(), &resource_id, seq)?;
    drop(conn);

    let crumbs = vec![
        Crumb {
            label: "projects".to_string(),
            href: Some("/".to_string()),
        },
        Crumb {
            label: project.clone(),
            href: Some(format!("/p/{}", urlencode(&project))),
        },
        Crumb {
            label: detail.summary.title.clone(),
            href: None,
        },
    ];
    let (title, css_url, app_js_url) = chrome(&detail.summary.title);

    let Some(revision) = detail.revision else {
        return render(&ResourceTemplate {
            title,
            css_url,
            app_js_url,
            crumbs,
            project,
            kind: detail.summary.kind,
            slug: detail.summary.slug,
            seq: 0,
            revisions: 0,
            pinned: false,
            files: Vec::new(),
            content: "<p class=\"empty\">no committed revision</p>".to_string(),
        });
    };

    let selected = query
        .file
        .as_deref()
        .and_then(|want| revision.files.iter().find(|f| f.path == want))
        .or_else(|| revision.files.first());

    let content = match selected {
        None => "<p class=\"empty\">this revision has no files</p>".to_string(),
        Some(file) => render_file(&state, &revision.id, &file.path, &file.content_type)?,
    };

    let files = revision
        .files
        .iter()
        .map(|f| FileTab {
            path: f.path.clone(),
            href: urlencode(&f.path),
            selected: selected.is_some_and(|s| s.path == f.path),
        })
        .collect();

    render(&ResourceTemplate {
        title,
        css_url,
        app_js_url,
        crumbs,
        project,
        kind: detail.summary.kind,
        slug: detail.summary.slug,
        seq: revision.seq,
        revisions: detail.summary.revisions,
        pinned: seq.is_some(),
        files,
        content,
    })
}

fn render_file(
    state: &AppState,
    revision_id: &str,
    path: &str,
    content_type: &str,
) -> AppResult<String> {
    let src = format!("/v1/revisions/{}/files/{}", revision_id, urlencode(path));

    // An HTML artifact opens in its own tab rather than being embedded. It is a
    // complete page, and nesting one page inside another only produced chrome
    // inside chrome and a frame whose height this page could not know. Isolation
    // is carried by the CSP `sandbox` header on the file route (see api.rs
    // `get_file`), so the artifact still cannot reach this origin's cookies.
    if content_type.contains("html") || path.ends_with(".html") {
        return Ok(format!(
            "<p class=\"artifact-open\"><a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">open artifact \u{2197}</a></p>\
             <p class=\"meta\">opens in a new tab, sandboxed — it cannot read your session</p>",
            escape(&src)
        ));
    }
    if content_type.starts_with("image/") {
        return Ok(format!(
            "<p><img src=\"{}\" alt=\"{}\"></p>",
            escape(&src),
            escape(path)
        ));
    }
    if path.ends_with(".md") || content_type.contains("markdown") {
        let conn = state.db();
        let sha: Option<String> = conn
            .query_row(
                "SELECT sha256 FROM rev_file WHERE revision_id = ?1 AND path = ?2",
                rusqlite::params![revision_id, path],
                |r| r.get(0),
            )
            .optional()?;
        drop(conn);
        let Some(sha) = sha else {
            return Ok("<p class=\"empty\">file not found</p>".to_string());
        };
        let bytes = state.blobs.read(&sha)?;
        let text = String::from_utf8_lossy(&bytes);
        // A Review Board / analysis carries typed fences (```review:finding …)
        // that comrak renders as anonymous grey code blocks. The post-pass turns
        // the ones we know into semantic markup and leaves the rest alone, so a
        // Board read here shows what it shows inside Krypton.
        return Ok(format!(
            "<article class=\"doc\">{}</article>",
            crate::render::render_review_blocks(&markdown_to_html(&text))
        ));
    }
    Ok(format!(
        "<p class=\"meta\"><a href=\"{}\">download {}</a></p>",
        escape(&src),
        escape(path)
    ))
}

/// Renders markdown with raw HTML disabled. Bundle text is agent-authored and
/// therefore untrusted; comrak's `unsafe_` option stays off so an embedded
/// `<script>` renders as text instead of executing on this origin.
pub fn markdown_to_html(source: &str) -> String {
    let mut options = comrak::Options::default();
    options.extension.table = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    options.extension.front_matter_delimiter = Some("---".to_string());
    options.render.r#unsafe = false;
    comrak::markdown_to_html(source, &options)
}

fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// ------------------------------------------------------------- auth screens

async fn login_page() -> AppResult<Html<String>> {
    let (title, css_url, app_js_url) = chrome("sign in");
    render(&LoginTemplate {
        title,
        css_url,
        app_js_url,
        page_js_url: assets::url("login.js"),
        crumbs: Vec::new(),
    })
}

async fn register_page() -> AppResult<Html<String>> {
    let (title, css_url, app_js_url) = chrome("register");
    render(&RegisterTemplate {
        title,
        css_url,
        app_js_url,
        page_js_url: assets::url("register.js"),
        crumbs: Vec::new(),
    })
}

async fn tokens_page() -> AppResult<Html<String>> {
    let (title, css_url, app_js_url) = chrome("tokens");
    render(&TokensTemplate {
        title,
        css_url,
        app_js_url,
        page_js_url: assets::url("tokens.js"),
        crumbs: Vec::new(),
    })
}

/// Web pages answer an unauthenticated read with a redirect to sign-in rather
/// than a JSON error, so a bookmarked private URL lands somewhere useful.
pub fn redirect_to_login() -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, "/login")], ()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_neutralises_html() {
        assert_eq!(
            escape("<script>x</script>"),
            "&lt;script&gt;x&lt;/script&gt;"
        );
        assert_eq!(escape("a & b"), "a &amp; b");
        assert_eq!(escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn markdown_does_not_pass_through_raw_html() {
        let rendered = markdown_to_html("# hi\n\n<script>alert(1)</script>\n");
        assert!(rendered.contains("<h1>"));
        assert!(
            !rendered.contains("<script>"),
            "raw html must not survive rendering: {rendered}"
        );
    }

    #[test]
    fn markdown_renders_tables() {
        let rendered = markdown_to_html("| a | b |\n|---|---|\n| 1 | 2 |\n");
        assert!(
            rendered.contains("<table>"),
            "table extension should be on: {rendered}"
        );
    }

    #[test]
    fn urlencode_keeps_paths_readable_but_escapes_specials() {
        assert_eq!(urlencode("assets/diagram.png"), "assets/diagram.png");
        assert_eq!(urlencode("a b.md"), "a%20b.md");
        assert_eq!(urlencode("q?x=1"), "q%3Fx%3D1");
    }
}
