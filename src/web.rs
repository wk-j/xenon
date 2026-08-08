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

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(index))
        .route("/login", get(login_page))
        .route("/register", get(register_page))
        .route("/settings/tokens", get(tokens_page))
        .route("/p/{project}", get(project_page))
        .route("/r/{project}/{kind}/{*slug}", get(resource_page))
}

/// Every page is rendered through here. `page_script` names an asset in
/// `assets/` (not inline source) so the browse UI has no inline `<script>` left
/// — which is what makes a real Content-Security-Policy possible later.
fn shell(title: &str, body: &str) -> Html<String> {
    shell_with(title, body, None)
}

fn shell_with(title: &str, body: &str, page_script: Option<&str>) -> Html<String> {
    Html(format!(
        r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{title} · xenon</title>
<link rel="stylesheet" href="{css}">
<script src="{app_js}" defer></script>{page_script}
</head><body><div class="wrap">
<header class="top"><h1>xenon</h1>
<nav>
  <a href="/">projects</a>
  <a href="/settings/tokens">tokens</a>
  <a href="/login">sign in</a>
</nav></header>
{body}
</div></body></html>"#,
        title = escape(title),
        css = assets::url("app.css"),
        app_js = assets::url("app.js"),
        page_script = script_tag(page_script),
    ))
}

fn script_tag(page_script: Option<&str>) -> String {
    match page_script {
        Some(name) => format!("\n<script src=\"{}\" defer></script>", assets::url(name)),
        None => String::new(),
    }
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

    let body = if rows.is_empty() {
        let hint = if actor.is_some() {
            "no projects yet — push one from krypton with #push"
        } else {
            "no public projects — sign in to see your own"
        };
        format!("<p class=\"empty\">{hint}</p>")
    } else {
        let cards = rows
            .iter()
            .map(|(slug, is_public, count)| {
                format!(
                    r#"<div class="card"><h3><a href="/p/{slug_attr}">{slug}</a></h3>
<div class="meta">{count} resource{plural} · {visibility}</div></div>"#,
                    slug_attr = escape(slug),
                    slug = escape(slug),
                    plural = if *count == 1 { "" } else { "s" },
                    visibility = if *is_public { "public" } else { "private" },
                )
            })
            .collect::<String>();
        format!("<div class=\"grid\">{cards}</div>")
    };
    Ok(shell("projects", &body))
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

    let mut tabs = format!(
        "<a href=\"/p/{p}\" class=\"{on}\">all</a>",
        p = escape(&project),
        on = if kind_filter.is_none() { "on" } else { "" }
    );
    for kind in RESOURCE_KINDS {
        tabs.push_str(&format!(
            "<a href=\"/p/{p}?kind={kind}\" class=\"{on}\">{kind}</a>",
            p = escape(&project),
            on = if kind_filter == Some(kind) { "on" } else { "" }
        ));
    }

    let list = if rows.is_empty() {
        "<p class=\"empty\">nothing published here yet</p>".to_string()
    } else {
        let cards = rows
            .iter()
            .map(|(kind, slug, title, updated, revisions)| {
                format!(
                    r#"<div class="card"><h3><a href="/r/{p}/{kind}/{slug_attr}">{title}</a></h3>
<div class="meta"><span class="pill k">{kind}</span> {slug} · {revisions} rev · updated {updated}</div></div>"#,
                    p = escape(&project),
                    kind = escape(kind),
                    slug_attr = escape(slug),
                    slug = escape(slug),
                    title = escape(title),
                    revisions = revisions,
                    updated = updated,
                )
            })
            .collect::<String>();
        format!("<div class=\"grid\">{cards}</div>")
    };

    let body = format!(
        "<h2 class=\"meta\">{}</h2><div class=\"kinds\">{tabs}</div>{list}",
        escape(&project)
    );
    Ok(shell(&project, &body))
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

    let Some(revision) = detail.revision else {
        return Ok(shell(
            &detail.summary.title,
            "<p class=\"empty\">no committed revision</p>",
        ));
    };

    let selected = query
        .file
        .as_deref()
        .and_then(|want| revision.files.iter().find(|f| f.path == want))
        .or_else(|| revision.files.first());

    let strip = if revision.files.len() > 1 {
        let items = revision
            .files
            .iter()
            .map(|f| {
                format!(
                    "<li><a class=\"{on}\" href=\"?file={path_attr}\">{path}</a></li>",
                    on = if selected.is_some_and(|s| s.path == f.path) {
                        "on"
                    } else {
                        ""
                    },
                    path_attr = escape(&urlencode(&f.path)),
                    path = escape(&f.path),
                )
            })
            .collect::<String>();
        format!("<ul class=\"files\">{items}</ul>")
    } else {
        String::new()
    };

    let content = match selected {
        None => "<p class=\"empty\">this revision has no files</p>".to_string(),
        Some(file) => render_file(&state, &revision.id, &file.path, &file.content_type)?,
    };

    let meta_line = format!(
        "<div class=\"meta\"><span class=\"pill k\">{kind}</span> {slug} · revision {seq} of {total}{pinned}</div>",
        kind = escape(&detail.summary.kind),
        slug = escape(&detail.summary.slug),
        seq = revision.seq,
        total = detail.summary.revisions,
        pinned = if seq.is_some() { " · pinned" } else { "" },
    );

    let body = format!(
        "<p class=\"meta\"><a href=\"/p/{p}\">{p}</a></p><h2>{title}</h2>{meta_line}<div style=\"height:14px\"></div>{strip}{content}",
        p = escape(&project),
        title = escape(&detail.summary.title),
    );
    Ok(shell(&detail.summary.title, &body))
}

fn render_file(
    state: &AppState,
    revision_id: &str,
    path: &str,
    content_type: &str,
) -> AppResult<String> {
    let src = format!("/v1/revisions/{}/files/{}", revision_id, urlencode(path));

    // HTML artifacts are agent-authored and must never run with this origin's
    // authority — they are framed sandboxed, with no same-origin token.
    if content_type.contains("html") || path.ends_with(".html") {
        return Ok(format!(
            "<iframe class=\"artifact\" sandbox=\"allow-scripts\" referrerpolicy=\"no-referrer\" src=\"{}\"></iframe>",
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

async fn login_page() -> Html<String> {
    shell_with(
        "sign in",
        r#"<h2>sign in</h2>
<form class="auth" id="f">
  <label for="email">email</label><input id="email" type="email" autocomplete="username" required>
  <label for="password">password</label>
  <input id="password" type="password" autocomplete="current-password" required>
  <button type="submit">sign in</button>
  <p class="msg" id="m"></p>
  <p class="meta">no account yet? <a href="/register">register</a></p>
</form>
"#,
        Some("login.js"),
    )
}

async fn register_page() -> Html<String> {
    shell_with(
        "register",
        r#"<h2>register</h2>
<p class="meta">the first account on a fresh instance becomes the admin and needs no invite.</p>
<form class="auth" id="f">
  <label for="email">email</label><input id="email" type="email" autocomplete="username" required>
  <label for="display_name">display name</label><input id="display_name" type="text">
  <label for="password">password (12+ characters)</label>
  <input id="password" type="password" autocomplete="new-password" minlength="12" required>
  <label for="invite">invite code (leave blank if you are the first user)</label>
  <input id="invite" type="text">
  <button type="submit">create account</button>
  <p class="msg" id="m"></p>
</form>
"#,
        Some("register.js"),
    )
}

async fn tokens_page() -> Html<String> {
    shell_with(
        "tokens",
        r#"<h2>api tokens</h2>
<p class="meta">mint one token per client. the secret is shown once, here, and never again —
copy it straight into krypton or your integration.</p>
<form class="auth" id="f">
  <label for="label">label</label>
  <input id="label" type="text" placeholder="krypton on this laptop" required>
  <label>scopes</label>
  <div class="scopes">
    <label><input type="checkbox" value="resource:write" checked> resource:write</label>
    <label><input type="checkbox" value="resource:read" checked> resource:read</label>
    <label><input type="checkbox" value="project:admin"> project:admin</label>
  </div>
  <label for="project">restrict to project (optional)</label>
  <input id="project" type="text" placeholder="all of your projects">
  <label for="days">expires in days (optional)</label><input id="days" type="number" min="1">
  <button type="submit">create token</button>
  <p class="msg" id="m"></p>
</form>
<div id="secret"></div>
<h3 class="meta">active tokens</h3>
<table class="data"><thead><tr>
<th>id</th><th>label</th><th>scopes</th><th>project</th><th>last used</th><th></th>
</tr></thead><tbody id="rows"></tbody></table>
<p class="empty" id="none" hidden>no active tokens</p>
"#,
        Some("tokens.js"),
    )
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
