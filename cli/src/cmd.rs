// One handler per subcommand. Each either pretty-prints or dumps JSON.

use crate::client::{encode_file_path, encode_segment, Client};
use crate::config::Settings;
use crate::error::{Error, Result};
use crate::out;
use crate::push;
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;

pub fn health(settings: &Settings) -> Result<()> {
    let body = Client::with_any(&settings.url, None, None)?.health()?;
    if settings.json {
        out::json(&json!({ "ok": body == "ok", "body": body }));
    } else {
        println!("{body}");
    }
    if body != "ok" {
        return Err(Error::usage(format!("unexpected /healthz body: {body}")));
    }
    Ok(())
}

pub fn register(
    settings: &mut Settings,
    email: String,
    password: Option<String>,
    name: Option<String>,
    invite: Option<String>,
) -> Result<()> {
    let password = read_password(password)?;
    let mut body = json!({ "email": email, "password": password });
    if let Some(name) = name {
        body["display_name"] = json!(name);
    }
    if let Some(invite) = invite {
        body["invite"] = json!(invite);
    }
    let client = Client::with_any(&settings.url, None, None)?;
    let res = client.post("/v1/auth/register", &body)?;
    let session = res
        .session
        .ok_or_else(|| Error::usage("server registered the account but sent no session cookie"))?;
    settings.persist_session(session);
    settings.save()?;
    emit(settings, &res.body, || print_user(&res.body))
}

pub fn login(settings: &mut Settings, email: String, password: Option<String>) -> Result<()> {
    let password = read_password(password)?;
    let client = Client::with_any(&settings.url, None, None)?;
    let res = client.post(
        "/v1/auth/login",
        &json!({ "email": email, "password": password }),
    )?;
    let session = res
        .session
        .ok_or_else(|| Error::usage("server accepted the login but sent no session cookie"))?;
    settings.persist_session(session);
    settings.save()?;
    emit(settings, &res.body, || print_user(&res.body))
}

pub fn logout(settings: &mut Settings) -> Result<()> {
    if settings.session.is_some() {
        let client = Client::with_session(&settings.url, settings.session.clone())?;
        // A dead session is still a successful local logout.
        let _ = client.post("/v1/auth/logout", &json!({}));
    }
    settings.clear_session();
    settings.save()?;
    if settings.json {
        out::json(&json!({ "ok": true }));
    } else {
        println!("signed out");
    }
    Ok(())
}

pub fn me(settings: &Settings) -> Result<()> {
    let client = Client::with_any(
        &settings.url,
        settings.token.clone(),
        settings.session.clone(),
    )?;
    let body = client.get("/v1/me")?;
    emit(settings, &body, || {
        if let Some(user) = body.get("user") {
            print_user(user);
        }
        if let Some(projects) = body.get("projects").and_then(Value::as_array) {
            println!();
            out::table(
                &["project", "public", "created"],
                &projects
                    .iter()
                    .map(|p| {
                        vec![
                            out::text(p, "slug"),
                            out::bool_field(p, "is_public"),
                            out::ts_field(p, "created_at"),
                        ]
                    })
                    .collect::<Vec<_>>(),
            );
        }
        if let Some(tokens) = body.get("tokens").and_then(Value::as_array) {
            println!();
            print_tokens(tokens);
        }
    })
}

pub fn invite(settings: &Settings) -> Result<()> {
    let client = Client::with_session(&settings.url, settings.session.clone())?;
    let res = client.post("/v1/invites", &json!({}))?;
    emit(settings, &res.body, || {
        out::kv(&[
            ("code", out::text(&res.body, "code")),
            ("expires", out::ts_field(&res.body, "expires_at")),
        ]);
    })
}

pub fn token_create(
    settings: &mut Settings,
    label: String,
    scopes: Vec<String>,
    project: Option<String>,
    expires_in_days: Option<i64>,
    save: bool,
) -> Result<()> {
    let scopes = if scopes.is_empty() {
        vec!["resource:read".to_string(), "resource:write".to_string()]
    } else {
        scopes
    };
    let mut body = json!({ "label": label, "scopes": scopes });
    if let Some(project) = project {
        body["project"] = json!(project);
    }
    if let Some(days) = expires_in_days {
        body["expires_in_days"] = json!(days);
    }
    let client = Client::with_session(&settings.url, settings.session.clone())?;
    let res = client.post("/v1/tokens", &body)?;
    if save {
        if let Some(token) = res.body.get("token").and_then(Value::as_str) {
            settings.persist_token(token.to_string());
            settings.save()?;
        }
    }
    emit(settings, &res.body, || {
        println!("token (shown once): {}", out::text(&res.body, "token"));
        out::kv(&[
            ("id", out::text(&res.body, "id")),
            ("scopes", scopes_field(&res.body)),
            ("project", out::opt_text(&res.body, "project")),
            ("expires", out::ts_field(&res.body, "expires_at")),
        ]);
        if save {
            println!("saved to {}", settings.path.display());
        }
    })
}

pub fn token_list(settings: &Settings) -> Result<()> {
    let client = Client::with_session(&settings.url, settings.session.clone())?;
    let body = client.get("/v1/tokens")?;
    emit(settings, &body, || {
        print_tokens(body.as_array().map(|a| a.as_slice()).unwrap_or(&[]));
    })
}

pub fn token_revoke(settings: &Settings, id: String) -> Result<()> {
    let client = Client::with_session(&settings.url, settings.session.clone())?;
    client.delete(&format!("/v1/tokens/{}", encode_segment(&id)))?;
    if settings.json {
        out::json(&json!({ "ok": true, "id": id }));
    } else {
        println!("revoked {id}");
    }
    Ok(())
}

pub fn token_set(settings: &mut Settings, token: String) -> Result<()> {
    settings.persist_token(token);
    settings.save()?;
    if settings.json {
        out::json(&json!({ "ok": true, "path": settings.path }));
    } else {
        println!("token saved to {}", settings.path.display());
    }
    Ok(())
}

pub fn token_unset(settings: &mut Settings) -> Result<()> {
    settings.clear_token();
    settings.save()?;
    if settings.json {
        out::json(&json!({ "ok": true }));
    } else {
        println!("stored token cleared");
    }
    Ok(())
}

pub fn project_list(settings: &Settings) -> Result<()> {
    let client = Client::with_any(
        &settings.url,
        settings.token.clone(),
        settings.session.clone(),
    )?;
    let body = client.get("/v1/projects")?;
    emit(settings, &body, || {
        let empty = Vec::new();
        let rows = body
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .map(|p| {
                vec![
                    out::text(p, "slug"),
                    out::bool_field(p, "is_public"),
                    out::i64_field(p, "resources"),
                    out::opt_text(p, "github_repo"),
                    out::ts_field(p, "created_at"),
                ]
            })
            .collect::<Vec<_>>();
        out::table(
            &["project", "public", "resources", "github", "created"],
            &rows,
        );
    })
}

pub fn project_set(
    settings: &Settings,
    slug: String,
    github_repo: Option<String>,
    clear_github_repo: bool,
) -> Result<()> {
    if github_repo.is_none() && !clear_github_repo {
        return Err(Error::usage(
            "pass --github-repo owner/repo or --clear-github-repo",
        ));
    }
    let body = if clear_github_repo {
        json!({ "github_repo": null })
    } else {
        json!({ "github_repo": github_repo })
    };
    // Prefer the session: this is an owner setting, and a typical resource
    // token does not carry `project:admin`.
    let client = if settings.session.is_some() {
        Client::with_session(&settings.url, settings.session.clone())?
    } else {
        Client::with_any(&settings.url, settings.token.clone(), None)?
    };
    let body = client.patch(&format!("/v1/projects/{}", encode_segment(&slug)), &body)?;
    emit(settings, &body, || {
        out::kv(&[
            ("project", out::text(&body, "slug")),
            ("public", out::bool_field(&body, "is_public")),
            ("github", out::opt_text(&body, "github_repo")),
        ]);
    })
}

pub fn resource_list(
    settings: &Settings,
    project: String,
    kind: Option<String>,
    since: Option<i64>,
    limit: Option<i64>,
) -> Result<()> {
    let mut q = vec![];
    if let Some(kind) = &kind {
        q.push(format!("kind={}", encode_segment(kind)));
    }
    if let Some(since) = since {
        q.push(format!("since={since}"));
    }
    if let Some(limit) = limit {
        q.push(format!("limit={limit}"));
    }
    let qs = if q.is_empty() {
        String::new()
    } else {
        format!("?{}", q.join("&"))
    };
    let client = Client::with_any(
        &settings.url,
        settings.token.clone(),
        settings.session.clone(),
    )?;
    let body = client.get(&format!(
        "/v1/projects/{}/resources{qs}",
        encode_segment(&project)
    ))?;
    emit(settings, &body, || {
        let empty = Vec::new();
        let rows = body
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .map(|r| {
                vec![
                    out::text(r, "id"),
                    out::text(r, "kind"),
                    out::text(r, "slug"),
                    out::text(r, "title"),
                    out::i64_field(r, "revisions"),
                    out::ts_field(r, "updated_at"),
                ]
            })
            .collect::<Vec<_>>();
        out::table(&["id", "kind", "slug", "title", "revs", "updated"], &rows);
    })
}

pub fn resource_show(settings: &Settings, locator: Vec<String>, seq: Option<i64>) -> Result<()> {
    let id = resolve_resource_id(settings, &locator)?;
    let mut path = format!("/v1/resources/{}", encode_segment(&id));
    if let Some(seq) = seq {
        path.push_str(&format!("?seq={seq}"));
    }
    let client = Client::with_any(
        &settings.url,
        settings.token.clone(),
        settings.session.clone(),
    )?;
    let body = client.get(&path)?;
    emit(settings, &body, || print_resource(&body))
}

pub fn resource_revisions(settings: &Settings, locator: Vec<String>) -> Result<()> {
    let id = resolve_resource_id(settings, &locator)?;
    let client = Client::with_any(
        &settings.url,
        settings.token.clone(),
        settings.session.clone(),
    )?;
    let body = client.get(&format!("/v1/resources/{}/revisions", encode_segment(&id)))?;
    emit(settings, &body, || {
        let empty = Vec::new();
        let rows = body
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .map(|r| {
                vec![
                    out::i64_field(r, "seq"),
                    out::text(r, "id"),
                    out::ts_field(r, "sealed_at"),
                    author_field(r.get("author")),
                ]
            })
            .collect::<Vec<_>>();
        out::table(&["seq", "id", "sealed", "author"], &rows);
    })
}

pub fn file_get(
    settings: &Settings,
    revision: String,
    path: String,
    output: Option<PathBuf>,
) -> Result<()> {
    let client = Client::with_any(
        &settings.url,
        settings.token.clone(),
        settings.session.clone(),
    )?;
    let bytes = client.get_bytes(&format!(
        "/v1/revisions/{}/files/{}",
        encode_segment(&revision),
        encode_file_path(&path)
    ))?;
    match output {
        Some(dest) => {
            if let Some(dir) = dest.parent() {
                if !dir.as_os_str().is_empty() {
                    std::fs::create_dir_all(dir)?;
                }
            }
            std::fs::write(&dest, &bytes)?;
            if settings.json {
                out::json(&json!({ "ok": true, "bytes": bytes.len(), "path": dest }));
            } else {
                println!("wrote {} ({} bytes)", dest.display(), bytes.len());
            }
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&bytes)?;
        }
    }
    Ok(())
}

pub struct PushOpts {
    pub project: String,
    pub kind: String,
    pub slug: String,
    pub title: String,
    pub files: Vec<PathBuf>,
    pub dirs: Vec<PathBuf>,
    pub stdin: bool,
    pub as_path: Option<String>,
    pub meta: Option<String>,
    pub origin: Option<String>,
    pub inline: bool,
    pub force: bool,
}

pub fn push(settings: &Settings, opts: PushOpts) -> Result<()> {
    let files = push::collect(&opts.files, &opts.dirs, opts.stdin, opts.as_path.as_deref())?;
    let meta = push::parse_json_object(opts.meta.as_deref(), json!({}))?;
    let origin = push::parse_json_object(opts.origin.as_deref(), push::default_origin())?;
    let client = Client::with_any(
        &settings.url,
        settings.token.clone(),
        settings.session.clone(),
    )?;
    let body = push::push(
        &client,
        push::Request {
            project: &opts.project,
            kind: &opts.kind,
            slug: &opts.slug,
            title: &opts.title,
            meta,
            origin,
            files: &files,
            force_inline: opts.inline,
            skip_scan: opts.force,
        },
    )?;
    emit(settings, &body, || {
        let unchanged = body.get("unchanged").and_then(Value::as_bool) == Some(true);
        let status = if unchanged { "unchanged" } else { "published" };
        out::kv(&[
            ("status", status.to_string()),
            ("url", out::opt_text(&body, "url")),
            ("resource", out::opt_text(&body, "resource_id")),
            ("revision", out::opt_text(&body, "revision_id")),
            ("seq", out::i64_field(&body, "seq")),
            ("uploaded", out::i64_field(&body, "uploaded")),
        ]);
    })
}

pub fn activity(
    settings: &Settings,
    project: Option<String>,
    kind: Option<String>,
    cursor: Option<i64>,
    limit: i64,
) -> Result<()> {
    let mut q = vec![format!("limit={limit}")];
    if let Some(project) = &project {
        q.push(format!("project={}", encode_segment(project)));
    }
    if let Some(kind) = &kind {
        q.push(format!("kind={}", encode_segment(kind)));
    }
    if let Some(cursor) = cursor {
        q.push(format!("cursor={cursor}"));
    }
    let client = Client::with_any(
        &settings.url,
        settings.token.clone(),
        settings.session.clone(),
    )?;
    let body = client.get(&format!("/v1/activity?{}", q.join("&")))?;
    emit(settings, &body, || {
        let events = body
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let rows = events
            .iter()
            .map(|e| {
                vec![
                    out::i64_field(e, "seq"),
                    out::text(e, "kind"),
                    out::opt_text(e, "actor"),
                    out::opt_text(e, "project"),
                    out::opt_text(e, "subject"),
                    out::ts_field(e, "created_at"),
                ]
            })
            .collect::<Vec<_>>();
        out::table(
            &["seq", "kind", "actor", "project", "subject", "when"],
            &rows,
        );
        if let Some(next) = body.get("next_cursor").and_then(Value::as_i64) {
            println!("next_cursor  {next}");
        }
    })
}

pub fn usage_show(
    settings: &Settings,
    project: String,
    from: Option<i64>,
    to: Option<i64>,
    group: String,
) -> Result<()> {
    let mut q = vec![format!("group={}", encode_segment(&group))];
    if let Some(from) = from {
        q.push(format!("from={from}"));
    }
    if let Some(to) = to {
        q.push(format!("to={to}"));
    }
    let client = Client::with_any(
        &settings.url,
        settings.token.clone(),
        settings.session.clone(),
    )?;
    let body = client.get(&format!(
        "/v1/projects/{}/usage?{}",
        encode_segment(&project),
        q.join("&")
    ))?;
    emit(settings, &body, || print_usage(&body))
}

pub fn usage_post(settings: &Settings, project: String, file: PathBuf) -> Result<()> {
    let raw = std::fs::read_to_string(&file)
        .map_err(|e| Error::io(&format!("read {}", file.display()), e))?;
    let parsed: Value = serde_json::from_str(&raw)?;
    let body = if parsed.get("turns").is_some() {
        parsed
    } else if parsed.is_array() {
        json!({ "turns": parsed })
    } else {
        return Err(Error::usage(
            "usage file must be { \"turns\": [...] } or a JSON array of turns",
        ));
    };
    let client = Client::with_any(
        &settings.url,
        settings.token.clone(),
        settings.session.clone(),
    )?;
    let res = client.post(
        &format!("/v1/projects/{}/usage/turns", encode_segment(&project)),
        &body,
    )?;
    emit(settings, &res.body, || {
        out::kv(&[
            ("accepted", out::i64_field(&res.body, "accepted")),
            ("duplicates", out::i64_field(&res.body, "duplicates")),
            (
                "rejected",
                res.body
                    .get("rejected")
                    .and_then(Value::as_array)
                    .map(|a| a.len().to_string())
                    .unwrap_or_else(|| "0".into()),
            ),
        ]);
    })
}

pub fn config_show(settings: &Settings) -> Result<()> {
    let token = match &settings.file.token {
        Some(t) if t.len() > 12 => format!("{}…{}", &t[..8], &t[t.len() - 4..]),
        Some(_) => "(set)".to_string(),
        None => "(unset)".to_string(),
    };
    let view = json!({
        "url": settings.url,
        "token": token,
        "session": if settings.session.is_some() { "set" } else { "unset" },
        "config": settings.path,
    });
    emit(settings, &view, || {
        out::kv(&[
            ("url", settings.url.clone()),
            ("token", token),
            (
                "session",
                if settings.session.is_some() {
                    "set".into()
                } else {
                    "unset".into()
                },
            ),
            ("config", settings.path.display().to_string()),
        ]);
    })
}

pub fn config_set_url(settings: &mut Settings, url: String) -> Result<()> {
    let url = url.trim_end_matches('/').to_string();
    settings.url = url.clone();
    settings.file.url = Some(url.clone());
    settings.save()?;
    if settings.json {
        out::json(&json!({ "ok": true, "url": url }));
    } else {
        println!("url {url}");
    }
    Ok(())
}

fn resolve_resource_id(settings: &Settings, locator: &[String]) -> Result<String> {
    match locator {
        [id] => Ok(id.clone()),
        [project, kind, slug] => {
            let client = Client::with_any(
                &settings.url,
                settings.token.clone(),
                settings.session.clone(),
            )?;
            let body = client.get(&format!(
                "/v1/projects/{}/resources?kind={}&limit=1000",
                encode_segment(project),
                encode_segment(kind)
            ))?;
            let found = body.as_array().and_then(|rows| {
                rows.iter()
                    .find(|r| r.get("slug").and_then(Value::as_str) == Some(slug.as_str()))
            });
            match found {
                Some(row) => row
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| Error::usage("resource listing had no id")),
                None => Err(Error::usage(format!(
                    "no {kind} named {slug} in project {project}"
                ))),
            }
        }
        _ => Err(Error::usage(
            "resource locator is <id> or <project> <kind> <slug>",
        )),
    }
}

fn print_user(user: &Value) {
    let admin = if user.get("is_admin").and_then(Value::as_bool) == Some(true) {
        "admin"
    } else {
        "user"
    };
    println!(
        "{}  {}  {admin}",
        out::text(user, "email"),
        out::text(user, "display_name")
    );
}

fn print_tokens(tokens: &[Value]) {
    let rows = tokens
        .iter()
        .map(|t| {
            vec![
                out::text(t, "id"),
                out::text(t, "label"),
                scopes_field(t),
                out::opt_text(t, "project"),
                out::ts_field(t, "expires_at"),
            ]
        })
        .collect::<Vec<_>>();
    out::table(&["id", "label", "scopes", "project", "expires"], &rows);
}

fn print_resource(body: &Value) {
    out::kv(&[
        ("id", out::text(body, "id")),
        ("project", out::text(body, "project")),
        ("kind", out::text(body, "kind")),
        ("slug", out::text(body, "slug")),
        ("title", out::text(body, "title")),
        ("revisions", out::i64_field(body, "revisions")),
        ("updated", out::ts_field(body, "updated_at")),
        ("last_author", author_field(body.get("last_author"))),
    ]);
    if let Some(rev) = body.get("revision") {
        println!();
        out::kv(&[
            ("revision", out::text(rev, "id")),
            ("seq", out::i64_field(rev, "seq")),
            ("sealed", out::ts_field(rev, "sealed_at")),
            ("author", author_field(rev.get("author"))),
        ]);
        if let Some(files) = rev.get("files").and_then(Value::as_array) {
            println!();
            let rows = files
                .iter()
                .map(|f| {
                    vec![
                        out::text(f, "path"),
                        out::i64_field(f, "size"),
                        out::text(f, "content_type"),
                        out::text(f, "sha256"),
                    ]
                })
                .collect::<Vec<_>>();
            out::table(&["path", "size", "type", "sha256"], &rows);
        }
    }
}

fn print_usage(body: &Value) {
    if let Some(totals) = body.get("totals") {
        out::kv(&[
            ("project", out::text(body, "project")),
            ("group", out::text(body, "group")),
            ("turns", out::i64_field(totals, "turns")),
            ("input", out::i64_field(totals, "inputTokens")),
            ("output", out::i64_field(totals, "outputTokens")),
            ("reported", out::opt_text(totals, "reportedCost")),
            ("estimated", out::opt_text(totals, "estimatedCost")),
        ]);
    }
    if let Some(buckets) = body.get("buckets").and_then(Value::as_array) {
        println!();
        let rows = buckets
            .iter()
            .map(|b| {
                vec![
                    out::opt_text(b, "key"),
                    out::i64_field(b, "turns"),
                    out::i64_field(b, "inputTokens"),
                    out::i64_field(b, "outputTokens"),
                    out::opt_text(b, "estimatedCost"),
                ]
            })
            .collect::<Vec<_>>();
        out::table(&["bucket", "turns", "input", "output", "estimated"], &rows);
    }
}

fn scopes_field(value: &Value) -> String {
    match value.get("scopes") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::String(s)) => s.clone(),
        _ => "-".to_string(),
    }
}

fn author_field(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return "-".to_string();
    };
    if value.is_null() {
        return "-".to_string();
    }
    let name = out::text(value, "name");
    match value.get("token_label").and_then(Value::as_str) {
        Some(label) if !label.is_empty() => {
            let revoked = if value.get("token_revoked").and_then(Value::as_bool) == Some(true) {
                " revoked"
            } else {
                ""
            };
            format!("{name} via {label}{revoked}")
        }
        _ => name,
    }
}

fn emit(settings: &Settings, body: &Value, human: impl FnOnce()) -> Result<()> {
    if settings.json {
        out::json(body);
    } else {
        human();
    }
    Ok(())
}

fn read_password(given: Option<String>) -> Result<String> {
    if let Some(password) = given {
        return Ok(password);
    }
    let password =
        rpassword::prompt_password("Password: ").map_err(|e| Error::io("read password", e))?;
    if password.is_empty() {
        return Err(Error::usage("password is required"));
    }
    Ok(password)
}
