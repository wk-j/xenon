// End-to-end tests over the real router: registration, token minting, the
// three-step push protocol, and the authorization boundaries between them.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use xenon::config::Config;
use xenon::state::AppState;
use xenon::util::sha256_hex;
use xenon::{build_app, db};

struct Server {
    app: axum::Router,
    _dir: tempfile::TempDir,
}

struct Res {
    status: StatusCode,
    body: Value,
    set_cookie: Option<String>,
}

impl Res {
    fn s(&self, key: &str) -> String {
        self.body
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    }
}

impl Server {
    fn start() -> Self {
        Self::start_with(|_| {})
    }

    fn start_with(tweak: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::for_test(dir.path().to_path_buf());
        tweak(&mut config);
        let conn = db::open(&config.db_path()).unwrap();
        let state = AppState::new(config, conn).unwrap();
        Self {
            app: build_app(state),
            _dir: dir,
        }
    }

    async fn send(&self, req: Request<Body>) -> Res {
        let response = self.app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());
        let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Res {
            status,
            body,
            set_cookie,
        }
    }

    async fn post(&self, path: &str, auth: Option<&str>, body: Value) -> Res {
        let mut req = Request::post(path).header(header::CONTENT_TYPE, "application/json");
        req = apply_auth(req, auth);
        self.send(req.body(Body::from(body.to_string())).unwrap())
            .await
    }

    async fn get(&self, path: &str, auth: Option<&str>) -> Res {
        let mut req = Request::get(path);
        req = apply_auth(req, auth);
        self.send(req.body(Body::empty()).unwrap()).await
    }

    async fn patch(&self, path: &str, auth: Option<&str>, body: Value) -> Res {
        let mut req = Request::patch(path).header(header::CONTENT_TYPE, "application/json");
        req = apply_auth(req, auth);
        self.send(req.body(Body::from(body.to_string())).unwrap())
            .await
    }

    /// A browse-UI page as raw HTML. `send` parses JSON, which an HTML response
    /// is not, so the body has to be read separately here.
    async fn get_html(&self, path: &str, session: Option<&str>) -> (StatusCode, String) {
        let cookie = session.map(|s| format!("xenon_session={s}"));
        self.get_html_cookie(path, cookie.as_deref()).await
    }

    async fn get_html_cookie(&self, path: &str, cookie: Option<&str>) -> (StatusCode, String) {
        let mut req = Request::get(path);
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        let response = self
            .app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    /// A browse-UI page whose answer is a redirect: the interesting part is
    /// where it sends the reader, which `get_html` throws away.
    async fn get_location(&self, path: &str) -> (StatusCode, String) {
        self.get_location_cookie(path, None).await
    }

    async fn get_location_cookie(&self, path: &str, cookie: Option<&str>) -> (StatusCode, String) {
        let mut req = Request::get(path);
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        let response = self
            .app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        (response.status(), location)
    }

    /// A browse-UI form post. Unlike `post`, the interesting parts of the answer
    /// are the redirect target and the cookie it clears, not a JSON body.
    async fn post_web(&self, path: &str, session: Option<&str>) -> (StatusCode, String, String) {
        let cookie = session.map(|s| format!("xenon_session={s}"));
        self.post_web_form(path, cookie.as_deref(), "").await
    }

    async fn post_web_form(
        &self,
        path: &str,
        cookie: Option<&str>,
        form: &str,
    ) -> (StatusCode, String, String) {
        let mut req =
            Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        let response = self
            .app
            .clone()
            .oneshot(req.body(Body::from(form.to_string())).unwrap())
            .await
            .unwrap();
        let head = |name: header::HeaderName| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        (
            response.status(),
            head(header::LOCATION),
            head(header::SET_COOKIE),
        )
    }

    /// Raw body plus the Content-Security-Policy header, for the file route.
    async fn get_file_with_csp(&self, path: &str, token: &str) -> (StatusCode, String, String) {
        let req = Request::get(path).header(header::AUTHORIZATION, format!("Bearer {token}"));
        let response = self
            .app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let csp = response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        (status, csp, String::from_utf8_lossy(&bytes).to_string())
    }

    async fn put_blob(&self, digest: &str, auth: &str, bytes: &[u8]) -> Res {
        let mut req = Request::put(format!("/v1/blobs/{digest}"));
        req = apply_auth(req, Some(auth));
        self.send(req.body(Body::from(bytes.to_vec())).unwrap())
            .await
    }

    /// Registers the first (admin) account and returns its session cookie.
    async fn register_first(&self) -> String {
        let res = self
            .post(
                "/v1/auth/register",
                None,
                json!({ "email": "wk@example.com", "password": "correct horse battery" }),
            )
            .await;
        assert_eq!(res.status, StatusCode::CREATED, "register: {:?}", res.body);
        assert!(
            res.body["is_admin"].as_bool().unwrap(),
            "first account must be admin"
        );
        cookie_value(&res)
    }

    async fn mint_token(&self, session: &str, scopes: Value) -> String {
        let res = self
            .post(
                "/v1/tokens",
                Some(&session_header(session)),
                json!({ "label": "test", "scopes": scopes }),
            )
            .await;
        assert_eq!(
            res.status,
            StatusCode::CREATED,
            "mint token: {:?}",
            res.body
        );
        res.s("token")
    }
}

fn apply_auth(
    req: axum::http::request::Builder,
    auth: Option<&str>,
) -> axum::http::request::Builder {
    match auth {
        None => req,
        Some(value) if value.starts_with("cookie:") => {
            req.header(header::COOKIE, value.trim_start_matches("cookie:"))
        }
        Some(token) => req.header(header::AUTHORIZATION, format!("Bearer {token}")),
    }
}

fn session_header(cookie: &str) -> String {
    format!("cookie:xenon_session={cookie}")
}

fn cookie_value(res: &Res) -> String {
    let raw = res.set_cookie.as_ref().expect("a session cookie");
    raw.split(';')
        .next()
        .unwrap()
        .trim_start_matches("xenon_session=")
        .to_string()
}

fn manifest(files: Vec<(&str, &[u8])>) -> Value {
    json!({
        "kind": "review",
        "slug": "2026-08-07-peering-guard-rewrite",
        "title": "Peering guard rewrite",
        "origin": { "hostname": "laptop" },
        "meta": { "lane": "Claude-2" },
        "files": files.iter().map(|(path, bytes)| json!({
            "path": path,
            "sha256": sha256_hex(bytes),
            "size": bytes.len(),
            "content_type": "text/markdown",
        })).collect::<Vec<_>>(),
    })
}

// ------------------------------------------------------------ registration

#[tokio::test]
async fn first_account_is_admin_and_later_signups_are_closed() {
    let server = Server::start();
    server.register_first().await;

    let second = server
        .post(
            "/v1/auth/register",
            None,
            json!({ "email": "stranger@example.com", "password": "another long password" }),
        )
        .await;
    assert_eq!(second.status, StatusCode::FORBIDDEN);
    assert_eq!(second.s("error"), "signup_closed");
}

#[tokio::test]
async fn an_admin_invite_admits_exactly_one_account() {
    let server = Server::start();
    let session = server.register_first().await;

    let invite = server
        .post("/v1/invites", Some(&session_header(&session)), json!({}))
        .await;
    assert_eq!(invite.status, StatusCode::OK, "{:?}", invite.body);
    let code = invite.s("code");

    let joined = server
        .post(
            "/v1/auth/register",
            None,
            json!({ "email": "friend@example.com", "password": "a sufficiently long one",
                    "invite": code }),
        )
        .await;
    assert_eq!(joined.status, StatusCode::CREATED, "{:?}", joined.body);
    assert!(
        !joined.body["is_admin"].as_bool().unwrap(),
        "invited users are not admins"
    );

    // Single use: the same code cannot admit a second account.
    let reused = server
        .post(
            "/v1/auth/register",
            None,
            json!({ "email": "gatecrasher@example.com", "password": "yet another long one",
                    "invite": code }),
        )
        .await;
    assert_eq!(reused.status, StatusCode::FORBIDDEN);
    assert_eq!(reused.s("error"), "invalid_invite");
}

#[tokio::test]
async fn open_signup_flag_admits_without_an_invite() {
    let server = Server::start_with(|c| c.allow_signup = true);
    server.register_first().await;
    let second = server
        .post(
            "/v1/auth/register",
            None,
            json!({ "email": "stranger@example.com", "password": "another long password" }),
        )
        .await;
    assert_eq!(second.status, StatusCode::CREATED);
}

#[tokio::test]
async fn duplicate_email_is_not_an_account_existence_oracle() {
    let server = Server::start_with(|c| c.allow_signup = true);
    server.register_first().await;
    let dup = server
        .post(
            "/v1/auth/register",
            None,
            json!({ "email": "WK@Example.com", "password": "another long password" }),
        )
        .await;
    assert_eq!(dup.status, StatusCode::CONFLICT);
    let message = dup.s("message");
    assert!(
        !message.contains("exists"),
        "message must not confirm the account: {message}"
    );
    assert!(
        !message.contains("taken"),
        "message must not confirm the account: {message}"
    );
}

#[tokio::test]
async fn login_rejects_a_wrong_password_and_rate_limits_repeats() {
    let server = Server::start();
    server.register_first().await;

    for _ in 0..5 {
        let res = server
            .post(
                "/v1/auth/login",
                None,
                json!({ "email": "wk@example.com", "password": "nope" }),
            )
            .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED);
        assert_eq!(res.s("error"), "invalid_credentials");
    }
    let limited = server
        .post(
            "/v1/auth/login",
            None,
            json!({ "email": "wk@example.com", "password": "nope" }),
        )
        .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn logout_invalidates_the_session_immediately() {
    let server = Server::start();
    let session = server.register_first().await;
    assert_eq!(
        server
            .get("/v1/me", Some(&session_header(&session)))
            .await
            .status,
        StatusCode::OK
    );

    let out = server
        .post(
            "/v1/auth/logout",
            Some(&session_header(&session)),
            json!({}),
        )
        .await;
    assert_eq!(out.status, StatusCode::OK);
    assert_eq!(
        server
            .get("/v1/me", Some(&session_header(&session)))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

// ------------------------------------------------------------------ tokens

#[tokio::test]
async fn a_token_can_never_mint_another_token() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    let escalation = server
        .post(
            "/v1/tokens",
            Some(&token),
            json!({ "label": "second", "scopes": ["resource:read"] }),
        )
        .await;
    assert_eq!(escalation.status, StatusCode::FORBIDDEN);
    assert_eq!(escalation.s("error"), "session_required");
}

#[tokio::test]
async fn a_revoked_token_stops_working_at_the_next_request() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server.mint_token(&session, json!(["resource:write"])).await;

    let listed = server
        .get("/v1/tokens", Some(&session_header(&session)))
        .await;
    let id = listed.body[0]["id"].as_str().unwrap().to_string();

    let accepted = server
        .post(
            "/v1/projects/krypton/resources",
            Some(&token),
            manifest(vec![("review.md", b"x")]),
        )
        .await;
    assert_eq!(accepted.status, StatusCode::ACCEPTED);

    let revoke = server
        .send(
            Request::delete(format!("/v1/tokens/{id}"))
                .header(header::COOKIE, format!("xenon_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(revoke.status, StatusCode::NO_CONTENT);

    let after = server
        .post(
            "/v1/projects/krypton/resources",
            Some(&token),
            manifest(vec![("review.md", b"x")]),
        )
        .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    assert_eq!(after.s("error"), "invalid_token");
}

#[tokio::test]
async fn write_scope_is_required_to_push_and_read_scope_to_list() {
    let server = Server::start();
    let session = server.register_first().await;
    let read_only = server.mint_token(&session, json!(["resource:read"])).await;

    let denied = server
        .post(
            "/v1/projects/krypton/resources",
            Some(&read_only),
            manifest(vec![("review.md", b"x")]),
        )
        .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(denied.s("error"), "missing_scope");

    // Write-without-read is allowed and useful: CI can push without being able
    // to enumerate the project.
    let write_only = server.mint_token(&session, json!(["resource:write"])).await;
    let pushed = server
        .post(
            "/v1/projects/krypton/resources",
            Some(&write_only),
            manifest(vec![("review.md", b"x")]),
        )
        .await;
    assert_eq!(pushed.status, StatusCode::ACCEPTED);

    // Reading back needs resource:read. The caller owns this project, so there
    // is nothing to hide from them — they get an actionable "missing scope"
    // rather than the 404 used to keep OTHER people's projects unenumerable.
    let listing = server
        .get("/v1/projects/krypton/resources", Some(&write_only))
        .await;
    assert_eq!(listing.status, StatusCode::FORBIDDEN);
    assert_eq!(listing.s("error"), "missing_scope");
}

// --------------------------------------------------------------- push flow

#[tokio::test]
async fn full_push_negotiates_uploads_and_commits() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    let review = b"# review\n\nthe guard is set after the await.\n".as_slice();
    let response = b"---\nnote: ship it\n---\n".as_slice();

    let ack = server
        .post(
            "/v1/projects/krypton/resources",
            Some(&token),
            manifest(vec![("review.md", review), ("response.md", response)]),
        )
        .await;
    assert_eq!(ack.status, StatusCode::ACCEPTED, "{:?}", ack.body);
    assert!(!ack.body["unchanged"].as_bool().unwrap());
    let missing: Vec<String> = serde_json::from_value(ack.body["missing"].clone()).unwrap();
    assert_eq!(missing.len(), 2, "both blobs are new");
    assert_eq!(
        ack.s("url"),
        "/r/krypton/review/2026-08-07-peering-guard-rewrite"
    );

    let revision = ack.s("revision_id");

    // Committing before the bytes arrive must fail, and name what is missing.
    let early = server
        .post(
            &format!("/v1/revisions/{revision}/commit"),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(early.status, StatusCode::CONFLICT);
    assert_eq!(early.s("error"), "missing_blobs");
    assert_eq!(early.body["detail"]["missing"].as_array().unwrap().len(), 2);

    for bytes in [review, response] {
        let put = server.put_blob(&sha256_hex(bytes), &token, bytes).await;
        assert_eq!(put.status, StatusCode::CREATED);
    }

    let commit = server
        .post(
            &format!("/v1/revisions/{revision}/commit"),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(commit.status, StatusCode::OK, "{:?}", commit.body);
    assert_eq!(commit.body["seq"].as_i64().unwrap(), 1);

    // Re-committing the same revision is refused, not silently repeated.
    let again = server
        .post(
            &format!("/v1/revisions/{revision}/commit"),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.s("error"), "already_committed");

    let listing = server
        .get("/v1/projects/krypton/resources", Some(&token))
        .await;
    assert_eq!(listing.body.as_array().unwrap().len(), 1);
    assert_eq!(listing.body[0]["kind"], "review");

    let file = server
        .get(
            &format!("/v1/revisions/{revision}/files/review.md"),
            Some(&token),
        )
        .await;
    assert_eq!(file.status, StatusCode::OK);
}

#[tokio::test]
async fn an_unchanged_push_transfers_nothing_and_adds_no_revision() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;
    let body = b"# review\n".as_slice();

    let first = server
        .post(
            "/v1/projects/krypton/resources",
            Some(&token),
            manifest(vec![("review.md", body)]),
        )
        .await;
    server.put_blob(&sha256_hex(body), &token, body).await;
    server
        .post(
            &format!("/v1/revisions/{}/commit", first.s("revision_id")),
            Some(&token),
            json!({}),
        )
        .await;

    let repeat = server
        .post(
            "/v1/projects/krypton/resources",
            Some(&token),
            manifest(vec![("review.md", body)]),
        )
        .await;
    assert_eq!(repeat.status, StatusCode::OK);
    assert!(
        repeat.body["unchanged"].as_bool().unwrap(),
        "identical content must short-circuit"
    );
    assert!(
        repeat.body["revision_id"].is_null(),
        "no revision should be opened"
    );
    assert!(repeat.body["missing"].as_array().unwrap().is_empty());

    let detail = server
        .get(
            &format!("/v1/resources/{}", repeat.s("resource_id")),
            Some(&token),
        )
        .await;
    assert_eq!(
        detail.body["revisions"].as_i64().unwrap(),
        1,
        "still exactly one revision"
    );
}

#[tokio::test]
async fn editing_one_file_uploads_only_that_file() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    let review = b"# review\n".as_slice();
    let response_v1 = b"note: thinking\n".as_slice();
    let response_v2 = b"note: ship it\n".as_slice();

    let first = server
        .post(
            "/v1/projects/krypton/resources",
            Some(&token),
            manifest(vec![("review.md", review), ("response.md", response_v1)]),
        )
        .await;
    for bytes in [review, response_v1] {
        server.put_blob(&sha256_hex(bytes), &token, bytes).await;
    }
    server
        .post(
            &format!("/v1/revisions/{}/commit", first.s("revision_id")),
            Some(&token),
            json!({}),
        )
        .await;

    // Only response.md changed — the unchanged review.md is already held.
    let second = server
        .post(
            "/v1/projects/krypton/resources",
            Some(&token),
            manifest(vec![("review.md", review), ("response.md", response_v2)]),
        )
        .await;
    let missing: Vec<String> = serde_json::from_value(second.body["missing"].clone()).unwrap();
    assert_eq!(
        missing,
        vec![sha256_hex(response_v2)],
        "only the changed file is requested"
    );

    server
        .put_blob(&sha256_hex(response_v2), &token, response_v2)
        .await;
    let commit = server
        .post(
            &format!("/v1/revisions/{}/commit", second.s("revision_id")),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(commit.body["seq"].as_i64().unwrap(), 2);

    // The earlier revision still resolves to the old bytes — history is kept.
    let old = server
        .get(
            &format!("/v1/revisions/{}/files/response.md", first.s("revision_id")),
            Some(&token),
        )
        .await;
    assert_eq!(old.status, StatusCode::OK);
}

#[tokio::test]
async fn a_blob_that_does_not_match_its_digest_is_rejected() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server.mint_token(&session, json!(["resource:write"])).await;

    let claimed = sha256_hex(b"innocent");
    let res = server.put_blob(&claimed, &token, b"malicious").await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.s("error"), "digest_mismatch");
}

#[tokio::test]
async fn an_uncommitted_revision_is_invisible() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;
    let body = b"# draft\n".as_slice();

    let ack = server
        .post(
            "/v1/projects/krypton/resources",
            Some(&token),
            manifest(vec![("review.md", body)]),
        )
        .await;
    server.put_blob(&sha256_hex(body), &token, body).await;

    // Never committed: the resource must not appear in listings, and its files
    // must not be readable.
    let listing = server
        .get("/v1/projects/krypton/resources", Some(&token))
        .await;
    assert!(
        listing.body.as_array().unwrap().is_empty(),
        "uncommitted work must stay hidden"
    );

    let file = server
        .get(
            &format!("/v1/revisions/{}/files/review.md", ack.s("revision_id")),
            Some(&token),
        )
        .await;
    assert_eq!(file.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn inline_upload_handles_a_fileless_attention_record() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    let res = server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "attention",
                "slug": "jdg-1786109040786-2edbd1b0",
                "title": "Server language for Xenon",
                "meta": { "reversibility": "costly", "lane": "Claude-2" },
                "contents": [],
            }),
        )
        .await;
    assert_eq!(res.status, StatusCode::CREATED, "{:?}", res.body);
    assert_eq!(res.body["seq"].as_i64().unwrap(), 1);

    let detail = server
        .get(
            &format!("/v1/resources/{}", res.s("resource_id")),
            Some(&token),
        )
        .await;
    assert_eq!(detail.body["revision"]["meta"]["reversibility"], "costly");
    assert!(detail.body["revision"]["files"]
        .as_array()
        .unwrap()
        .is_empty());
}

/// Krypton spec 224. A day carries the derived record and, optionally, a lane's
/// narration of it. Both are markdown and `brief.md` sorts first, so the page
/// must open on the record — the narration is a reading of it, not the thing.
#[tokio::test]
async fn a_daily_note_publishes_and_opens_on_its_record_not_its_narration() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    let res = server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "daily",
                "slug": "2026-08-15",
                "title": "2026-08-15 (เสาร์)",
                "meta": { "date": "2026-08-15", "hasBrief": true, "handEdited": false },
                "contents": [
                    {
                        "path": "brief.md",
                        "content_base64": data_encoding::BASE64.encode(b"# narration\n\nthe day in prose\n"),
                        "content_type": "text/markdown",
                    },
                    {
                        "path": "note.md",
                        "content_base64": data_encoding::BASE64.encode(b"# 2026-08-15\n\n52 turns, 5 commits\n"),
                        "content_type": "text/markdown",
                    },
                ],
            }),
        )
        .await;
    assert_eq!(res.status, StatusCode::CREATED, "{:?}", res.body);

    let detail = server
        .get(
            &format!("/v1/resources/{}", res.s("resource_id")),
            Some(&token),
        )
        .await;
    let files = detail.body["revision"]["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(detail.body["revision"]["meta"]["hasBrief"], true);

    // The browse page defaults to the record; the narration stays one click away.
    let (status, html) = server
        .get_html("/r/krypton/daily/2026-08-15", Some(&session))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("52 turns, 5 commits"), "opens on the record");
    assert!(!html.contains("the day in prose"), "not on the narration");
    assert!(html.contains("brief.md"), "narration is still reachable");

    let (status, html) = server
        .get_html("/r/krypton/daily/2026-08-15?file=brief.md", Some(&session))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("the day in prose"));
}

#[tokio::test]
async fn inline_upload_stores_file_bodies() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    let res = server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "analysis",
                "slug": "wk-j/krypton/12",
                "title": "issue 12 root cause",
                "contents": [{
                    "path": "root-cause.md",
                    "content_base64": data_encoding::BASE64.encode(b"# root cause\n"),
                    "content_type": "text/markdown",
                }],
            }),
        )
        .await;
    assert_eq!(res.status, StatusCode::CREATED, "{:?}", res.body);

    let file = server
        .get(
            &format!("/v1/revisions/{}/files/root-cause.md", res.s("revision_id")),
            Some(&token),
        )
        .await;
    assert_eq!(file.status, StatusCode::OK);
}

// --------------------------------------------------------- isolation & web

#[tokio::test]
async fn one_user_cannot_see_or_write_another_users_project() {
    let server = Server::start_with(|c| c.allow_signup = true);
    let owner = server.register_first().await;
    let owner_token = server
        .mint_token(&owner, json!(["resource:write", "resource:read"]))
        .await;
    let body = b"# private\n".as_slice();

    let ack = server
        .post(
            "/v1/projects/krypton/resources",
            Some(&owner_token),
            manifest(vec![("review.md", body)]),
        )
        .await;
    server.put_blob(&sha256_hex(body), &owner_token, body).await;
    server
        .post(
            &format!("/v1/revisions/{}/commit", ack.s("revision_id")),
            Some(&owner_token),
            json!({}),
        )
        .await;

    let intruder_res = server
        .post(
            "/v1/auth/register",
            None,
            json!({ "email": "other@example.com", "password": "another long password" }),
        )
        .await;
    let intruder = cookie_value(&intruder_res);
    let intruder_token = server
        .mint_token(&intruder, json!(["resource:write", "resource:read"]))
        .await;

    // Not "forbidden" — "not found", so project names are not enumerable.
    let read = server
        .get("/v1/projects/krypton/resources", Some(&intruder_token))
        .await;
    assert_eq!(read.status, StatusCode::NOT_FOUND);

    let write = server
        .post(
            "/v1/projects/krypton/resources",
            Some(&intruder_token),
            manifest(vec![("x.md", b"x")]),
        )
        .await;
    assert_eq!(write.status, StatusCode::NOT_FOUND);

    let detail = server
        .get(
            &format!("/v1/resources/{}", ack.s("resource_id")),
            Some(&intruder_token),
        )
        .await;
    assert_eq!(detail.status, StatusCode::NOT_FOUND);

    let stolen_commit = server
        .post(
            &format!("/v1/revisions/{}/commit", ack.s("revision_id")),
            Some(&intruder_token),
            json!({}),
        )
        .await;
    assert_eq!(stolen_commit.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_project_scoped_token_cannot_reach_a_second_project() {
    let server = Server::start();
    let session = server.register_first().await;
    let broad = server.mint_token(&session, json!(["resource:write"])).await;

    // Create the project first so it can be named in the token's scope.
    server
        .post(
            "/v1/projects/krypton/resources",
            Some(&broad),
            manifest(vec![("review.md", b"x")]),
        )
        .await;

    let scoped = server
        .post(
            "/v1/tokens",
            Some(&session_header(&session)),
            json!({ "label": "ci", "scopes": ["resource:write"], "project": "krypton" }),
        )
        .await;
    assert_eq!(scoped.status, StatusCode::CREATED, "{:?}", scoped.body);
    let scoped = scoped.s("token");

    let same = server
        .post(
            "/v1/projects/krypton/resources",
            Some(&scoped),
            manifest(vec![("review.md", b"x")]),
        )
        .await;
    assert_eq!(same.status, StatusCode::ACCEPTED);

    let other = server
        .post(
            "/v1/projects/other/resources",
            Some(&scoped),
            manifest(vec![("review.md", b"x")]),
        )
        .await;
    assert_eq!(other.status, StatusCode::FORBIDDEN);
    assert_eq!(other.s("error"), "project_scoped_token");
}

#[tokio::test]
async fn malformed_manifests_are_rejected_at_the_edge() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server.mint_token(&session, json!(["resource:write"])).await;

    let cases = [
        (
            json!({ "kind": "nonsense", "slug": "a", "title": "t" }),
            "invalid_kind",
        ),
        (
            json!({ "kind": "review", "slug": "../etc", "title": "t" }),
            "invalid_slug",
        ),
        (
            json!({ "kind": "review", "slug": "a", "title": "  " }),
            "invalid_title",
        ),
        (
            json!({ "kind": "review", "slug": "a", "title": "t",
                    "files": [{ "path": "../x", "sha256": "a".repeat(64), "size": 1 }] }),
            "invalid_file_path",
        ),
        (
            json!({ "kind": "review", "slug": "a", "title": "t",
                    "files": [{ "path": "x", "sha256": "nope", "size": 1 }] }),
            "invalid_digest",
        ),
        (
            json!({ "kind": "review", "slug": "a", "title": "t", "files": [
                { "path": "x", "sha256": "a".repeat(64), "size": 1 },
                { "path": "x", "sha256": "b".repeat(64), "size": 1 }] }),
            "duplicate_file_path",
        ),
    ];
    for (body, expected) in cases {
        let res = server
            .post("/v1/projects/krypton/resources", Some(&token), body)
            .await;
        assert_eq!(
            res.s("error"),
            expected,
            "unexpected result: {:?}",
            res.body
        );
    }

    // A project slug spanning two path segments cannot even route.
    let bad_project = server
        .post(
            "/v1/projects/wk-j/krypton/resources",
            Some(&token),
            manifest(vec![("a.md", b"x")]),
        )
        .await;
    assert_eq!(bad_project.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unauthenticated_callers_cannot_read_and_public_is_for_any_account() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;
    let body = b"# private\n".as_slice();

    let ack = server
        .post(
            "/v1/projects/krypton/resources",
            Some(&token),
            manifest(vec![("review.md", body)]),
        )
        .await;
    server.put_blob(&sha256_hex(body), &token, body).await;
    server
        .post(
            &format!("/v1/revisions/{}/commit", ack.s("revision_id")),
            Some(&token),
            json!({}),
        )
        .await;

    assert_eq!(
        server.get("/v1/projects", None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server
            .get("/v1/projects/krypton/resources", None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server.get("/v1/activity", None).await.status,
        StatusCode::UNAUTHORIZED
    );

    // A bad credential is an error, never a silent downgrade to anonymous.
    let bogus = server
        .get("/v1/projects", Some("xen_aaaaaaaaaaaa_bbbbbbbb"))
        .await;
    assert_eq!(bogus.status, StatusCode::UNAUTHORIZED);

    let (friend, _) = register_invited(&server, &session, "friend@example.com").await;
    assert_eq!(
        server
            .get(
                "/v1/projects/krypton/resources",
                Some(&session_header(&friend)),
            )
            .await
            .status,
        StatusCode::NOT_FOUND,
        "a private project is still only the owner's"
    );

    let opened = server
        .patch(
            "/v1/admin/projects/krypton",
            Some(&session_header(&session)),
            json!({ "is_public": true }),
        )
        .await;
    assert_eq!(opened.status, StatusCode::OK, "{:?}", opened.body);

    let listed = server
        .get("/v1/projects", Some(&session_header(&friend)))
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    let slugs: Vec<&str> = listed
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["slug"].as_str().unwrap())
        .collect();
    assert!(
        slugs.contains(&"krypton"),
        "any signed-in account sees a public project: {slugs:?}"
    );
    assert_eq!(
        server
            .get(
                "/v1/projects/krypton/resources",
                Some(&session_header(&friend)),
            )
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        server
            .get("/v1/projects/krypton/resources", None)
            .await
            .status,
        StatusCode::UNAUTHORIZED,
        "public is not the open internet"
    );
}

#[tokio::test]
async fn browse_pages_render_and_escape_untrusted_titles() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;
    let body = b"# heading\n\ntext\n".as_slice();

    let mut m = manifest(vec![("review.md", body)]);
    m["title"] = json!("<img src=x onerror=alert(1)>");
    let ack = server
        .post("/v1/projects/krypton/resources", Some(&token), m)
        .await;
    server.put_blob(&sha256_hex(body), &token, body).await;
    server
        .post(
            &format!("/v1/revisions/{}/commit", ack.s("revision_id")),
            Some(&token),
            json!({}),
        )
        .await;

    let page = server
        .send(
            Request::get("/r/krypton/review/2026-08-07-peering-guard-rewrite")
                .header(header::COOKIE, format!("xenon_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(page.status, StatusCode::OK);

    let html = String::from_utf8(
        axum::body::to_bytes(
            server
                .app
                .clone()
                .oneshot(
                    Request::get("/r/krypton/review/2026-08-07-peering-guard-rewrite")
                        .header(header::COOKIE, format!("xenon_session={session}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .into_body(),
            1024 * 1024,
        )
        .await
        .unwrap()
        .to_vec(),
    )
    .unwrap();

    // askama emits numeric entities (`&#60;`) where the old hand-rolled escaper
    // emitted named ones (`&lt;`). Both are correct, so assert on the property
    // that matters — the tag must not survive as markup — rather than on which
    // escaper produced it.
    assert!(
        !html.contains("<img src=x onerror"),
        "unescaped title would be an XSS sink: {html}"
    );
    assert!(
        html.contains("&#60;img src=x") || html.contains("&lt;img src=x"),
        "the title must be escaped: {html}"
    );
    assert!(
        html.contains("<h1>heading</h1>"),
        "markdown should render: {html}"
    );
}

#[tokio::test]
async fn health_endpoint_needs_no_credential() {
    let server = Server::start();
    let res = server.get("/healthz", None).await;
    assert_eq!(res.status, StatusCode::OK);
}

/// The acceptance test for stage 1 of docs/02-frontend-architecture.md: a Review
/// Board pushed from Krypton must reach the browse UI as semantic markup, not as
/// the raw fence source that comrak alone produces.
#[tokio::test]
async fn a_published_review_board_renders_its_typed_blocks() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    let board = "# รีวิว Xenon publisher\n\n\
        เนื้อความอธิบายว่าโค้ดนี้ทำอะไร\n\n\
        ```review:walkthrough\ntitle: อ่านตามลำดับนี้\nsteps:\n  - at: src/xenon.rs:742\n    say: หัวใจของการเปลี่ยนแปลง\n```\n\n\
        ```review:finding\nseverity: blocking\ntitle: คิวลองใหม่ไม่เคยถูกอ่าน\nfile: src/commands.rs\nline: 1477\n```\n\n\
        ```review:metrics\nReviewers: 1\nBlockers: 4\n```\n\n\
        ```review:svg\n<svg viewBox=\"0 0 4 4\"><circle cx=\"2\" cy=\"2\" r=\"1\"/></svg>\n```\n\n\
        ```review:svg\n<svg onload=\"alert(1)\"></svg>\n```\n\n\
        ```rust\nfn untouched() {}\n```\n";

    let res = server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "review",
                "slug": "2026-08-08-stage-one",
                "title": "stage one",
                "contents": [{
                    "path": "review.md",
                    "content_base64": data_encoding::BASE64.encode(board.as_bytes()),
                    "content_type": "text/markdown",
                }],
            }),
        )
        .await;
    assert_eq!(res.status, StatusCode::CREATED, "{:?}", res.body);

    let (status, html) = server
        .get_html("/r/krypton/review/2026-08-08-stage-one", Some(&session))
        .await;
    assert_eq!(status, StatusCode::OK);

    // The fences are gone, replaced by semantic markup.
    assert!(
        !html.contains("language-review:"),
        "typed fences should not survive as code blocks: {html}"
    );
    assert!(html.contains("rv-steps"), "walkthrough missing");
    assert!(html.contains("src/xenon.rs:742"), "step anchor missing");
    assert!(
        html.contains("rv-finding--blocking"),
        "finding tone missing"
    );
    assert!(html.contains("BLOCK"), "severity chip missing");
    assert!(html.contains("rv-metrics"), "metrics missing");

    // Thai prose and titles survive the byte-oriented post-pass.
    assert!(html.contains("คิวลองใหม่ไม่เคยถูกอ่าน"));
    assert!(html.contains("เนื้อความอธิบายว่าโค้ดนี้ทำอะไร"));

    // The clean diagram passes through; the hostile one is refused whole.
    assert!(html.contains("<div class=\"rv-svg\">"), "clean svg refused");
    assert!(html.contains("svg not rendered"), "hostile svg not refused");
    assert!(
        !html.contains("onload=\"alert(1)\""),
        "handler markup must never reach the page live: {html}"
    );

    // A non-review fence is left exactly as comrak wrote it.
    assert!(
        html.contains("language-rust"),
        "unrelated fence was touched"
    );
}

/// An attention flag is the one kind with NO files — question, chosen option,
/// rationale, trade-offs and uncertainty all travel in `meta`. Before the meta
/// renderer the page showed its title over "this revision has no files", which
/// is the entire payload withheld from the reader.
#[tokio::test]
async fn a_published_attention_flag_renders_its_whole_payload() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    let res = server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "attention",
                "slug": "jdg-1786195508583-22c4b9f0",
                "title": "ควรแจ้งผลด้วยกล่องข้อความ หรือปล่อยให้ดูที่แถบสถานะ?",
                "meta": {
                    "id": "jdg-1786195508583-22c4b9f0",
                    "laneId": "claude-1",
                    "laneName": "Claude-1",
                    "createdAt": 1786195508583i64,
                    "question": "ควรแจ้งผลด้วยกล่องข้อความ หรือปล่อยให้ดูที่แถบสถานะ?",
                    "chosen": "แจ้งด้วยกล่องข้อความเด้งมุมจอ",
                    "rationale": "ถ้าสถานะไม่เปลี่ยน หน้าจอจะไม่ขยับเลย",
                    "tradedOff": ["ไม่แจ้งอะไรเลย", "สร้างกลไก chip ใหม่"],
                    "uncertainty": "ไม่แน่ใจว่าคุณรำคาญกล่องเด้งแค่ไหน",
                    "reversibility": "costly"
                },
                "contents": [],
            }),
        )
        .await;
    assert_eq!(res.status, StatusCode::CREATED, "{:?}", res.body);

    let (status, html) = server
        .get_html(
            "/r/krypton/attention/jdg-1786195508583-22c4b9f0",
            Some(&session),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        !html.contains("this revision has no files"),
        "the file-only empty state must not survive a fileless kind: {html}"
    );
    // Every field the lane wrote reaches the reader.
    for expected in [
        "แจ้งด้วยกล่องข้อความเด้งมุมจอ",
        "ถ้าสถานะไม่เปลี่ยน หน้าจอจะไม่ขยับเลย",
        "ไม่แจ้งอะไรเลย",
        "สร้างกลไก chip ใหม่",
        "ไม่แน่ใจว่าคุณรำคาญกล่องเด้งแค่ไหน",
        "Claude-1",
    ] {
        assert!(html.contains(expected), "missing {expected} in {html}");
    }
    // Reversibility carries as a text chip as well as a colour.
    assert!(
        html.contains("jdg__tier--costly"),
        "tier tone missing: {html}"
    );
    assert!(html.contains("costly"), "tier text missing: {html}");
    // The epoch renders as a date. (The slug carries the same digits, so the
    // real check is that `createdAt` never reaches the fallback table — that is
    // where an unformatted value would surface.)
    assert!(
        html.contains("2026-08-08 13:25 UTC"),
        "timestamp raw: {html}"
    );
    assert!(
        !html.contains("createdAt"),
        "createdAt fell through to the generic table unformatted: {html}"
    );
}

/// Frontend assets are separate files served from `/assets`, not string
/// constants inside a handler. Guard both halves: the pages must reference them,
/// and the references must actually resolve.
#[tokio::test]
async fn pages_link_external_assets_and_carry_no_inline_script() {
    let server = Server::start();
    let (status, html) = server.get_html("/login", None).await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        html.contains("<link rel=\"stylesheet\" href=\"/assets/app.css?v="),
        "stylesheet must be linked, not inlined: {html}"
    );
    assert!(html.contains("/assets/app.js?v="), "shared helpers missing");
    assert!(html.contains("/assets/login.js?v="), "page script missing");
    assert!(
        !html.contains("<style>"),
        "no inline style should remain: {html}"
    );
    assert!(
        !html.contains("<script>"),
        "no inline script should remain — it is what blocks a CSP: {html}"
    );

    // Every referenced asset resolves, with a cacheable content-hashed URL.
    for name in ["app.css", "app.js", "login.js", "register.js", "tokens.js"] {
        let (status, body) = server.get_html(&format!("/assets/{name}"), None).await;
        assert_eq!(status, StatusCode::OK, "/assets/{name}");
        assert!(!body.is_empty(), "/assets/{name} is empty");
    }

    let (missing, _) = server.get_html("/assets/nope.css", None).await;
    assert_eq!(missing, StatusCode::NOT_FOUND);
}

/// The project list renders from `templates/index.html`, and askama escapes the
/// values it interpolates. Guards the move off `format!`-built HTML.
#[tokio::test]
async fn the_project_list_renders_from_a_template_and_escapes_slugs() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    let (_, empty) = server.get_html("/projects", Some(&session)).await;
    assert!(
        empty.contains("no projects yet"),
        "signed-in empty state: {empty}"
    );

    // A project slug is agent-derived, so it is exactly the kind of value that
    // must not reach the page as live markup.
    server
        .post(
            "/v1/projects/wk-j.krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "doc",
                "slug": "docs/a.md",
                "title": "a",
                "contents": [],
            }),
        )
        .await;

    let (status, html) = server.get_html("/projects", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("href=\"/p/wk-j.krypton\""), "{html}");
    assert!(html.contains("1 resource ·"), "singular, not '1 resources'");
    assert!(html.contains("private"));
    assert!(!html.contains("no projects yet"));

    // The card wears a monogram logo derived from the slug: first letter,
    // uppercased, on a hue hashed from the whole name.
    assert!(
        html.contains("class=\"logo\"") && html.contains(">W</span>"),
        "no monogram on the card: {html}"
    );
    let (_, page) = server.get_html("/p/wk-j.krypton", Some(&session)).await;
    assert!(
        page.contains("logo--lg") && page.contains(">W</span>"),
        "the project page header lost its monogram: {page}"
    );
}

/// Linking a project to its GitHub repository (`PATCH /v1/projects/{slug}`)
/// makes rendered markdown turn `#123` into a link to that issue. Prose only:
/// code spans, fences and pre-existing links keep their text.
#[tokio::test]
async fn a_linked_project_renders_issue_refs_as_github_links() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;
    let admin = session_header(&session);

    let md = "fixes #12, see `#13`\n\n```\nnot #14\n```\n";
    let res = server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "doc",
                "slug": "docs/notes.md",
                "title": "notes",
                "contents": [{
                    "path": "notes.md",
                    "content_base64": data_encoding::BASE64.encode(md.as_bytes()),
                    "content_type": "text/markdown",
                }],
            }),
        )
        .await;
    assert_eq!(res.status, StatusCode::CREATED, "{:?}", res.body);

    // Unlinked, the reference is plain text.
    let (_, page) = server
        .get_html("/r/krypton/doc/docs/notes.md", Some(&session))
        .await;
    assert!(!page.contains("issues/12"), "{page}");

    // A write token lacks project:admin, so it may not change settings.
    let denied = server
        .patch(
            "/v1/projects/krypton",
            Some(&token),
            json!({ "github_repo": "wk-j/xenon" }),
        )
        .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN, "{:?}", denied.body);

    // The session may, and the URL form is stored normalized.
    let ok = server
        .patch(
            "/v1/projects/krypton",
            Some(&admin),
            json!({ "github_repo": "https://github.com/wk-j/xenon" }),
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.body);
    assert_eq!(ok.body["github_repo"], "wk-j/xenon");

    let bad = server
        .patch(
            "/v1/projects/krypton",
            Some(&admin),
            json!({ "github_repo": "not a repo" }),
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{:?}", bad.body);

    // Linked: prose gets the link; code, fence and the header link stand.
    let (_, page) = server
        .get_html("/r/krypton/doc/docs/notes.md", Some(&session))
        .await;
    assert!(
        page.contains("<a href=\"https://github.com/wk-j/xenon/issues/12\">#12</a>"),
        "{page}"
    );
    assert!(!page.contains("issues/13"), "code span stays text: {page}");
    assert!(!page.contains("issues/14"), "fence stays text: {page}");

    let (_, project) = server.get_html("/p/krypton", Some(&session)).await;
    assert!(
        project.contains("href=\"https://github.com/wk-j/xenon\""),
        "project header should carry the repo link: {project}"
    );

    // `{}` leaves the link alone; an explicit null clears it.
    let noop = server
        .patch("/v1/projects/krypton", Some(&admin), json!({}))
        .await;
    assert_eq!(noop.body["github_repo"], "wk-j/xenon", "{:?}", noop.body);
    let cleared = server
        .patch(
            "/v1/projects/krypton",
            Some(&admin),
            json!({ "github_repo": null }),
        )
        .await;
    assert!(cleared.body["github_repo"].is_null(), "{:?}", cleared.body);
}

/// An analysis bundle's slug (`owner/repo/N`) names the repo its issue lives
/// in, and `#M` on that page resolves there — not to the project's linked
/// repo, which may belong to a different codebase entirely. Meta-only pages
/// (an attention flag) get the same detection as documents.
#[tokio::test]
async fn an_analysis_page_resolves_refs_against_the_repo_in_its_slug() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    let md = "duplicate of #447\n";
    let res = server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "analysis",
                "slug": "acme/custom-ui/448",
                "title": "issue 448",
                "contents": [{
                    "path": "fix-plan.md",
                    "content_base64": data_encoding::BASE64.encode(md.as_bytes()),
                    "content_type": "text/markdown",
                }],
            }),
        )
        .await;
    assert_eq!(res.status, StatusCode::CREATED, "{:?}", res.body);

    // Even with NO project link, the slug alone carries the repo.
    let (_, page) = server
        .get_html("/r/krypton/analysis/acme/custom-ui/448", Some(&session))
        .await;
    assert!(
        page.contains("https://github.com/acme/custom-ui/issues/447"),
        "{page}"
    );

    // A project link does not override the more specific slug repo.
    server
        .patch(
            "/v1/projects/krypton",
            Some(&session_header(&session)),
            json!({ "github_repo": "wk-j/backend" }),
        )
        .await;
    let (_, page) = server
        .get_html("/r/krypton/analysis/acme/custom-ui/448", Some(&session))
        .await;
    assert!(
        page.contains("acme/custom-ui/issues/447") && !page.contains("wk-j/backend/issues"),
        "{page}"
    );

    // An attention flag has no files; its meta prose gets the same detection,
    // and the reference lands in the references section.
    let flag = server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "attention",
                "slug": "jdg-1",
                "title": "which retry policy?",
                "meta": { "rationale": "matches what #21 settled", "reversibility": "reversible" },
                "contents": [],
            }),
        )
        .await;
    assert_eq!(flag.status, StatusCode::CREATED, "{:?}", flag.body);
    let (_, page) = server
        .get_html("/r/krypton/attention/jdg-1", Some(&session))
        .await;
    assert!(
        page.contains("https://github.com/wk-j/backend/issues/21"),
        "{page}"
    );
    assert!(page.contains("class=\"refs\""), "{page}");
}

/// Every external destination a resource's content mentions — links out, and
/// GitHub issues via `#N` — is gathered into one references section at the
/// foot of the page, one row per URL however often it is cited.
#[tokio::test]
async fn external_links_collect_into_a_references_section() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;
    let md = "see [the docs](https://example.com/docs), #7,\n\
              https://example.com/docs again, and [a tab](?file=other.md)\n";
    let res = server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "doc",
                "slug": "docs/refs.md",
                "title": "refs",
                "contents": [{
                    "path": "refs.md",
                    "content_base64": data_encoding::BASE64.encode(md.as_bytes()),
                    "content_type": "text/markdown",
                }],
            }),
        )
        .await;
    assert_eq!(res.status, StatusCode::CREATED, "{:?}", res.body);

    // The project exists only after that first push, so it is linkable now.
    let linked = server
        .patch(
            "/v1/projects/krypton",
            Some(&session_header(&session)),
            json!({ "github_repo": "wk-j/xenon" }),
        )
        .await;
    assert_eq!(linked.status, StatusCode::OK, "{:?}", linked.body);

    let (_, page) = server
        .get_html("/r/krypton/doc/docs/refs.md", Some(&session))
        .await;
    let refs = page
        .split("<section class=\"refs\">")
        .nth(1)
        .and_then(|s| s.split("</section>").next())
        .expect("a references section");

    assert_eq!(
        refs.matches("https://example.com/docs").count(),
        1,
        "cited twice, listed once: {refs}"
    );
    assert!(refs.contains(">the docs</a>"), "{refs}");
    assert!(refs.contains(">wk-j/xenon#7</a>"), "the issue row: {refs}");
    assert!(
        !refs.contains("?file="),
        "internal links are not references: {refs}"
    );

    // A page whose content points nowhere external has no section at all.
    let bare = server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "doc",
                "slug": "docs/plain.md",
                "title": "plain",
                "contents": [{
                    "path": "plain.md",
                    "content_base64": data_encoding::BASE64.encode(b"just words\n"),
                    "content_type": "text/markdown",
                }],
            }),
        )
        .await;
    assert_eq!(bare.status, StatusCode::CREATED, "{:?}", bare.body);
    let (_, plain) = server
        .get_html("/r/krypton/doc/docs/plain.md", Some(&session))
        .await;
    assert!(!plain.contains("class=\"refs\""), "{plain}");
}

/// The project list leads with the most recently touched project, not the
/// alphabetically first one. The slugs here are chosen so the two orders
/// disagree: a regression back to slug order puts `aardvark` on top.
#[tokio::test]
async fn the_project_list_orders_the_most_recently_updated_first() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    for project in ["aardvark", "zebra"] {
        server
            .post(
                &format!("/v1/projects/{project}/resources:inline"),
                Some(&token),
                json!({
                    "kind": "doc",
                    "slug": "docs/a.md",
                    "title": "a",
                    "contents": [],
                }),
            )
            .await;
    }

    // Timestamps are unix seconds, so the two writes above almost certainly
    // tie. Backdate aardvark's activity by an hour to make the order real.
    let conn = db::open(&server._dir.path().join("xenon.db")).unwrap();
    conn.execute(
        "UPDATE resource SET updated_at = updated_at - 3600
         WHERE project_id = (SELECT id FROM project WHERE slug = 'aardvark')",
        [],
    )
    .unwrap();

    let (status, html) = server.get_html("/projects", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    let zebra = html.find("href=\"/p/zebra\"").expect("zebra listed");
    let aardvark = html.find("href=\"/p/aardvark\"").expect("aardvark listed");
    assert!(
        zebra < aardvark,
        "the most recently updated project should lead: {html}"
    );
}

/// The nav tells the reader who they are. It was static markup — every page
/// offered "sign in" to a reader who was already signed in, and a `tokens` link
/// that only bounced an anonymous one back to the login form.
#[tokio::test]
async fn the_nav_reflects_who_is_reading() {
    let server = Server::start();
    let session = server.register_first().await;

    let (anon_home, _) = server.get_html("/", None).await;
    assert_eq!(
        anon_home,
        StatusCode::SEE_OTHER,
        "the app is not readable without a session"
    );
    let (anon_projects, _) = server.get_html("/projects", None).await;
    assert_eq!(anon_projects, StatusCode::SEE_OTHER);

    let (status, login) = server.get_html("/login", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        login.contains("<a href=\"/login\" class=\"on\" aria-current=\"page\">sign in</a>"),
        "an anonymous reader needs the way in: {login}"
    );
    assert!(
        !login.contains("/settings/tokens"),
        "the tokens link only bounces an anonymous reader back: {login}"
    );
    assert!(!login.contains("sign out"), "{login}");

    // Every page carries the same chrome, so check one of each shape.
    for path in ["/", "/login", "/settings/tokens", "/admin"] {
        let (status, html) = server.get_html(path, Some(&session)).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(
            html.contains("action=\"/logout\""),
            "{path} still offers no way out: {html}"
        );
        assert!(
            !html.contains("<a href=\"/login\">sign in</a>"),
            "{path} offers sign-in to someone already signed in: {html}"
        );
        // `wk@example.com` registers without a display name, so the nav shows
        // the local part.
        assert!(
            html.contains("class=\"top__who\">wk<"),
            "{path} does not say which account is signed in: {html}"
        );
        assert!(
            html.contains("href=\"/admin\""),
            "{path} hides admin from the first account: {html}"
        );
        assert!(
            html.contains("class=\"nav__go\"") && html.contains("class=\"nav__util\""),
            "{path} flattened the nav back into one undifferentiated row: {html}"
        );
    }
}

/// Dark is the default paint; light is a cookie the chrome form sets, and the
/// next page is drawn in that mode without a flash of the other.
#[tokio::test]
async fn the_browse_ui_can_switch_theme() {
    let server = Server::start();

    let (status, login) = server.get_html("/login", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        login.contains("data-theme=\"dark\""),
        "unset cookie is dark: {login}"
    );
    assert!(
        login.contains("action=\"/theme\""),
        "the switch has to live on every page, including sign-in: {login}"
    );
    assert!(
        login.contains("name=\"next\" value=\"/login\""),
        "the form must say where to return; Referer is stripped: {login}"
    );
    assert!(
        login.contains("value=\"light\"") && login.contains("use light theme"),
        "dark page: the control posts light, and says so: {login}"
    );
    assert!(
        !login.contains("value=\"dark\""),
        "a toggle posts the other mode, not both: {login}"
    );

    let (status, location, cookie) = server
        .post_web_form("/theme", None, "theme=light&next=/login")
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/login");
    assert!(
        cookie.contains("xenon_theme=light") && cookie.contains("HttpOnly"),
        "light must be a real cookie, not just a query: {cookie}"
    );

    let (status, login) = server
        .get_html_cookie("/login", Some("xenon_theme=light"))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        login.contains("data-theme=\"light\""),
        "the cookie has to paint the page, not just sit there: {login}"
    );
    assert!(
        login.contains("value=\"dark\"") && login.contains("use dark theme"),
        "light page: the control posts dark, and says so: {login}"
    );
    assert!(
        !login.contains("value=\"light\""),
        "a toggle posts the other mode, not both: {login}"
    );

    let (status, location, cookie) = server
        .post_web_form(
            "/theme",
            Some("xenon_theme=light"),
            "theme=neon&next=/login",
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/login");
    assert!(
        cookie.is_empty(),
        "a junk value must not mint or overwrite a cookie: {cookie}"
    );

    let (status, location, _) = server
        .post_web_form("/theme", None, "theme=dark&next=https://evil.example/")
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/");

    let session = server.register_first().await;
    let (status, home) = server
        .get_html_cookie(
            "/",
            Some(&format!("xenon_session={session}; xenon_theme=light")),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(home.contains("data-theme=\"light\""), "{home}");
    assert!(home.contains("name=\"next\" value=\"/\""), "{home}");
}

/// A page that lists items can be read as cards or as rows. Like the theme, the
/// choice is a cookie, so it is made once and holds on every list page — and it
/// changes the layout only: the same items, with the same text, either way.
#[tokio::test]
async fn the_browse_ui_can_switch_between_card_and_list_mode() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server.mint_token(&session, json!(["resource:write"])).await;
    let res = server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "doc",
                "slug": "notes",
                "title": "Release notes",
                "contents": [{
                    "path": "notes.md",
                    "content_base64": data_encoding::BASE64.encode(b"# notes\n"),
                    "content_type": "text/markdown",
                }],
            }),
        )
        .await;
    assert_eq!(res.status, StatusCode::CREATED, "{:?}", res.body);

    // Cards is what an unset cookie paints, on both list pages.
    for path in ["/projects", "/p/krypton/resources"] {
        let (status, html) = server.get_html(path, Some(&session)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            html.contains("action=\"/view\""),
            "{path} has a list but no display-mode switch: {html}"
        );
        assert!(
            html.contains(&format!("name=\"next\" value=\"{path}\"")),
            "{path} must say where to return; Referer is stripped: {html}"
        );
        assert!(
            html.contains("class=\"grid\""),
            "{path} should start in card mode: {html}"
        );
        assert!(html.contains("value=\"card\" class=\"on\""), "{html}");
    }

    let (status, location, cookie) = server
        .post_web_form("/view", None, "view=list&next=/projects")
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/projects");
    assert!(
        cookie.contains("xenon_view=list") && cookie.contains("HttpOnly"),
        "the mode must be a real cookie, not just a query: {cookie}"
    );

    let signed_in_list = format!("xenon_session={session}; xenon_view=list");
    for (path, item) in [
        ("/projects", "krypton"),
        ("/p/krypton/resources", "Release notes"),
    ] {
        let (status, html) = server.get_html_cookie(path, Some(&signed_in_list)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            html.contains("class=\"grid grid--list\""),
            "{path} ignored the cookie: {html}"
        );
        assert!(html.contains("value=\"list\" class=\"on\""), "{html}");
        assert!(!html.contains("value=\"card\" class=\"on\""), "{html}");
        assert!(
            html.contains(item),
            "list mode must not drop what the cards showed: {html}"
        );
    }

    let (status, location, cookie) = server
        .post_web_form(
            "/view",
            Some("xenon_view=list"),
            "view=table&next=/projects",
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/projects");
    assert!(
        cookie.is_empty(),
        "a junk mode must not mint or overwrite a cookie: {cookie}"
    );
}

/// Signing out from the browse UI ends the session and lands on a page, not on
/// the JSON body that `/v1/auth/logout` answers with.
#[tokio::test]
async fn the_browse_ui_can_sign_out() {
    let server = Server::start();
    let session = server.register_first().await;

    let (status, location, cookie) = server.post_web("/logout", Some(&session)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/");
    assert!(
        cookie.contains("xenon_session=;") && cookie.contains("Max-Age=0"),
        "the cookie must be cleared, not just the row: {cookie}"
    );

    // The session row is gone, so a copy of the cookie value is dead too.
    assert_eq!(
        server
            .get("/v1/me", Some(&session_header(&session)))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let (status, _) = server.get_html("/", Some(&session)).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "a dead session is sent to sign in, not shown an empty feed"
    );
}

/// A private page decides authentication on the server. `/settings/tokens` used
/// to render for anyone and let its script discover the 401 afterwards, which
/// flashed an empty token table at a reader who was never going to see one.
#[tokio::test]
async fn the_tokens_page_redirects_an_anonymous_reader() {
    let server = Server::start();
    let session = server.register_first().await;

    let (status, _) = server.get_html("/settings/tokens", None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (status, html) = server.get_html("/settings/tokens", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("api tokens"), "{html}");
}

/// An HTML artifact is served as its own sandboxed top-level document and linked
/// from the resource page — not embedded. The isolation that used to come from
/// the iframe now comes from the CSP `sandbox` header, so the artifact's own
/// scripts run while still being unable to reach this origin.
#[tokio::test]
async fn html_artifacts_are_sandboxed_documents_opened_in_their_own_tab() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    let artifact = "<html><head><title>t</title></head><body>\
                    <script>document.title='ran'</script>hi</body></html>";
    let res = server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "artifact",
                "slug": "hm-1/Claude-1/art-1",
                "title": "t",
                "contents": [
                    { "path": "artifact.html",
                      "content_base64": data_encoding::BASE64.encode(artifact.as_bytes()),
                      "content_type": "text/html" },
                    { "path": "note.txt",
                      "content_base64": data_encoding::BASE64.encode(b"plain"),
                      "content_type": "text/plain" }
                ],
            }),
        )
        .await;
    assert_eq!(res.status, StatusCode::CREATED, "{:?}", res.body);

    let detail = server
        .get(
            &format!("/v1/resources/{}", res.s("resource_id")),
            Some(&token),
        )
        .await;
    let rev = detail.body["revision"]["id"].as_str().unwrap().to_string();

    // The HTML file is sandboxed into an opaque origin, and its bytes are its own.
    let (status, csp, body) = server
        .get_file_with_csp(&format!("/v1/revisions/{rev}/files/artifact.html"), &token)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        csp.contains("sandbox allow-scripts"),
        "not sandboxed: {csp}"
    );
    assert!(
        !csp.contains("allow-same-origin"),
        "same-origin would defeat the whole point: {csp}"
    );
    assert!(csp.contains("form-action 'none'"), "{csp}");
    assert_eq!(
        body, artifact,
        "the artifact's bytes must be served verbatim"
    );

    // A non-HTML file keeps the strict policy and gains no script capability.
    let (_, csp, body) = server
        .get_file_with_csp(&format!("/v1/revisions/{rev}/files/note.txt"), &token)
        .await;
    assert_eq!(body, "plain");
    assert!(csp.contains("default-src 'none'"), "{csp}");
    assert!(
        !csp.contains("sandbox"),
        "only HTML needs sandboxing: {csp}"
    );

    // The resource page links out instead of embedding.
    let (status, page) = server
        .get_html("/r/krypton/artifact/hm-1/Claude-1/art-1", Some(&session))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("open artifact"), "{page}");
    assert!(page.contains("target=\"_blank\""));
    assert!(page.contains("rel=\"noopener noreferrer\""));
    assert!(
        !page.contains("<iframe"),
        "nothing should be embedded: {page}"
    );
}

/// A text file is read on the page. Evidence pushed as `.json` used to render
/// as nothing but a download link, which made the one file a reviewer opened
/// the page for the one file the page would not show.
#[tokio::test]
async fn text_files_are_read_on_the_page_and_binaries_stay_downloads() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    // Declared as octet-stream on purpose: that is the default a client gets
    // when it says nothing, and trusting it is what hid these files before.
    let evidence = "{\n  \"node\": \"<b>a</b>\",\n  \"ok\": true\n}\n";
    let res = server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "analysis",
                "slug": "2026-08-10-evidence",
                "title": "evidence",
                "contents": [
                    { "path": "evidence-node.json",
                      "content_base64": data_encoding::BASE64.encode(evidence.as_bytes()),
                      "content_type": "application/octet-stream" },
                    { "path": "shot.bin",
                      "content_base64": data_encoding::BASE64.encode(&[0u8, 159, 146, 150]),
                      "content_type": "application/octet-stream" }
                ],
            }),
        )
        .await;
    assert_eq!(res.status, StatusCode::CREATED, "{:?}", res.body);

    let (status, page) = server
        .get_html(
            "/r/krypton/analysis/2026-08-10-evidence?file=evidence-node.json",
            Some(&session),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("filetext__body"),
        "not laid out inline: {page}"
    );
    assert!(page.contains("&quot;ok&quot;"), "body missing: {page}");
    assert!(
        page.contains("&lt;b&gt;a&lt;/b&gt;"),
        "file bytes must reach the page escaped: {page}"
    );
    assert!(page.contains("4 lines"), "{page}");

    // Bytes that are not text are still offered as a download rather than
    // being forced through a lossy decode.
    let (status, page) = server
        .get_html(
            "/r/krypton/analysis/2026-08-10-evidence?file=shot.bin",
            Some(&session),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("download shot.bin"), "{page}");
    assert!(!page.contains("filetext__body"), "{page}");
}

/// Every page below the root offers one click back to each level above it, and
/// the current page is text rather than a link to itself.
#[tokio::test]
async fn deep_pages_carry_a_breadcrumb_trail_back_to_the_root() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "review",
                "slug": "2026-08-08-a",
                "title": "a board",
                "contents": [{
                    "path": "review.md",
                    "content_base64": data_encoding::BASE64.encode(b"# a board\n"),
                    "content_type": "text/markdown",
                }],
            }),
        )
        .await;

    // The root has nowhere to go up to, so it shows no trail at all.
    let (_, root) = server.get_html("/", Some(&session)).await;
    assert!(!root.contains("nav class=\"crumbs\""), "{root}");

    // A project links back to the project list, which is `/projects` — the root
    // is the activity feed and is nobody's parent.
    let (_, project) = server.get_html("/p/krypton", Some(&session)).await;
    assert!(
        project.contains("<a href=\"/projects\">projects</a>"),
        "{project}"
    );
    assert!(
        project.contains("crumbs__here\" aria-current=\"page\">krypton"),
        "the current page must not link to itself: {project}"
    );

    // Resources sit one level under the project home.
    let (_, resources) = server
        .get_html("/p/krypton/resources", Some(&session))
        .await;
    assert!(
        resources.contains("<a href=\"/p/krypton\">krypton</a>"),
        "resources must link back to the project: {resources}"
    );
    assert!(
        resources.contains("crumbs__here\" aria-current=\"page\">resources"),
        "{resources}"
    );

    // A resource links back to both levels above it.
    let (_, resource) = server
        .get_html("/r/krypton/review/2026-08-08-a", Some(&session))
        .await;
    assert!(
        resource.contains("<a href=\"/projects\">projects</a>"),
        "{resource}"
    );
    assert!(
        resource.contains("<a href=\"/p/krypton\">krypton</a>"),
        "missing the project crumb: {resource}"
    );
    assert!(resource.contains("crumbs__here"), "{resource}");
}

/// Pushing new content for a slug that already exists must never overwrite what
/// is on the server: it appends a revision. The previous one stays sealed,
/// addressable, and byte-identical, and its blob is untouched.
#[tokio::test]
async fn a_second_push_appends_a_revision_and_leaves_the_first_intact() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    async fn push(server: &Server, token: &str, body: &str, title: &str) -> Res {
        server
            .post(
                "/v1/projects/krypton/resources:inline",
                Some(token),
                json!({
                    "kind": "artifact",
                    "slug": "hm-1/Claude-1/art-9",
                    "title": title,
                    "contents": [{
                        "path": "artifact.html",
                        "content_base64": data_encoding::BASE64.encode(body.as_bytes()),
                        "content_type": "text/html",
                    }],
                }),
            )
            .await
    }

    const V1: &str = "<html><body>version one</body></html>";
    const V2: &str = "<html><body>version two</body></html>";

    let first = push(&server, &token, V1, "v1").await;
    assert_eq!(first.status, StatusCode::CREATED, "{:?}", first.body);
    assert_eq!(first.body["seq"].as_i64().unwrap(), 1);
    let resource_id = first.s("resource_id");

    let second = push(&server, &token, V2, "v2").await;
    assert_eq!(second.status, StatusCode::CREATED, "{:?}", second.body);
    assert_eq!(
        second.body["seq"].as_i64().unwrap(),
        2,
        "a changed push must append, not replace"
    );
    assert_eq!(
        second.s("resource_id"),
        resource_id,
        "it is the same resource, not a new one"
    );

    // Both revisions are listed, newest first.
    let revs = server
        .get(
            &format!("/v1/resources/{resource_id}/revisions"),
            Some(&token),
        )
        .await;
    // The route returns a bare array, not an object wrapper.
    let seqs: Vec<i64> = revs
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["seq"].as_i64().unwrap())
        .collect();
    assert_eq!(seqs, vec![2, 1], "history must keep both: {:?}", revs.body);

    // The head serves v2 …
    let head = server
        .get(&format!("/v1/resources/{resource_id}"), Some(&token))
        .await;
    let head_rev = head.body["revision"]["id"].as_str().unwrap().to_string();
    let (_, _, body) = server
        .get_file_with_csp(
            &format!("/v1/revisions/{head_rev}/files/artifact.html"),
            &token,
        )
        .await;
    assert_eq!(body, V2);

    // … and revision 1 is still there, unchanged, addressable by its own id.
    let pinned = server
        .get(&format!("/v1/resources/{resource_id}?seq=1"), Some(&token))
        .await;
    let old_rev = pinned.body["revision"]["id"].as_str().unwrap().to_string();
    assert_ne!(old_rev, head_rev);
    let (status, _, old_body) = server
        .get_file_with_csp(
            &format!("/v1/revisions/{old_rev}/files/artifact.html"),
            &token,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the old revision must still resolve"
    );
    assert_eq!(old_body, V1, "the first version must be byte-identical");

    // Re-pushing v2 unchanged adds nothing at all.
    let again = push(&server, &token, V2, "v2").await;
    assert_eq!(
        again.body["seq"].as_i64().unwrap(),
        2,
        "no phantom revision"
    );
}

// ------------------------------------------------------------------ activity

/// Every publish leaves exactly one row, and a second push of *changed* content
/// is a revision rather than a second publish. A no-op push leaves nothing —
/// re-running `#push` has to be a no-op in the feed as well as on disk.
#[tokio::test]
async fn publishing_records_publish_then_revise_and_nothing_for_a_no_op() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    async fn push(server: &Server, token: &str, body: &str) {
        server
            .post(
                "/v1/projects/krypton/resources:inline",
                Some(token),
                json!({
                    "kind": "review",
                    "slug": "2026-08-09-a",
                    "title": "a board",
                    "contents": [{
                        "path": "review.md",
                        "content_base64": data_encoding::BASE64.encode(body.as_bytes()),
                        "content_type": "text/markdown",
                    }],
                }),
            )
            .await;
    }

    push(&server, &token, "# v1\n").await;
    push(&server, &token, "# v2\n").await;
    push(&server, &token, "# v2\n").await; // unchanged — must not appear

    let feed = server
        .get("/v1/activity", Some(&session_header(&session)))
        .await;
    let kinds: Vec<&str> = feed.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "resource.revise",
            "resource.publish",
            "project.create",
            "token.create",
            "account.register"
        ],
        "newest first, and the unchanged push adds nothing"
    );

    let publish = feed.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "resource.publish")
        .unwrap();
    assert_eq!(publish["subject"], "a board");
    assert_eq!(publish["project"], "krypton");
    assert_eq!(publish["url"], "/r/krypton/review/2026-08-09-a");
    assert_eq!(
        publish["detail"]["kind"], "review",
        "the resource kind rides along so the feed can colour the row"
    );
    assert!(
        publish["detail"]["token_id"].is_string(),
        "a machine push names the token behind it: {publish}"
    );
}

/// The visibility predicate, end to end: a private project's rows belong to its
/// owner, and one account's security rows are never another account's business.
#[tokio::test]
async fn the_feed_shows_each_caller_only_what_they_may_see() {
    let server = Server::start_with(|c| c.allow_signup = true);
    let owner = server.register_first().await;
    let owner_token = server
        .mint_token(&owner, json!(["resource:write", "resource:read"]))
        .await;
    server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&owner_token),
            json!({
                "kind": "doc",
                "slug": "docs/a.md",
                "title": "private doc",
                "contents": [],
            }),
        )
        .await;

    let intruder_res = server
        .post(
            "/v1/auth/register",
            None,
            json!({ "email": "other@example.com", "password": "another long password" }),
        )
        .await;
    let intruder = cookie_value(&intruder_res);

    let subjects = |body: &Value| -> Vec<String> {
        body["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| format!("{}:{}", e["kind"].as_str().unwrap(), e["subject"]))
            .collect()
    };

    let theirs = server
        .get("/v1/activity", Some(&session_header(&intruder)))
        .await;
    let seen = subjects(&theirs.body);
    assert!(
        seen.iter().all(|s| s.starts_with("account.register")),
        "a second user sees only their own registration: {seen:?}"
    );

    let anonymous = server.get("/v1/activity", None).await;
    assert_eq!(
        anonymous.status,
        StatusCode::UNAUTHORIZED,
        "the feed is not an anonymous surface: {:?}",
        anonymous.body
    );

    let mine = server
        .get("/v1/activity", Some(&session_header(&owner)))
        .await;
    assert!(
        subjects(&mine.body)
            .iter()
            .any(|s| s.contains("private doc")),
        "the owner still sees their own private-project row"
    );
}

/// A failed sign-in is recorded, and an attempt against an email nobody owns
/// belongs to nobody — otherwise the feed becomes the account-existence oracle
/// that the login endpoint refuses to be.
#[tokio::test]
async fn a_failed_sign_in_is_recorded_without_naming_an_account() {
    let server = Server::start();
    let session = server.register_first().await;

    let wrong = server
        .post(
            "/v1/auth/login",
            None,
            json!({ "email": "wk@example.com", "password": "not the password" }),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);

    let ghost = server
        .post(
            "/v1/auth/login",
            None,
            json!({ "email": "ghost@example.com", "password": "not the password" }),
        )
        .await;
    assert_eq!(ghost.status, StatusCode::UNAUTHORIZED);

    // The first account is the admin, so it sees both — its own failure and the
    // orphaned one.
    let feed = server
        .get(
            "/v1/activity?kind=account.login_failed",
            Some(&session_header(&session)),
        )
        .await;
    let events = feed.body["events"].as_array().unwrap();
    assert_eq!(events.len(), 2, "{:?}", feed.body);
    assert!(
        events.iter().any(|e| e["subject"] == "ghost@example.com"),
        "the attempted address is kept for the admin: {events:?}"
    );
    assert!(
        events.iter().all(|e| e["detail"]["ip"].is_string()),
        "where it came from is the point of the row"
    );
}

/// The page renders, groups by day, and pages with a cursor that neither
/// repeats nor skips a row.
#[tokio::test]
async fn the_activity_page_renders_and_pages() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    for i in 0..3 {
        server
            .post(
                "/v1/projects/krypton/resources:inline",
                Some(&token),
                json!({
                    "kind": "artifact",
                    "slug": format!("lane/a{i}"),
                    "title": format!("artifact {i}"),
                    "contents": [],
                }),
            )
            .await;
    }

    // The feed is the home page.
    let (status, html) = server.get_html("/", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("feed__day\">today"), "day heading: {html}");
    assert!(html.contains("artifact 2"), "{html}");
    assert!(
        html.contains("k--artifact"),
        "a resource row wears its kind hue: {html}"
    );
    assert!(
        html.contains("/r/krypton/artifact/lane/a2"),
        "rows link to what they are about: {html}"
    );

    // Page 2 starts strictly older than the last row of page 1.
    let first = server
        .get("/v1/activity?limit=2", Some(&session_header(&session)))
        .await;
    let cursor = first.body["next_cursor"].as_i64().expect("a cursor");
    let second = server
        .get(
            &format!("/v1/activity?limit=2&cursor={cursor}"),
            Some(&session_header(&session)),
        )
        .await;
    let ids: Vec<&str> = first.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second.body["events"].as_array().unwrap())
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    let unique: std::collections::HashSet<&&str> = ids.iter().collect();
    assert_eq!(
        ids.len(),
        unique.len(),
        "a page must not repeat a row: {ids:?}"
    );

    // An unknown kind is rejected at the edge rather than silently ignored.
    let bad = server
        .get(
            "/v1/activity?kind=nonsense",
            Some(&session_header(&session)),
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

/// The feed took over the root, so the two pages that moved must both still be
/// reachable — and every link the feed prints must point at its new address, or
/// a filter click would bounce through the redirect on every chip.
#[tokio::test]
async fn the_home_page_is_the_feed_and_the_project_list_moved_to_its_own_url() {
    let server = Server::start();
    let session = server.register_first().await;

    let (status, home) = server.get_html("/", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        home.contains("kinds--events"),
        "the root must render the feed, not the project list: {home}"
    );
    assert!(
        !home.contains("no projects yet"),
        "the project list must not still be at the root: {home}"
    );

    let (status, projects) = server.get_html("/projects", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(projects.contains("no projects yet"), "{projects}");

    // The nav offers both, names the root as activity, and marks the section
    // the reader is on — a flat row of equal words is how the chrome used to
    // hide which of the eight items was current.
    assert!(
        home.contains("<a href=\"/\" class=\"on\" aria-current=\"page\">activity</a>"),
        "{home}"
    );
    assert!(
        home.contains("<a href=\"/projects\">projects</a>"),
        "{home}"
    );
    assert!(
        !home.contains("href=\"/projects\" class=\"on\""),
        "projects must not light up on the feed: {home}"
    );

    // Filter chips and the pager address the feed at `/`, not at the old URL.
    assert!(
        !home.contains("href=\"/activity"),
        "a link still points at the pre-move feed URL: {home}"
    );
    assert!(
        home.contains("href=\"/?kind=resource.publish\""),
        "the kind chips must filter in place: {home}"
    );

    // The old address keeps working for anything already bookmarked or linked,
    // filters and cursor included.
    let (status, to) = server.get_location("/activity").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(to, "/");

    let (status, to) = server
        .get_location("/activity?kind=resource.publish&project=krypton")
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        to, "/?kind=resource.publish&project=krypton",
        "a bookmarked filter must survive the move"
    );
}

/// Opening a project is that project's feed, not its resource list: the same
/// reason `/` is the fleet feed rather than the project list.
#[tokio::test]
async fn entering_a_project_opens_its_activity_feed() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;

    server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&token),
            json!({
                "kind": "doc",
                "slug": "notes",
                "title": "Release notes",
                "contents": [],
            }),
        )
        .await;
    server
        .post(
            "/v1/projects/other/resources:inline",
            Some(&token),
            json!({
                "kind": "doc",
                "slug": "elsewhere",
                "title": "Somewhere else",
                "contents": [],
            }),
        )
        .await;

    let (status, html) = server.get_html("/p/krypton", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("feed__day\">today"),
        "the project home must be a feed: {html}"
    );
    assert!(
        html.contains("Release notes"),
        "this project's publish must appear: {html}"
    );
    assert!(
        !html.contains("Somewhere else"),
        "another project's rows must not leak onto this feed: {html}"
    );
    assert!(
        !html.contains("minted token") && !html.contains("signed in"),
        "account events have no project and must stay off this feed: {html}"
    );
    assert!(
        html.contains("href=\"/p/krypton\" class=\"on\" aria-current=\"page\">activity</a>"),
        "activity is the current tab: {html}"
    );
    assert!(
        html.contains("href=\"/p/krypton/resources\">resources</a>"),
        "resources must be one click away: {html}"
    );
    assert!(
        html.contains("href=\"/p/krypton/usage\">llm usage</a>"),
        "usage must still be a peer tab: {html}"
    );
    assert!(
        !html.contains("class=\"feed__project\""),
        "a project feed should not stamp its own name on every row: {html}"
    );
    assert!(
        html.contains("href=\"/p/krypton?kind=resource.publish\""),
        "kind chips filter this project in place: {html}"
    );
    assert!(
        !html.contains("href=\"/?kind="),
        "project chips must not bounce to the fleet feed: {html}"
    );

    let (status, resources) = server
        .get_html("/p/krypton/resources", Some(&session))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        resources.contains("Release notes") && resources.contains("class=\"grid\""),
        "the listing moved to /resources: {resources}"
    );
    assert!(
        resources.contains(
            "href=\"/p/krypton/resources\" class=\"on\" aria-current=\"page\">resources</a>"
        ),
        "resources is the current tab: {resources}"
    );

    // A bookmarked resource-kind filter on the old project URL still lands
    // on the list it named.
    let (status, to) = server
        .get_location_cookie(
            "/p/krypton?kind=review",
            Some(&format!("xenon_session={session}")),
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(to, "/p/krypton/resources?kind=review");

    let (status, filtered) = server
        .get_html("/p/krypton?kind=resource.publish", Some(&session))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        filtered.contains("Release notes"),
        "an event-kind filter stays on the project feed: {filtered}"
    );
    assert!(
        filtered.contains("href=\"/p/krypton?kind=resource.publish\"")
            && filtered.contains("class=\"on\">resource.publish</a>"),
        "the event-kind chip must stay selected: {filtered}"
    );
}

/// Signing out and revoking a token are the two account events a reader is most
/// likely to go looking for, so both must actually land.
#[tokio::test]
async fn signing_out_and_revoking_a_token_are_recorded() {
    let server = Server::start();
    let session = server.register_first().await;
    let created = server
        .post(
            "/v1/tokens",
            Some(&session_header(&session)),
            json!({ "label": "laptop", "scopes": ["resource:read"] }),
        )
        .await;
    let id = created.s("id");

    server
        .send(
            Request::delete(format!("/v1/tokens/{id}"))
                .header(header::COOKIE, format!("xenon_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    server.post_web("/logout", Some(&session)).await;

    // The session is gone, so read the log back as a fresh one.
    let again = server
        .post(
            "/v1/auth/login",
            None,
            json!({ "email": "wk@example.com", "password": "correct horse battery" }),
        )
        .await;
    let session = cookie_value(&again);
    let feed = server
        .get("/v1/activity", Some(&session_header(&session)))
        .await;
    let events = feed.body["events"].as_array().unwrap();
    let revoke = events
        .iter()
        .find(|e| e["kind"] == "token.revoke")
        .unwrap_or_else(|| panic!("no revoke row: {events:?}"));
    assert_eq!(
        revoke["subject"], "laptop",
        "a token is named the way its owner named it"
    );
    assert!(
        events.iter().any(|e| e["kind"] == "account.logout"),
        "no logout row: {events:?}"
    );
}

// --------------------------------------------------------------- authorship

/// Every upload carries the account and the credential the server
/// authenticated, per revision — and the page shows the verified half apart
/// from what the client merely claimed about itself.
#[tokio::test]
async fn each_upload_records_who_pushed_it_and_with_which_token() {
    let server = Server::start();
    let session = server.register_first().await;
    let laptop = server
        .post(
            "/v1/tokens",
            Some(&session_header(&session)),
            json!({ "label": "krypton on this laptop", "scopes": ["resource:write", "resource:read"] }),
        )
        .await;
    let laptop_token = laptop.s("token");

    async fn push(server: &Server, token: &str, body: &str, lane: &str) -> Res {
        server
            .post(
                "/v1/projects/krypton/resources:inline",
                Some(token),
                json!({
                    "kind": "review",
                    "slug": "2026-08-09-a",
                    "title": "a board",
                    "meta": { "lane": lane },
                    "origin": { "hostname": "macbook" },
                    "contents": [{
                        "path": "review.md",
                        "content_base64": data_encoding::BASE64.encode(body.as_bytes()),
                        "content_type": "text/markdown",
                    }],
                }),
            )
            .await
    }

    let first = push(&server, &laptop_token, "# v1\n", "Claude-1").await;
    let resource_id = first.s("resource_id");

    let detail = server
        .get(
            &format!("/v1/resources/{resource_id}"),
            Some(&session_header(&session)),
        )
        .await;
    assert_eq!(detail.body["revision"]["author"]["name"], "wk");
    assert_eq!(
        detail.body["revision"]["author"]["token_label"], "krypton on this laptop",
        "the credential names the machine: {:?}",
        detail.body["revision"]
    );
    assert_eq!(detail.body["revision"]["author"]["token_revoked"], false);
    assert_eq!(
        detail.body["last_author"]["name"], "wk",
        "the resource says who last touched it without a second fetch"
    );

    // A second machine revises it. Each revision keeps its own pusher.
    let desktop = server
        .post(
            "/v1/tokens",
            Some(&session_header(&session)),
            json!({ "label": "the desktop", "scopes": ["resource:write", "resource:read"] }),
        )
        .await;
    push(&server, &desktop.s("token"), "# v2\n", "Claude-2").await;

    let revisions = server
        .get(
            &format!("/v1/resources/{resource_id}/revisions"),
            Some(&session_header(&session)),
        )
        .await;
    let rows = revisions.body.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["author"]["token_label"], "the desktop");
    assert_eq!(
        rows[1]["author"]["token_label"], "krypton on this laptop",
        "revision 1 keeps the token that actually pushed it"
    );

    // The page shows the verified half in its own voice, and the client's own
    // claims marked as claims.
    let (status, html) = server
        .get_html("/r/krypton/review/2026-08-09-a", Some(&session))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("byline__who\">wk"), "{html}");
    assert!(html.contains("the desktop"), "{html}");
    assert!(
        html.contains("Claude-2 from macbook"),
        "lane and host belong in the byline: {html}"
    );
    assert!(
        html.contains("not verified"),
        "the claimed half must say it is a claim: {html}"
    );
}

/// A revoked token still names itself on what it pushed. The revocation is part
/// of the story, not a reason to erase who did the work.
#[tokio::test]
async fn a_revoked_token_still_names_itself_on_its_uploads() {
    let server = Server::start();
    let session = server.register_first().await;
    let minted = server
        .post(
            "/v1/tokens",
            Some(&session_header(&session)),
            json!({ "label": "retired laptop", "scopes": ["resource:write"] }),
        )
        .await;

    server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&minted.s("token")),
            json!({ "kind": "doc", "slug": "docs/a.md", "title": "a doc", "contents": [] }),
        )
        .await;
    server
        .send(
            Request::delete(format!("/v1/tokens/{}", minted.s("id")))
                .header(header::COOKIE, format!("xenon_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;

    let (_, html) = server
        .get_html("/r/krypton/doc/docs/a.md", Some(&session))
        .await;
    assert!(
        html.contains("retired laptop (revoked)"),
        "a revoked token keeps its name and is marked: {html}"
    );
}

/// A push authenticated by a session (a human with curl and a cookie, not a
/// machine) records the account and no token. NULL means "not recorded", which
/// is exactly what happened.
#[tokio::test]
async fn a_session_push_records_the_account_and_no_token() {
    let server = Server::start();
    let session = server.register_first().await;

    let ack = server
        .post(
            "/v1/projects/krypton/resources:inline",
            Some(&session_header(&session)),
            json!({ "kind": "doc", "slug": "docs/b.md", "title": "by hand", "contents": [] }),
        )
        .await;
    assert_eq!(ack.status, StatusCode::CREATED, "{:?}", ack.body);

    let detail = server
        .get(
            &format!("/v1/resources/{}", ack.s("resource_id")),
            Some(&session_header(&session)),
        )
        .await;
    assert_eq!(detail.body["revision"]["author"]["name"], "wk");
    assert!(
        detail.body["revision"]["author"]["token_label"].is_null(),
        "no token was used, so none is claimed: {:?}",
        detail.body["revision"]["author"]
    );
}

// ─── Per-turn LLM usage (Krypton spec 214) ───────────────────────────────────

fn usage_turn(id: &str, at: i64, model: &str, lane: &str, input: i64, output: i64) -> Value {
    json!({
        "v": 1, "id": id, "at": at, "durationMs": 4200,
        "hostname": "mbp", "harnessId": "hm-1", "lane": lane, "backend": "claude",
        "model": model, "modelConfirmed": true, "sessionId": "s1", "turn": 1,
        "stopReason": "end_turn", "origin": "user",
        "tokens": { "input": input, "output": output, "cachedRead": 1000 },
        "context": { "used": 132000, "size": 1000000 }
    })
}

/// The end-to-end shape Krypton actually drives: mint a write token, post turns
/// as they end, read them back aggregated.
#[tokio::test]
async fn usage_turns_ingest_and_aggregate() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;
    let at = 1_786_233_600_000i64;

    let res = server
        .post(
            "/v1/projects/wk-j.krypton/usage/turns",
            Some(&token),
            json!({ "turns": [
                usage_turn("usg-1", at, "claude-opus-5", "Claude-1", 100, 10),
                usage_turn("usg-2", at, "claude-opus-5", "Claude-1", 200, 20),
                usage_turn("usg-3", at, "gpt-5", "Codex-1", 300, 30),
            ]}),
        )
        .await;
    assert_eq!(res.status, StatusCode::ACCEPTED, "{:?}", res.body);
    assert_eq!(res.body["accepted"], 3);
    assert_eq!(res.body["duplicates"], 0);

    let res = server
        .get("/v1/projects/wk-j.krypton/usage?group=model", Some(&token))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{:?}", res.body);
    assert_eq!(res.body["totals"]["turns"], 3);
    assert_eq!(res.body["totals"]["inputTokens"], 600);
    assert_eq!(res.body["totals"]["outputTokens"], 60);
    assert_eq!(res.body["buckets"][0]["key"], "claude-opus-5");
    assert_eq!(res.body["buckets"][0]["turns"], 2);
}

/// The property the whole ingest design rests on: a client that cannot tell
/// whether its POST landed re-sends the same ids, and must not be double-billed.
#[tokio::test]
async fn re_posting_the_same_turns_is_a_duplicate_not_a_second_charge() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;
    let at = 1_786_233_600_000i64;
    let batch = json!({ "turns": [usage_turn("usg-1", at, "claude-opus-5", "Claude-1", 100, 10)] });

    server
        .post(
            "/v1/projects/p.one/usage/turns",
            Some(&token),
            batch.clone(),
        )
        .await;
    let again = server
        .post("/v1/projects/p.one/usage/turns", Some(&token), batch)
        .await;
    assert_eq!(again.body["accepted"], 0);
    assert_eq!(again.body["duplicates"], 1);

    let res = server.get("/v1/projects/p.one/usage", Some(&token)).await;
    assert_eq!(res.body["totals"]["turns"], 1);
    assert_eq!(res.body["totals"]["inputTokens"], 100);
}

/// One unusable row must not take the batch behind it down: a fleet's ledger
/// cannot be held hostage by a single bad row.
#[tokio::test]
async fn a_rejected_row_is_named_and_the_rest_of_the_batch_still_lands() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(&session, json!(["resource:write", "resource:read"]))
        .await;
    let at = 1_786_233_600_000i64;
    let mut future_row = usage_turn("usg-future", at, "claude-opus-5", "Claude-1", 1, 1);
    future_row["v"] = json!(99);

    let res = server
        .post(
            "/v1/projects/p.one/usage/turns",
            Some(&token),
            json!({ "turns": [future_row, usage_turn("usg-ok", at, "claude-opus-5", "Claude-1", 5, 5)] }),
        )
        .await;
    assert_eq!(res.body["accepted"], 1);
    assert_eq!(res.body["rejected"][0]["id"], "usg-future");

    let res = server.get("/v1/projects/p.one/usage", Some(&token)).await;
    assert_eq!(res.body["totals"]["turns"], 1);
}

/// Usage is project data, so it must obey the same read boundary resources do.
#[tokio::test]
async fn usage_is_not_readable_without_access_to_the_project() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server.mint_token(&session, json!(["resource:write"])).await;
    server
        .post(
            "/v1/projects/p.one/usage/turns",
            Some(&token),
            json!({ "turns": [usage_turn("usg-1", 1_786_233_600_000, "m", "L", 1, 1)] }),
        )
        .await;

    let anon = server.get("/v1/projects/p.one/usage", None).await;
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED, "{:?}", anon.body);
}

/// A write token must not be able to read the ledger back unless it was also
/// granted read — the scopes are separate for a reason.
#[tokio::test]
async fn a_write_only_token_cannot_read_the_usage_it_wrote() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server.mint_token(&session, json!(["resource:write"])).await;
    server
        .post(
            "/v1/projects/p.one/usage/turns",
            Some(&token),
            json!({ "turns": [usage_turn("usg-1", 1_786_233_600_000, "m", "L", 1, 1)] }),
        )
        .await;

    let res = server.get("/v1/projects/p.one/usage", Some(&token)).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{:?}", res.body);
}

/// The browse page renders the numbers, and says so when a model has no rate
/// rather than printing a zero that reads as "free".
#[tokio::test]
async fn the_usage_page_renders_totals_and_names_unpriced_models() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server.mint_token(&session, json!(["resource:write"])).await;
    server
        .post(
            "/v1/projects/p.one/usage/turns",
            Some(&token),
            json!({ "turns": [usage_turn(
                "usg-1", 1_786_233_600_000, "some-unpriced-model", "Claude-1", 4242, 99
            )]}),
        )
        .await;

    let (status, html) = server
        .get_html("/p/p.one/usage?days=0", Some(&session))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("llm usage"), "{html}");
    assert!(
        html.contains("4,242"),
        "input tokens must be on the page, grouped: {html}"
    );
    assert!(
        html.contains("no rate for some-unpriced-model"),
        "an unpriced model must be named, not silently blank: {html}"
    );
    // Every axis a spend question is asked along, including the backend one the
    // API served from the start but the page did not offer.
    for group in ["by model", "by lane", "by backend", "by day"] {
        assert!(html.contains(group), "missing grouping {group}: {html}");
    }
}

/// A ledger has to be able to show a row. Aggregates alone can say a week cost
/// $40 and offer nothing to point at when that looks wrong, and the per-turn
/// facts that cannot be summed exist nowhere else.
#[tokio::test]
async fn the_usage_page_lists_the_turns_its_totals_are_made_of() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server.mint_token(&session, json!(["resource:write"])).await;

    let mut unconfirmed = usage_turn(
        "usg-2",
        1_786_233_600_000 + 1000,
        "claude-opus-5",
        "Codex-1",
        7,
        3,
    );
    unconfirmed["modelConfirmed"] = json!(false);
    unconfirmed["stopReason"] = json!("max_tokens");
    // An adapter that reports no counters at all.
    unconfirmed["tokens"] = Value::Null;

    server
        .post(
            "/v1/projects/p.one/usage/turns",
            Some(&token),
            json!({ "turns": [
                usage_turn("usg-1", 1_786_233_600_000, "claude-opus-5", "Claude-1", 4242, 99),
                unconfirmed,
            ]}),
        )
        .await;

    let (status, html) = server
        .get_html("/p/p.one/usage?days=0", Some(&session))
        .await;
    assert_eq!(status, StatusCode::OK);
    // The turn's absolute instant, not "3 min ago": this column is what gets
    // lined up against a provider's invoice.
    assert!(
        html.contains("2026-08-09 00:00:00"),
        "a turn must show when it happened: {html}"
    );
    assert!(html.contains("Codex-1"), "each turn names its lane: {html}");
    assert!(
        html.contains("end_turn") && html.contains("max_tokens"),
        "stop reason lives only in the ledger: {html}"
    );
    assert!(
        html.contains("13%"),
        "context level is a level, shown per turn: {html}"
    );
    assert!(
        html.contains("1 unreported"),
        "a turn nobody measured is counted and named, never folded into a zero: {html}"
    );
    // The Codex-1 lane here is a single unmeasured turn. Its token sums are
    // zero by construction, and printing them would say the lane was free.
    assert!(
        html.contains("none reported"),
        "a bucket with no counters at all must go blank, not print zeros: {html}"
    );
    assert!(
        html.contains("the agent never confirmed it"),
        "an unconfirmed model id must be marked as intent, not fact: {html}"
    );
}

/// The kind chips said which kinds exist but not how much of each, so the only
/// way to learn a kind was empty was to click it. The counts are of the whole
/// project, so they must not move when a filter is on.
#[tokio::test]
async fn the_kind_filter_chips_carry_their_counts() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server.mint_token(&session, json!(["resource:write"])).await;

    async fn push(server: &Server, token: &str, kind: &str, slug: &str) {
        server
            .post(
                "/v1/projects/krypton/resources:inline",
                Some(token),
                json!({
                    "kind": kind,
                    "slug": slug,
                    "title": slug,
                    "contents": [{
                        "path": "note.md",
                        "content_base64": data_encoding::BASE64.encode(b"body"),
                        "content_type": "text/markdown",
                    }],
                }),
            )
            .await;
    }

    push(&server, &token, "artifact", "art-a").await;
    push(&server, &token, "artifact", "art-b").await;
    push(&server, &token, "review", "rev-a").await;

    let (status, html) = server
        .get_html("/p/krypton/resources", Some(&session))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(">all<span class=\"kinds__n\">3</span>"),
        "the reset chip counts everything in the project: {html}"
    );
    assert!(
        html.contains(">artifact<span class=\"kinds__n\">2</span>"),
        "each kind chip carries its own count: {html}"
    );
    assert!(
        html.contains(">review<span class=\"kinds__n\">1</span>"),
        "each kind chip carries its own count: {html}"
    );
    // A kind nobody has published is the case the counts exist for: the chip
    // stays put and says zero instead of being a click that goes nowhere.
    assert!(
        html.contains(">analysis<span class=\"kinds__n\">0</span>"),
        "an empty kind says zero rather than disappearing: {html}"
    );

    // Filtering narrows the list below, never the legend above it.
    let (status, filtered) = server
        .get_html("/p/krypton/resources?kind=review", Some(&session))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        filtered.contains(">artifact<span class=\"kinds__n\">2</span>")
            && filtered.contains(">all<span class=\"kinds__n\">3</span>"),
        "counts describe the project, so a filter must not change them: {filtered}"
    );
}

/// The page existed but nothing linked to it, so it was reachable only by
/// someone who already knew the URL.
#[tokio::test]
async fn the_project_page_links_to_its_usage_ledger() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server.mint_token(&session, json!(["resource:write"])).await;
    server
        .post(
            "/v1/projects/p.one/usage/turns",
            Some(&token),
            json!({ "turns": [usage_turn(
                "usg-1", 1_786_233_600_000, "claude-opus-5", "Claude-1", 1, 1
            )]}),
        )
        .await;

    let (status, html) = server.get_html("/p/p.one", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("/p/p.one/usage"),
        "the project page must offer its usage ledger: {html}"
    );
    assert!(
        html.contains("/p/p.one/resources"),
        "the project page must offer its resources: {html}"
    );
}

/// An empty range is not an error, and the page has to say what would put rows
/// in it — an empty table with no explanation reads as a broken feature.
#[tokio::test]
async fn an_empty_usage_range_explains_itself() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server.mint_token(&session, json!(["resource:write"])).await;
    // A turn from 2020: the project exists and has history, but nothing lands
    // inside a one-day window.
    server
        .post(
            "/v1/projects/p.one/usage/turns",
            Some(&token),
            json!({ "turns": [usage_turn(
                "usg-old", 1_600_000_000_000, "claude-opus-5", "Claude-1", 1, 1
            )]}),
        )
        .await;

    let (status, html) = server
        .get_html("/p/p.one/usage?days=1", Some(&session))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("no turns in this range"), "{html}");
    assert!(
        html.contains("usage_log"),
        "the empty state must name what produces rows: {html}"
    );
}

// ---------------------------------------------------------- administration

async fn register_invited(server: &Server, admin_session: &str, email: &str) -> (String, String) {
    let invite = server
        .post(
            "/v1/invites",
            Some(&session_header(admin_session)),
            json!({}),
        )
        .await;
    assert_eq!(invite.status, StatusCode::OK, "{:?}", invite.body);
    let joined = server
        .post(
            "/v1/auth/register",
            None,
            json!({
                "email": email,
                "password": "a sufficiently long one",
                "invite": invite.s("code"),
            }),
        )
        .await;
    assert_eq!(joined.status, StatusCode::CREATED, "{:?}", joined.body);
    (cookie_value(&joined), joined.s("id"))
}

/// The admin roster, project list, and invite ledger are session-only and
/// admin-only. A token minted by the same admin must not see them.
#[tokio::test]
async fn admin_routes_require_an_admin_session() {
    let server = Server::start();
    let session = server.register_first().await;
    let token = server
        .mint_token(
            &session,
            json!(["resource:read", "resource:write", "project:admin"]),
        )
        .await;
    let (friend, _) = register_invited(&server, &session, "friend@example.com").await;

    for path in ["/v1/admin/users", "/v1/admin/projects", "/v1/admin/invites"] {
        let anon = server.get(path, None).await;
        assert_eq!(anon.status, StatusCode::UNAUTHORIZED, "{path}");

        let via_token = server.get(path, Some(&token)).await;
        assert_eq!(via_token.status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(via_token.s("error"), "session_required", "{path}");

        let member = server.get(path, Some(&session_header(&friend))).await;
        assert_eq!(member.status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(member.s("error"), "admin_required", "{path}");

        let admin = server.get(path, Some(&session_header(&session))).await;
        assert_eq!(admin.status, StatusCode::OK, "{path}: {:?}", admin.body);
        assert!(admin.body.as_array().is_some(), "{path} returns a list");
    }
}

#[tokio::test]
async fn an_admin_lists_every_user_and_cannot_disable_themselves() {
    let server = Server::start();
    let session = server.register_first().await;
    let (friend_session, friend_id) =
        register_invited(&server, &session, "friend@example.com").await;

    let users = server
        .get("/v1/admin/users", Some(&session_header(&session)))
        .await;
    assert_eq!(users.status, StatusCode::OK);
    let rows = users.body.as_array().unwrap();
    assert_eq!(rows.len(), 2, "{:?}", users.body);
    assert!(
        rows.iter()
            .any(|u| u["email"] == "wk@example.com" && u["is_admin"] == true),
        "{:?}",
        users.body
    );
    assert!(
        rows.iter()
            .any(|u| u["email"] == "friend@example.com" && u["is_admin"] == false),
        "{:?}",
        users.body
    );

    let me = server.get("/v1/me", Some(&session_header(&session))).await;
    let my_id = me.body["user"]["id"].as_str().unwrap();
    let self_disable = server
        .patch(
            &format!("/v1/admin/users/{my_id}"),
            Some(&session_header(&session)),
            json!({ "disabled": true }),
        )
        .await;
    assert_eq!(self_disable.status, StatusCode::FORBIDDEN);
    assert_eq!(self_disable.s("error"), "cannot_disable_self");

    let disabled = server
        .patch(
            &format!("/v1/admin/users/{friend_id}"),
            Some(&session_header(&session)),
            json!({ "disabled": true }),
        )
        .await;
    assert_eq!(disabled.status, StatusCode::OK, "{:?}", disabled.body);
    assert!(disabled.body["disabled_at"].as_i64().is_some());

    // Their session is gone, login is refused, and an old cookie is dead.
    assert_eq!(
        server
            .get("/v1/me", Some(&session_header(&friend_session)))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let login = server
        .post(
            "/v1/auth/login",
            None,
            json!({ "email": "friend@example.com", "password": "a sufficiently long one" }),
        )
        .await;
    assert_eq!(login.status, StatusCode::UNAUTHORIZED);
    assert_eq!(login.s("error"), "account_disabled");

    let enabled = server
        .patch(
            &format!("/v1/admin/users/{friend_id}"),
            Some(&session_header(&session)),
            json!({ "disabled": false }),
        )
        .await;
    assert_eq!(enabled.status, StatusCode::OK);
    assert!(enabled.body["disabled_at"].is_null());
    let back = server
        .post(
            "/v1/auth/login",
            None,
            json!({ "email": "friend@example.com", "password": "a sufficiently long one" }),
        )
        .await;
    assert_eq!(back.status, StatusCode::OK, "{:?}", back.body);
}

/// Visibility has no other write path. Making a project public is what lets
/// any signed-in account see it; making it private hides it from everyone
/// except the owner (and an admin session).
#[tokio::test]
async fn an_admin_can_toggle_any_projects_visibility() {
    let server = Server::start();
    let session = server.register_first().await;
    let (friend_session, _) = register_invited(&server, &session, "friend@example.com").await;
    let friend_token = server
        .mint_token(&friend_session, json!(["resource:write", "resource:read"]))
        .await;
    let created = server
        .post(
            "/v1/projects/friends.notes/resources:inline",
            Some(&friend_token),
            json!({
                "kind": "doc",
                "slug": "notes",
                "title": "notes",
                "contents": [],
            }),
        )
        .await;
    assert!(created.status.is_success(), "{:?}", created.body);

    let listed = server
        .get("/v1/admin/projects", Some(&session_header(&session)))
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    let rows = listed.body.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["slug"], "friends.notes");
    assert_eq!(rows[0]["is_public"], false);
    assert_eq!(rows[0]["owner"]["email"], "friend@example.com");

    // Admin session can open someone else's private project; their token cannot.
    let admin_read = server
        .get(
            "/v1/projects/friends.notes/resources",
            Some(&session_header(&session)),
        )
        .await;
    assert_eq!(admin_read.status, StatusCode::OK, "{:?}", admin_read.body);
    let admin_token = server.mint_token(&session, json!(["resource:read"])).await;
    let token_read = server
        .get("/v1/projects/friends.notes/resources", Some(&admin_token))
        .await;
    assert_eq!(token_read.status, StatusCode::NOT_FOUND);

    let opened = server
        .patch(
            "/v1/admin/projects/friends.notes",
            Some(&session_header(&session)),
            json!({ "is_public": true }),
        )
        .await;
    assert_eq!(opened.status, StatusCode::OK, "{:?}", opened.body);
    assert_eq!(opened.body["is_public"], true);

    assert_eq!(
        server
            .get("/v1/projects/friends.notes/resources", None)
            .await
            .status,
        StatusCode::UNAUTHORIZED,
        "public still requires a login"
    );

    let closed = server
        .patch(
            "/v1/admin/projects/friends.notes",
            Some(&session_header(&session)),
            json!({ "is_public": false }),
        )
        .await;
    assert_eq!(closed.status, StatusCode::OK);
    assert_eq!(
        server
            .get("/v1/projects/friends.notes/resources", None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn the_admin_page_is_only_for_an_admin_session() {
    let server = Server::start();
    let session = server.register_first().await;
    let (friend, _) = register_invited(&server, &session, "friend@example.com").await;

    let (anon, _) = server.get_html("/admin", None).await;
    assert_eq!(anon, StatusCode::SEE_OTHER);

    let (member, _) = server.get_html("/admin", Some(&friend)).await;
    assert_eq!(member, StatusCode::NOT_FOUND);
    let (_, member_home) = server.get_html("/", Some(&friend)).await;
    assert!(
        !member_home.contains("href=\"/admin\""),
        "a member must not see the admin link: {member_home}"
    );

    let (status, html) = server.get_html("/admin", Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("administration"), "{html}");
    assert!(html.contains("admin.js"), "{html}");

    let invites = server
        .get("/v1/admin/invites", Some(&session_header(&session)))
        .await;
    assert_eq!(invites.status, StatusCode::OK);
    let rows = invites.body.as_array().unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the invite that admitted the friend: {:?}",
        invites.body
    );
    assert!(rows[0]["used_at"].as_i64().is_some());
    assert_eq!(rows[0]["used_by"]["email"], "friend@example.com");
}
