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

    /// A browse-UI page as raw HTML. `send` parses JSON, which an HTML response
    /// is not, so the body has to be read separately here.
    async fn get_html(&self, path: &str, session: Option<&str>) -> (StatusCode, String) {
        let mut req = Request::get(path);
        if let Some(session) = session {
            req = req.header(header::COOKIE, format!("xenon_session={session}"));
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
        let response = self
            .app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
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
        let mut req = Request::post(path);
        if let Some(session) = session {
            req = req.header(header::COOKIE, format!("xenon_session={session}"));
        }
        let response = self
            .app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
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
async fn anonymous_callers_see_public_projects_only() {
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

    let anon = server.get("/v1/projects", None).await;
    assert!(
        anon.body.as_array().unwrap().is_empty(),
        "private projects must not be listed"
    );
    assert_eq!(
        server
            .get("/v1/projects/krypton/resources", None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    // A bad credential is an error, never a silent downgrade to anonymous.
    let bogus = server
        .get("/v1/projects", Some("xen_aaaaaaaaaaaa_bbbbbbbb"))
        .await;
    assert_eq!(bogus.status, StatusCode::UNAUTHORIZED);
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
}

/// The nav tells the reader who they are. It was static markup — every page
/// offered "sign in" to a reader who was already signed in, and a `tokens` link
/// that only bounced an anonymous one back to the login form.
#[tokio::test]
async fn the_nav_reflects_who_is_reading() {
    let server = Server::start();
    let session = server.register_first().await;

    let (_, anonymous) = server.get_html("/", None).await;
    assert!(
        anonymous.contains("<a href=\"/login\">sign in</a>"),
        "an anonymous reader needs the way in: {anonymous}"
    );
    assert!(
        !anonymous.contains("/settings/tokens"),
        "the tokens link only bounces an anonymous reader back: {anonymous}"
    );
    assert!(!anonymous.contains("sign out"), "{anonymous}");

    // Every page carries the same chrome, so check one of each shape.
    for path in ["/", "/login", "/settings/tokens"] {
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
    }
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
    let (_, html) = server.get_html("/", Some(&session)).await;
    assert!(html.contains("<a href=\"/login\">sign in</a>"), "{html}");
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
    assert!(
        anonymous.body["events"].as_array().unwrap().is_empty(),
        "nothing here is public: {:?}",
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

    // The nav offers both, and names the root as activity.
    assert!(home.contains("<a href=\"/\">activity</a>"), "{home}");
    assert!(
        home.contains("<a href=\"/projects\">projects</a>"),
        "{home}"
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
    assert_eq!(anon.status, StatusCode::NOT_FOUND, "{:?}", anon.body);
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
