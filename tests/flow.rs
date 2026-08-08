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

    assert!(html.contains("&lt;img src=x"), "the title must be escaped");
    assert!(
        !html.contains("<img src=x onerror"),
        "unescaped title would be an XSS sink"
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
