// Xenon — accounts, sessions, invites, and API tokens.
//
// Bootstrap has no seeded credential: the first account to register becomes the
// admin. After that, registration requires either an admin-issued invite code
// or XENON_ALLOW_SIGNUP=1, so a public-internet instance is closed by default.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::{self, Actor};
use crate::error::{AppError, AppResult};
use crate::event;
use crate::state::AppState;
use crate::util::{new_id, now, random_base32, sha256_hex};

pub const INVITE_TTL_SECS: i64 = 60 * 60 * 24 * 7;
const MAX_LABEL_LEN: usize = 120;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/auth/register", post(register))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/me", get(me))
        .route("/v1/invites", post(create_invite))
        .route("/v1/tokens", post(create_token).get(list_tokens))
        .route("/v1/tokens/{id}", delete(revoke_token))
}

// ------------------------------------------------------------------ payloads

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub invite: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct UserView {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub is_admin: bool,
    pub created_at: i64,
}

#[derive(Serialize)]
pub struct TokenView {
    pub id: String,
    pub label: String,
    pub scopes: Vec<String>,
    pub project: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

#[derive(Serialize)]
pub struct MeResponse {
    pub user: UserView,
    pub projects: Vec<ProjectView>,
    pub tokens: Vec<TokenView>,
}

#[derive(Serialize)]
pub struct ProjectView {
    pub id: String,
    pub slug: String,
    pub is_public: bool,
    pub created_at: i64,
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub label: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub expires_in_days: Option<i64>,
}

#[derive(Serialize)]
pub struct CreateTokenResponse {
    pub id: String,
    /// The only time the secret is ever returned.
    pub token: String,
    pub scopes: Vec<String>,
    pub project: Option<String>,
    pub expires_at: Option<i64>,
}

#[derive(Serialize)]
pub struct InviteResponse {
    pub code: String,
    pub expires_at: i64,
}

// ----------------------------------------------------------------- handlers

async fn register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> AppResult<Response> {
    let email = normalize_email(&req.email)?;
    let display_name = match req.display_name.as_deref().map(str::trim) {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => email.split('@').next().unwrap_or("user").to_string(),
    };
    // Hash before taking the lock — argon2 is deliberately slow.
    let password_hash = auth::hash_password(&req.password)?;

    let conn = state.db();
    let user_count: i64 = conn.query_row("SELECT count(*) FROM user", [], |r| r.get(0))?;
    let is_first_user = user_count == 0;

    // The first account bootstraps the instance and needs no invite. After
    // that, registration is closed unless explicitly opened or invited.
    let mut consumed_invite: Option<String> = None;
    if !is_first_user && !state.config.allow_signup {
        let code = req
            .invite
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .ok_or_else(|| {
                AppError::forbidden("signup_closed", "registration requires an invite code")
            })?;
        consumed_invite = Some(claim_invite(&conn, code)?);
    }

    let user_id = new_id("usr_").map_err(AppError::internal)?;
    let created = conn.execute(
        "INSERT INTO user (id, email, display_name, password_hash, is_admin, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            user_id,
            email,
            display_name,
            password_hash,
            i64::from(is_first_user),
            now()
        ],
    );
    if let Err(e) = created {
        // Do not distinguish "email taken" from other failures in the message —
        // the endpoint must not become an account-existence oracle.
        log::warn!("registration rejected for a duplicate or invalid account: {e}");
        return Err(AppError::conflict(
            "registration_failed",
            "could not create this account; if you already have one, log in instead",
        ));
    }
    if let Some(code_hash) = consumed_invite {
        conn.execute(
            "UPDATE invite SET used_by = ?1, used_at = ?2 WHERE code_hash = ?3",
            params![user_id, now(), code_hash],
        )?;
        event::record(
            &conn,
            event::New::account(event::INVITE_CLAIM, &display_name, &email)
                .actor_id(Some(&user_id)),
        )?;
    }
    event::record_and_prune(
        &state,
        &conn,
        event::New::account(event::ACCOUNT_REGISTER, &display_name, &email)
            .actor_id(Some(&user_id))
            .detail(serde_json::json!({ "ip": client_ip(&headers), "admin": is_first_user })),
    )?;

    let session = start_session(&conn, &user_id, &headers)?;
    let user = load_user(&conn, &user_id)?;
    drop(conn);

    Ok((
        StatusCode::CREATED,
        [(
            axum::http::header::SET_COOKIE,
            auth::session_cookie(
                &session,
                state.config.insecure_cookies,
                auth::SESSION_TTL_SECS,
            ),
        )],
        Json(user),
    )
        .into_response())
}

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> AppResult<Response> {
    let email = normalize_email(&req.email)?;
    let bucket = format!("{}|{}", client_ip(&headers), email);
    check_login_rate(&state, &bucket)?;

    // One generic failure for both unknown-email and wrong-password, so the
    // endpoint cannot be used to enumerate which accounts exist.
    let rejected = || AppError::unauthorized("invalid_credentials", "incorrect email or password");

    let conn = state.db();
    let found = conn
        .query_row(
            "SELECT id, password_hash, disabled_at FROM user WHERE email = ?1",
            [&email],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .optional()?;

    // A failure for an email nobody owns is recorded with no actor, so only an
    // admin can ever see it. Attaching it to an account — or showing it to
    // anyone else — would rebuild the account-existence oracle that the generic
    // error above exists to prevent.
    let record_failure = |user_id: Option<&str>| {
        // A known account is named; an unknown email is "someone", because
        // there is nobody to name and inventing one would be a guess.
        let who = user_id
            .map(|id| event::actor_name(&conn, id))
            .unwrap_or_else(|| "someone".to_string());
        event::record(
            &conn,
            event::New::account(event::ACCOUNT_LOGIN_FAILED, &who, &email)
                .actor_id(user_id)
                .detail(serde_json::json!({ "ip": client_ip(&headers) })),
        )
    };

    let Some((user_id, password_hash, disabled_at)) = found else {
        // Still spend the hashing time so timing does not reveal existence.
        let _ = auth::verify_password(&req.password, DUMMY_HASH);
        record_failure(None)?;
        return Err(rejected());
    };
    if !auth::verify_password(&req.password, &password_hash) {
        record_failure(Some(&user_id))?;
        return Err(rejected());
    }
    if disabled_at.is_some() {
        return Err(AppError::unauthorized(
            "account_disabled",
            "this account is disabled",
        ));
    }

    clear_login_rate(&state, &bucket);
    let session = start_session(&conn, &user_id, &headers)?;
    let user = load_user(&conn, &user_id)?;
    event::record_and_prune(
        &state,
        &conn,
        event::New::account(event::ACCOUNT_LOGIN, &user.display_name, &email)
            .actor_id(Some(&user_id))
            .detail(serde_json::json!({
                "ip": client_ip(&headers),
                "user_agent": user_agent(&headers),
            })),
    )?;
    drop(conn);

    Ok((
        [(
            axum::http::header::SET_COOKIE,
            auth::session_cookie(
                &session,
                state.config.insecure_cookies,
                auth::SESSION_TTL_SECS,
            ),
        )],
        Json(user),
    )
        .into_response())
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> AppResult<Response> {
    {
        let conn = state.db();
        // `end_session` records the sign-out itself, so both this route and the
        // browse UI's form log it identically.
        auth::end_session(&conn, &headers)?;
    }
    Ok((
        [(
            axum::http::header::SET_COOKIE,
            auth::clear_session_cookie(state.config.insecure_cookies),
        )],
        Json(serde_json::json!({ "ok": true })),
    )
        .into_response())
}

async fn me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> AppResult<Json<MeResponse>> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;
    let user = load_user(&conn, &actor.user_id)?;

    let mut stmt = conn.prepare(
        "SELECT id, slug, is_public, created_at FROM project WHERE owner_id = ?1 ORDER BY slug",
    )?;
    let projects = stmt
        .query_map([&actor.user_id], |r| {
            Ok(ProjectView {
                id: r.get(0)?,
                slug: r.get(1)?,
                is_public: r.get::<_, i64>(2)? != 0,
                created_at: r.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(MeResponse {
        user,
        projects,
        tokens: load_tokens(&conn, &actor.user_id)?,
    }))
}

async fn create_invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> AppResult<Json<InviteResponse>> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;
    actor.require_session()?;
    actor.require_admin()?;

    let code = random_base32(24).map_err(AppError::internal)?;
    let expires_at = now() + INVITE_TTL_SECS;
    conn.execute(
        "INSERT INTO invite (code_hash, created_by, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            sha256_hex(code.as_bytes()),
            actor.user_id,
            now(),
            expires_at
        ],
    )?;
    event::record(
        &conn,
        event::New::account(
            event::INVITE_CREATE,
            &event::actor_name(&conn, &actor.user_id),
            "an invite code",
        )
        .by(&actor)
        .detail(serde_json::json!({ "expires_at": expires_at })),
    )?;
    Ok(Json(InviteResponse { code, expires_at }))
}

async fn create_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateTokenRequest>,
) -> AppResult<(StatusCode, Json<CreateTokenResponse>)> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;
    // The escalation guard: minting requires a session, so a stolen token
    // cannot mint a fresh one that outlives its own revocation.
    actor.require_session()?;

    let label = req.label.trim();
    if label.is_empty() || label.len() > MAX_LABEL_LEN {
        return Err(AppError::bad_request(
            "invalid_label",
            format!("label must be 1..={MAX_LABEL_LEN} characters"),
        ));
    }
    let scopes = auth::validate_scopes(&req.scopes)?;

    // A token may only be bound to a project its own user already owns.
    let project_id = match req
        .project
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        None => None,
        Some(slug) => Some(
            conn.query_row(
                "SELECT id FROM project WHERE slug = ?1 AND owner_id = ?2",
                params![slug, actor.user_id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| AppError::not_found(format!("no project {slug} owned by you")))?,
        ),
    };

    let expires_at = match req.expires_in_days {
        None => None,
        Some(days) if days > 0 => Some(now() + days * 86_400),
        Some(_) => {
            return Err(AppError::bad_request(
                "invalid_expiry",
                "expires_in_days must be a positive number of days",
            ))
        }
    };

    let minted = auth::mint_token()?;
    conn.execute(
        "INSERT INTO token (id, hash, user_id, project_id, label, scopes, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            minted.id,
            minted.hash,
            actor.user_id,
            project_id,
            label,
            scopes,
            now(),
            expires_at
        ],
    )?;
    event::record_and_prune(
        &state,
        &conn,
        event::New::account(
            event::TOKEN_CREATE,
            &event::actor_name(&conn, &actor.user_id),
            label,
        )
        .by(&actor)
        .detail(serde_json::json!({
            "token_id": minted.id,
            "scopes": auth::parse_scopes(&scopes),
            "project": req.project,
        })),
    )?;

    Ok((
        StatusCode::CREATED,
        Json(CreateTokenResponse {
            id: minted.id,
            token: minted.plaintext,
            scopes: auth::parse_scopes(&scopes),
            project: req.project,
            expires_at,
        }),
    ))
}

async fn list_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<TokenView>>> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;
    actor.require_session()?;
    Ok(Json(load_tokens(&conn, &actor.user_id)?))
}

async fn revoke_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;
    actor.require_session()?;

    // The label is read before the update so the event can name the token the
    // way its owner does, not by its opaque id.
    let label: Option<String> = conn
        .query_row(
            "SELECT label FROM token WHERE id = ?1 AND user_id = ?2 AND revoked_at IS NULL",
            params![id, actor.user_id],
            |r| r.get(0),
        )
        .optional()?;

    let affected = conn.execute(
        "UPDATE token SET revoked_at = ?1
         WHERE id = ?2 AND user_id = ?3 AND revoked_at IS NULL",
        params![now(), id, actor.user_id],
    )?;
    if affected == 0 {
        return Err(AppError::not_found("no such active token"));
    }
    event::record(
        &conn,
        event::New::account(
            event::TOKEN_REVOKE,
            &event::actor_name(&conn, &actor.user_id),
            label.as_deref().unwrap_or(&id),
        )
        .by(&actor)
        .detail(serde_json::json!({ "token_id": id })),
    )?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------------ helpers

/// A valid argon2 hash of a value nobody knows, used to keep the failure path
/// of an unknown email as slow as a real verification.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$\
                          x3ZQ0lqKk3xHc6y1lTMYQvKUW7bHhTFPfQ0PbYqvUxE";

pub fn normalize_email(raw: &str) -> AppResult<String> {
    let email = raw.trim().to_lowercase();
    let valid = email.len() >= 3
        && email.len() <= 254
        && email.matches('@').count() == 1
        && !email.starts_with('@')
        && !email.ends_with('@')
        && !email.contains(char::is_whitespace)
        && email
            .split('@')
            .nth(1)
            .is_some_and(|d| d.contains('.') && !d.starts_with('.'));
    if !valid {
        return Err(AppError::bad_request(
            "invalid_email",
            "that is not a valid email address",
        ));
    }
    Ok(email)
}

fn claim_invite(conn: &Connection, code: &str) -> AppResult<String> {
    let code_hash = sha256_hex(code.as_bytes());
    let expires_at: Option<i64> = conn
        .query_row(
            "SELECT expires_at FROM invite WHERE code_hash = ?1 AND used_at IS NULL",
            [&code_hash],
            |r| r.get(0),
        )
        .optional()?;
    let Some(expires_at) = expires_at else {
        return Err(AppError::forbidden(
            "invalid_invite",
            "that invite code is not valid",
        ));
    };
    if expires_at <= now() {
        return Err(AppError::forbidden(
            "invalid_invite",
            "that invite code has expired",
        ));
    }
    Ok(code_hash)
}

/// The client's `User-Agent`, bounded. Shared by the session row and the
/// activity log so both record the same thing.
fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(200).collect::<String>())
}

fn start_session(conn: &Connection, user_id: &str, headers: &HeaderMap) -> AppResult<String> {
    let session = auth::mint_session()?;
    let agent = user_agent(headers);
    conn.execute(
        "INSERT INTO session (id, user_id, created_at, expires_at, user_agent)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            session.id,
            user_id,
            now(),
            now() + auth::SESSION_TTL_SECS,
            agent
        ],
    )?;
    Ok(session.value)
}

fn load_user(conn: &Connection, user_id: &str) -> AppResult<UserView> {
    conn.query_row(
        "SELECT id, email, display_name, is_admin, created_at FROM user WHERE id = ?1",
        [user_id],
        |r| {
            Ok(UserView {
                id: r.get(0)?,
                email: r.get(1)?,
                display_name: r.get(2)?,
                is_admin: r.get::<_, i64>(3)? != 0,
                created_at: r.get(4)?,
            })
        },
    )
    .optional()?
    .ok_or_else(|| AppError::not_found("user no longer exists"))
}

fn load_tokens(conn: &Connection, user_id: &str) -> AppResult<Vec<TokenView>> {
    let mut stmt = conn.prepare(
        "SELECT t.id, t.label, t.scopes, p.slug, t.created_at, t.expires_at, t.last_used_at
         FROM token t LEFT JOIN project p ON p.id = t.project_id
         WHERE t.user_id = ?1 AND t.revoked_at IS NULL
         ORDER BY t.created_at DESC",
    )?;
    let rows = stmt
        .query_map([user_id], |r| {
            Ok(TokenView {
                id: r.get(0)?,
                label: r.get(1)?,
                scopes: auth::parse_scopes(&r.get::<_, String>(2)?),
                project: r.get(3)?,
                created_at: r.get(4)?,
                expires_at: r.get(5)?,
                last_used_at: r.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Behind a reverse proxy the socket peer is the proxy, so the forwarded header
/// is the only useful discriminator. It is client-controlled and therefore
/// spoofable — this is rate-limiting granularity, never an authorization input.
fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn check_login_rate(state: &AppState, bucket: &str) -> AppResult<()> {
    let mut attempts = state
        .login_attempts
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let cutoff = now() - auth::LOGIN_WINDOW_SECS;

    // Opportunistically drop expired buckets so the map cannot grow without
    // bound under a spray of distinct emails.
    attempts.retain(|_, times| {
        times.retain(|t| *t > cutoff);
        !times.is_empty()
    });

    let entry = attempts.entry(bucket.to_string()).or_default();
    if entry.len() >= auth::LOGIN_MAX_ATTEMPTS {
        return Err(AppError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many login attempts; try again in a few minutes",
        ));
    }
    entry.push(now());
    Ok(())
}

fn clear_login_rate(state: &AppState, bucket: &str) {
    let mut attempts = state
        .login_attempts
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    attempts.remove(bucket);
}

/// Resolves the project a write is targeting, creating it on first push under
/// the actor's ownership. Shared by the ingest routes.
pub fn resolve_or_create_project(
    conn: &Connection,
    actor: &Actor,
    slug: &str,
) -> AppResult<String> {
    if !crate::util::is_valid_slug(slug) {
        return Err(AppError::bad_request(
            "invalid_project",
            "malformed project slug",
        ));
    }

    let existing: Option<(String, String)> = conn
        .query_row(
            "SELECT id, owner_id FROM project WHERE slug = ?1",
            [slug],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;

    if let Some((id, owner_id)) = existing {
        if owner_id != actor.user_id {
            // Deliberately "not found" rather than "forbidden": a caller who
            // does not own a project should not learn that it exists.
            return Err(AppError::not_found(format!("no project {slug}")));
        }
        assert_token_project(actor, &id)?;
        return Ok(id);
    }

    // A project-bound token cannot conjure a second project.
    if actor.token_project().is_some() {
        return Err(AppError::forbidden(
            "project_scoped_token",
            "this token is bound to a different project and cannot create a new one",
        ));
    }

    let id = new_id("prj_").map_err(AppError::internal)?;
    conn.execute(
        "INSERT INTO project (id, slug, owner_id, is_public, created_at)
         VALUES (?1, ?2, ?3, 0, ?4)",
        params![id, slug, actor.user_id, now()],
    )?;
    crate::event::record(
        conn,
        crate::event::New::project_scoped(
            crate::event::PROJECT_CREATE,
            &crate::event::actor_name(conn, &actor.user_id),
            slug,
        )
        .by(actor)
        .in_project(&id, slug),
    )?;
    Ok(id)
}

pub fn assert_token_project(actor: &Actor, project_id: &str) -> AppResult<()> {
    match actor.token_project() {
        None => Ok(()),
        Some(bound) if bound == project_id => Ok(()),
        Some(_) => Err(AppError::forbidden(
            "project_scoped_token",
            "this token is bound to a different project",
        )),
    }
}
