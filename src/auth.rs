// Xenon — authentication and authorization.
//
// Two credential types reach a handler:
//   * a session cookie, held by a logged-in human in a browser;
//   * a bearer token, held by a machine (a Krypton install, or an external
//     service integration).
//
// The asymmetry that matters: a token can never mint another token. Token
// creation requires a session, so a leaked integration token cannot escalate
// into a permanent foothold — it can only do what its scopes already allow.

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use axum::http::HeaderMap;
use rusqlite::{Connection, OptionalExtension};

use crate::error::{AppError, AppResult};
use crate::util::{constant_time_eq, now, random_base32, random_bytes, sha256_hex};

pub const SESSION_COOKIE: &str = "xenon_session";
pub const SESSION_TTL_SECS: i64 = 60 * 60 * 24 * 30;
pub const TOKEN_PREFIX: &str = "xen_";

/// Login attempts allowed per (ip, email) inside the window.
pub const LOGIN_MAX_ATTEMPTS: usize = 5;
pub const LOGIN_WINDOW_SECS: i64 = 15 * 60;

pub const SCOPE_RESOURCE_READ: &str = "resource:read";
pub const SCOPE_RESOURCE_WRITE: &str = "resource:write";
pub const SCOPE_PROJECT_ADMIN: &str = "project:admin";

pub const ALL_SCOPES: [&str; 3] = [
    SCOPE_RESOURCE_READ,
    SCOPE_RESOURCE_WRITE,
    SCOPE_PROJECT_ADMIN,
];

// ---------------------------------------------------------------- passwords

pub const MIN_PASSWORD_LEN: usize = 12;

pub fn hash_password(password: &str) -> AppResult<String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(AppError::bad_request(
            "weak_password",
            format!("password must be at least {MIN_PASSWORD_LEN} characters"),
        ));
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::internal(format!("password hashing failed: {e}")))
}

pub fn verify_password(password: &str, encoded: &str) -> bool {
    match PasswordHash::new(encoded) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

// ------------------------------------------------------------------- actors

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthVia {
    Session,
    Token {
        token_id: String,
        scopes: Vec<String>,
        project_id: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub user_id: String,
    pub is_admin: bool,
    pub via: AuthVia,
}

impl Actor {
    pub fn is_session(&self) -> bool {
        matches!(self.via, AuthVia::Session)
    }

    /// A session carries the user's full authority. A token carries only its
    /// granted scopes, and — when bound to a project — only for that project.
    pub fn has_scope(&self, scope: &str) -> bool {
        match &self.via {
            AuthVia::Session => true,
            AuthVia::Token { scopes, .. } => scopes.iter().any(|s| s == scope),
        }
    }

    pub fn token_project(&self) -> Option<&str> {
        match &self.via {
            AuthVia::Session => None,
            AuthVia::Token { project_id, .. } => project_id.as_deref(),
        }
    }

    /// Which token authenticated this request, if one did. Recorded on activity
    /// rows so a machine push is attributable to the credential behind it, not
    /// just to the human who owns it.
    pub fn token_id(&self) -> Option<&str> {
        match &self.via {
            AuthVia::Session => None,
            AuthVia::Token { token_id, .. } => Some(token_id),
        }
    }

    pub fn require_scope(&self, scope: &'static str) -> AppResult<()> {
        if self.has_scope(scope) {
            return Ok(());
        }
        Err(AppError::forbidden(
            "missing_scope",
            format!("token lacks the {scope} scope"),
        ))
    }

    /// Tokens may not mint tokens, manage invites, or change account settings.
    pub fn require_session(&self) -> AppResult<()> {
        if self.is_session() {
            return Ok(());
        }
        Err(AppError::forbidden(
            "session_required",
            "this operation requires a logged-in session; API tokens cannot perform it",
        ))
    }

    pub fn require_admin(&self) -> AppResult<()> {
        if self.is_admin {
            return Ok(());
        }
        Err(AppError::forbidden(
            "admin_required",
            "this operation requires an admin account",
        ))
    }
}

// ------------------------------------------------------------------ scopes

pub fn parse_scopes(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

pub fn validate_scopes(scopes: &[String]) -> AppResult<String> {
    if scopes.is_empty() {
        return Err(AppError::bad_request(
            "invalid_scopes",
            "at least one scope is required",
        ));
    }
    for scope in scopes {
        if !ALL_SCOPES.contains(&scope.as_str()) {
            return Err(AppError::bad_request(
                "invalid_scopes",
                format!(
                    "unknown scope {scope}; valid scopes are {}",
                    ALL_SCOPES.join(", ")
                ),
            ));
        }
    }
    let mut unique: Vec<&String> = scopes.iter().collect();
    unique.sort();
    unique.dedup();
    Ok(unique
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(","))
}

// ------------------------------------------------------------------ tokens

pub struct MintedToken {
    pub id: String,
    /// The full `xen_<id>_<secret>` string. Returned to the caller exactly once
    /// and never persisted — only the secret's sha256 is stored.
    pub plaintext: String,
    pub hash: String,
}

pub fn mint_token() -> AppResult<MintedToken> {
    let id = random_base32(12).map_err(AppError::internal)?;
    let secret = random_base32(32).map_err(AppError::internal)?;
    let hash = sha256_hex(secret.as_bytes());
    Ok(MintedToken {
        plaintext: format!("{TOKEN_PREFIX}{id}_{secret}"),
        id,
        hash,
    })
}

/// Splits `xen_<id>_<secret>`. Returns None for anything malformed, so a
/// garbage header is rejected before it reaches the database.
pub fn split_token(raw: &str) -> Option<(&str, &str)> {
    let body = raw.strip_prefix(TOKEN_PREFIX)?;
    let (id, secret) = body.split_once('_')?;
    if id.is_empty() || secret.is_empty() {
        return None;
    }
    Some((id, secret))
}

// ---------------------------------------------------------------- sessions

pub struct MintedSession {
    /// The cookie value handed to the browser.
    pub value: String,
    /// sha256 of the value — this is what `session.id` stores.
    pub id: String,
}

pub fn mint_session() -> AppResult<MintedSession> {
    let value = crate::util::hex(&random_bytes(32).map_err(AppError::internal)?);
    let id = sha256_hex(value.as_bytes());
    Ok(MintedSession { value, id })
}

pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let (key, value) = pair.split_once('=')?;
        if key.trim() == name {
            return Some(value.trim().to_string());
        }
    }
    None
}

pub fn session_cookie(value: &str, insecure: bool, max_age: i64) -> String {
    // SameSite=Lax keeps the cookie off cross-site POSTs (so a hostile page
    // cannot mint a token on the user's behalf) while surviving ordinary
    // top-level navigation into the browse UI.
    let secure = if insecure { "" } else { " Secure;" };
    format!("{SESSION_COOKIE}={value}; Path=/; HttpOnly;{secure} SameSite=Lax; Max-Age={max_age}")
}

pub fn clear_session_cookie(insecure: bool) -> String {
    session_cookie("", insecure, 0)
}

/// Delete the session this request's cookie points at, if it has one, and
/// record the sign-out. Shared by the JSON logout endpoint and the browse UI's
/// sign-out form so both mean the same thing by "signed out" — the row goes,
/// not just the cookie, so a copied cookie value is dead too.
///
/// The activity row is written here rather than in the two handlers for the
/// same reason: a sign-out that is only logged on one of two routes is worse
/// than one that is not logged at all, because the gap is invisible.
pub fn end_session(conn: &Connection, headers: &HeaderMap) -> AppResult<()> {
    let Some(value) = read_cookie(headers, SESSION_COOKIE) else {
        return Ok(());
    };
    let session_id = sha256_hex(value.as_bytes());

    // Who it was has to be read before the row is gone.
    let user: Option<(String, String, String)> = conn
        .query_row(
            "SELECT u.id, u.display_name, u.email
             FROM session s JOIN user u ON u.id = s.user_id
             WHERE s.id = ?1",
            [&session_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;

    conn.execute("DELETE FROM session WHERE id = ?1", [&session_id])?;

    if let Some((user_id, display_name, email)) = user {
        crate::event::record(
            conn,
            crate::event::New::account(crate::event::ACCOUNT_LOGOUT, &display_name, &email)
                .actor_id(Some(&user_id)),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------- authentication

fn bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let rest = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    let trimmed = rest.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Resolves the caller. Returns `Ok(None)` when no credential was supplied at
/// all (the caller decides whether that is allowed — public projects permit
/// anonymous reads); returns `Err` when a credential was supplied but is bad,
/// so a typo never silently degrades into an anonymous request.
pub fn authenticate(conn: &Connection, headers: &HeaderMap) -> AppResult<Option<Actor>> {
    if let Some(raw) = bearer(headers) {
        return Ok(Some(authenticate_token(conn, &raw)?));
    }
    if let Some(value) = read_cookie(headers, SESSION_COOKIE) {
        return Ok(Some(authenticate_session(conn, &value)?));
    }
    Ok(None)
}

pub fn authenticate_token(conn: &Connection, raw: &str) -> AppResult<Actor> {
    let invalid = || AppError::unauthorized("invalid_token", "invalid or revoked API token");

    let (id, secret) = split_token(raw).ok_or_else(invalid)?;
    let row = conn
        .query_row(
            "SELECT t.hash, t.user_id, t.project_id, t.scopes, t.expires_at, t.revoked_at,
                    u.is_admin, u.disabled_at
             FROM token t JOIN user u ON u.id = t.user_id
             WHERE t.id = ?1",
            [id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, Option<i64>>(7)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(invalid)?;

    let (hash, user_id, project_id, scopes, expires_at, revoked_at, is_admin, disabled_at) = row;

    if !constant_time_eq(&sha256_hex(secret.as_bytes()), &hash) {
        return Err(invalid());
    }
    // Revocation and expiry are checked per request with no caching, so an
    // in-flight multi-blob push starts failing at its very next call.
    if revoked_at.is_some() {
        return Err(invalid());
    }
    if disabled_at.is_some() {
        return Err(AppError::unauthorized(
            "account_disabled",
            "this account is disabled",
        ));
    }
    if expires_at.is_some_and(|at| at <= now()) {
        return Err(AppError::unauthorized(
            "token_expired",
            "this API token has expired",
        ));
    }

    conn.execute(
        "UPDATE token SET last_used_at = ?1 WHERE id = ?2",
        rusqlite::params![now(), id],
    )?;

    Ok(Actor {
        user_id,
        is_admin: is_admin != 0,
        via: AuthVia::Token {
            token_id: id.to_string(),
            scopes: parse_scopes(&scopes),
            project_id,
        },
    })
}

pub fn authenticate_session(conn: &Connection, cookie_value: &str) -> AppResult<Actor> {
    let invalid = || AppError::unauthorized("invalid_session", "session expired or invalid");

    let session_id = sha256_hex(cookie_value.as_bytes());
    let row = conn
        .query_row(
            "SELECT s.user_id, s.expires_at, u.is_admin, u.disabled_at
             FROM session s JOIN user u ON u.id = s.user_id
             WHERE s.id = ?1",
            [&session_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(invalid)?;

    let (user_id, expires_at, is_admin, disabled_at) = row;
    if expires_at <= now() {
        conn.execute("DELETE FROM session WHERE id = ?1", [&session_id])?;
        return Err(invalid());
    }
    if disabled_at.is_some() {
        return Err(AppError::unauthorized(
            "account_disabled",
            "this account is disabled",
        ));
    }

    Ok(Actor {
        user_id,
        is_admin: is_admin != 0,
        via: AuthVia::Session,
    })
}

/// Authenticated-or-bust, for endpoints with no anonymous mode.
pub fn require_actor(conn: &Connection, headers: &HeaderMap) -> AppResult<Actor> {
    authenticate(conn, headers)?
        .ok_or_else(|| AppError::unauthorized("unauthenticated", "authentication required"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trips_and_rejects_wrong_input() {
        let hash = hash_password("correct horse battery").unwrap();
        assert!(verify_password("correct horse battery", &hash));
        assert!(!verify_password("Correct horse battery", &hash));
        assert!(!verify_password("", &hash));
        // A stored value that isn't a PHC string must fail closed, not panic.
        assert!(!verify_password("anything", "not-a-hash"));
    }

    #[test]
    fn short_passwords_are_rejected_before_hashing() {
        let err = hash_password("short").unwrap_err();
        assert_eq!(err.code, "weak_password");
    }

    #[test]
    fn hashes_are_salted_so_equal_passwords_differ() {
        let a = hash_password("correct horse battery").unwrap();
        let b = hash_password("correct horse battery").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn minted_token_parses_back_and_matches_its_hash() {
        let minted = mint_token().unwrap();
        let (id, secret) = split_token(&minted.plaintext).expect("well-formed token");
        assert_eq!(id, minted.id);
        assert_eq!(sha256_hex(secret.as_bytes()), minted.hash);
        assert!(minted.plaintext.starts_with(TOKEN_PREFIX));
        // The plaintext secret must not be recoverable from what we store.
        assert!(!minted.hash.contains(secret));
    }

    #[test]
    fn split_token_rejects_malformed_input() {
        assert!(split_token("").is_none());
        assert!(split_token("xen_").is_none());
        assert!(split_token("xen_abc").is_none());
        assert!(split_token("xen__secret").is_none());
        assert!(split_token("ghp_abc_def").is_none());
    }

    #[test]
    fn scope_validation_rejects_unknown_and_dedupes() {
        assert_eq!(
            validate_scopes(&["resource:read".into(), "resource:read".into()]).unwrap(),
            "resource:read"
        );
        assert_eq!(
            validate_scopes(&["resource:write".into(), "resource:read".into()]).unwrap(),
            "resource:read,resource:write"
        );
        assert!(validate_scopes(&[]).is_err());
        assert!(validate_scopes(&["admin".into()]).is_err());
    }

    #[test]
    fn session_actor_has_every_scope_but_token_actor_does_not() {
        let session = Actor {
            user_id: "u".into(),
            is_admin: false,
            via: AuthVia::Session,
        };
        assert!(session.has_scope(SCOPE_RESOURCE_WRITE));
        assert!(session.require_session().is_ok());

        let token = Actor {
            user_id: "u".into(),
            is_admin: false,
            via: AuthVia::Token {
                token_id: "t".into(),
                scopes: vec![SCOPE_RESOURCE_WRITE.into()],
                project_id: None,
            },
        };
        assert!(token.has_scope(SCOPE_RESOURCE_WRITE));
        assert!(!token.has_scope(SCOPE_RESOURCE_READ));
        // The escalation guard: a token can never mint another token.
        assert_eq!(
            token.require_session().unwrap_err().code,
            "session_required"
        );
    }

    #[test]
    fn cookie_parsing_finds_the_named_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "other=1; xenon_session=abc123; trailing=2".parse().unwrap(),
        );
        assert_eq!(
            read_cookie(&headers, SESSION_COOKIE).as_deref(),
            Some("abc123")
        );
        assert_eq!(read_cookie(&headers, "nope"), None);
    }

    #[test]
    fn cookie_is_secure_unless_explicitly_insecure() {
        assert!(session_cookie("v", false, 100).contains("Secure"));
        assert!(!session_cookie("v", true, 100).contains("Secure"));
        assert!(session_cookie("v", false, 100).contains("HttpOnly"));
        assert!(session_cookie("v", false, 100).contains("SameSite=Lax"));
    }

    #[test]
    fn bearer_header_is_parsed_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer xen_a_b".parse().unwrap(),
        );
        assert_eq!(bearer(&headers).as_deref(), Some("xen_a_b"));
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "bearer xen_a_b".parse().unwrap(),
        );
        assert_eq!(bearer(&headers).as_deref(), Some("xen_a_b"));
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic abc".parse().unwrap(),
        );
        assert_eq!(bearer(&headers), None);
    }
}
