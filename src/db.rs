// Xenon — SQLite schema and connection handling.
//
// The database holds metadata only; file bytes live in the content-addressed
// blob store (`blob.rs`). Traffic is low enough that a single connection behind
// a mutex is the right call — it removes a pool dependency and makes the
// manifest/commit transactions trivially serialisable.

use rusqlite::Connection;
use std::path::Path;

pub const SCHEMA_VERSION: i64 = 3;

pub fn open(path: &Path) -> Result<Connection, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create data dir: {e}"))?;
    }
    let conn = Connection::open(path).map_err(|e| format!("open database: {e}"))?;
    configure(&conn)?;
    migrate(&conn)?;
    Ok(conn)
}

#[cfg(test)]
pub fn open_in_memory() -> Result<Connection, String> {
    let conn = Connection::open_in_memory().map_err(|e| format!("open database: {e}"))?;
    configure(&conn)?;
    migrate(&conn)?;
    Ok(conn)
}

fn configure(conn: &Connection) -> Result<(), String> {
    // WAL survives an unclean shutdown without losing committed revisions;
    // foreign_keys is off by default in SQLite and we rely on it for cascades.
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )
    .map_err(|e| format!("configure database: {e}"))
}

fn migrate(conn: &Connection) -> Result<(), String> {
    let current: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| format!("read schema version: {e}"))?;

    if current > SCHEMA_VERSION {
        return Err(format!(
            "database schema version {current} is newer than this binary supports ({SCHEMA_VERSION}); \
             upgrade xenon or restore an older data directory"
        ));
    }
    if current == SCHEMA_VERSION {
        return Ok(());
    }

    if current < 1 {
        conn.execute_batch(SCHEMA_V1)
            .map_err(|e| format!("apply schema v1: {e}"))?;
    }
    if current < 2 {
        conn.execute_batch(SCHEMA_V2)
            .map_err(|e| format!("apply schema v2: {e}"))?;
    }
    if current < 3 {
        conn.execute_batch(SCHEMA_V3)
            .map_err(|e| format!("apply schema v3: {e}"))?;
    }

    conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
        .map_err(|e| format!("stamp schema version: {e}"))?;
    Ok(())
}

/// Note on deletion policy: `resource`/`revision`/`rev_file` cascade from their
/// parent, but `user` deletion is intentionally NOT cascaded into `project` —
/// a disabled or removed account keeps its published work (see spec 212 edge
/// cases). Accounts are disabled via `user.disabled_at`, not deleted.
const SCHEMA_V1: &str = r#"
CREATE TABLE user (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    disabled_at   INTEGER
);

CREATE TABLE session (
    id         TEXT PRIMARY KEY,      -- sha256 of the cookie value, never the value itself
    user_id    TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    user_agent TEXT
);
CREATE INDEX session_user_idx ON session(user_id);

CREATE TABLE invite (
    code_hash  TEXT PRIMARY KEY,
    created_by TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_by    TEXT REFERENCES user(id) ON DELETE SET NULL,
    used_at    INTEGER
);

CREATE TABLE token (
    id           TEXT PRIMARY KEY,    -- public half, safe to display
    hash         TEXT NOT NULL UNIQUE,-- sha256 of the secret half
    user_id      TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    project_id   TEXT REFERENCES project(id) ON DELETE CASCADE,
    label        TEXT NOT NULL,
    scopes       TEXT NOT NULL,       -- comma-separated
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER,
    last_used_at INTEGER,
    revoked_at   INTEGER
);
CREATE INDEX token_user_idx ON token(user_id);

CREATE TABLE project (
    id         TEXT PRIMARY KEY,
    slug       TEXT NOT NULL UNIQUE,
    owner_id   TEXT NOT NULL REFERENCES user(id),
    is_public  INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE INDEX project_owner_idx ON project(owner_id);

CREATE TABLE resource (
    id            TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    slug          TEXT NOT NULL,
    title         TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    head_revision TEXT,
    UNIQUE(project_id, kind, slug)
);
CREATE INDEX resource_project_kind_idx ON resource(project_id, kind, updated_at DESC);

CREATE TABLE revision (
    id          TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL REFERENCES resource(id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    meta        TEXT NOT NULL,
    origin      TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    sealed_at   INTEGER,              -- NULL until commit; an open revision is invisible
    UNIQUE(resource_id, seq)
);
CREATE INDEX revision_resource_idx ON revision(resource_id, seq DESC);

CREATE TABLE rev_file (
    revision_id  TEXT NOT NULL REFERENCES revision(id) ON DELETE CASCADE,
    path         TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    size         INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    PRIMARY KEY(revision_id, path)
);
CREATE INDEX rev_file_sha_idx ON rev_file(sha256);

CREATE TABLE blob (
    sha256     TEXT PRIMARY KEY,
    size       INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
"#;

/// v2 — the activity log (spec `docs/03-activity-feed.md`).
///
/// Every foreign key is `ON DELETE SET NULL` and every human-readable field is
/// frozen at write time: a feed row has to still render after its project,
/// resource, or account is gone. An append-only log that loses rows when
/// something is deleted is not a log.
///
/// `audience` says where visibility comes from, not what it is — `project` rows
/// follow their project's current `is_public`, `account` rows are for their own
/// user (and an admin). Deciding it on read rather than freezing a flag is the
/// one place this diverges from Gitea's `action` table; see the spec.
const SCHEMA_V2: &str = r#"
CREATE TABLE event (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    audience     TEXT NOT NULL,
    actor_id     TEXT REFERENCES user(id) ON DELETE SET NULL,
    actor_name   TEXT NOT NULL,
    project_id   TEXT REFERENCES project(id) ON DELETE SET NULL,
    project_slug TEXT,
    resource_id  TEXT REFERENCES resource(id) ON DELETE SET NULL,
    subject      TEXT NOT NULL,
    detail       TEXT NOT NULL DEFAULT '{}',
    created_at   INTEGER NOT NULL
);
CREATE INDEX event_time_idx    ON event(created_at DESC);
CREATE INDEX event_project_idx ON event(project_id, created_at DESC);
CREATE INDEX event_actor_idx   ON event(actor_id, created_at DESC);
"#;

/// v3 — who uploaded each revision (spec `docs/04-upload-authorship.md`).
///
/// Stored beside `origin`, never merged into it: `origin` is whatever the
/// pushing client claimed about itself, while these two columns are who the
/// server authenticated. Presenting them as one fact would launder an assertion
/// into a verification.
///
/// The backfill is a fact being written down, not a default being invented:
/// `account::resolve_or_create_project` has always answered 404 to anyone but
/// the project's owner, so every pre-v3 revision was pushed by that owner.
/// `author_token_id` stays NULL there because the credential genuinely was
/// never recorded — NULL means "not recorded", never "unknown human".
const SCHEMA_V3: &str = r#"
ALTER TABLE revision ADD COLUMN author_id       TEXT REFERENCES user(id)  ON DELETE SET NULL;
ALTER TABLE revision ADD COLUMN author_token_id TEXT REFERENCES token(id) ON DELETE SET NULL;
CREATE INDEX revision_author_idx ON revision(author_id);

UPDATE revision SET author_id = (
    SELECT p.owner_id FROM resource r JOIN project p ON p.id = r.project_id
    WHERE r.id = revision.resource_id
) WHERE author_id IS NULL;
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_is_idempotent_and_stamps_version() {
        let conn = open_in_memory().unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        // Running again must not error or duplicate tables.
        migrate(&conn).unwrap();
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        // user, session, invite, token, project, resource, revision, rev_file,
        // blob, event
        assert_eq!(tables, 10, "expected the 10 schema tables");
    }

    /// Upgrading a database written before v3 must attribute every existing
    /// revision to its project's owner. That is not a guess: pushing has always
    /// been owner-only, so the owner provably is the uploader.
    #[test]
    fn v3_backfills_authorship_for_revisions_pushed_before_it_existed() {
        let conn = Connection::open_in_memory().unwrap();
        configure(&conn).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(SCHEMA_V2).unwrap();
        conn.execute_batch("PRAGMA user_version = 2").unwrap();

        conn.execute_batch(
            "INSERT INTO user (id, email, display_name, password_hash, created_at)
               VALUES ('u1','a@example.com','wk','h',0);
             INSERT INTO project (id, slug, owner_id, is_public, created_at)
               VALUES ('p1','wk-j.krypton','u1',0,0);
             INSERT INTO resource (id, project_id, kind, slug, title, created_at, updated_at)
               VALUES ('res1','p1','review','a','a board',0,0);
             INSERT INTO revision (id, resource_id, seq, meta, origin, created_at, sealed_at)
               VALUES ('rev1','res1',1,'{}','{}',0,1);",
        )
        .unwrap();

        migrate(&conn).unwrap();

        let (author, token): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT author_id, author_token_id FROM revision WHERE id = 'rev1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(author.as_deref(), Some("u1"));
        assert_eq!(
            token, None,
            "the credential was never recorded, so it stays unrecorded rather than invented"
        );
    }

    #[test]
    fn refuses_a_newer_schema_than_the_binary_understands() {
        let conn = Connection::open_in_memory().unwrap();
        configure(&conn).unwrap();
        conn.execute_batch("PRAGMA user_version = 999").unwrap();
        let err = migrate(&conn).unwrap_err();
        assert!(
            err.contains("newer than this binary supports"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn email_uniqueness_is_case_insensitive() {
        let conn = open_in_memory().unwrap();
        conn.execute(
            "INSERT INTO user (id, email, display_name, password_hash, created_at)
             VALUES ('u1', 'Wk@Example.com', 'wk', 'h', 0)",
            [],
        )
        .unwrap();
        let second = conn.execute(
            "INSERT INTO user (id, email, display_name, password_hash, created_at)
             VALUES ('u2', 'wk@example.com', 'wk2', 'h', 0)",
            [],
        );
        assert!(
            second.is_err(),
            "a differently-cased duplicate email must be rejected"
        );
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let conn = open_in_memory().unwrap();
        let orphan = conn.execute(
            "INSERT INTO project (id, slug, owner_id, created_at) VALUES ('p1','s','nobody',0)",
            [],
        );
        assert!(orphan.is_err(), "project must not reference a missing user");
    }
}
