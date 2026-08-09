// Xenon — SQLite schema and connection handling.
//
// The database holds metadata only; file bytes live in the content-addressed
// blob store (`blob.rs`). Traffic is low enough that a single connection behind
// a mutex is the right call — it removes a pool dependency and makes the
// manifest/commit transactions trivially serialisable.

use rusqlite::Connection;
use std::path::Path;

pub const SCHEMA_VERSION: i64 = 4;

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

/// Bring the database up to `SCHEMA_VERSION`.
///
/// **`user_version` is a hint, not the truth.** Every step below is written to
/// be a no-op when it has already been applied, and all of them run on every
/// boot — the stamp only decides whether there is anything worth logging.
///
/// This is not theoretical tidiness. A database in this repo reached
/// `user_version = 3` with none of v3's columns, because a rebuild-on-save loop
/// restarted the server in the window where `SCHEMA_VERSION` had been bumped to
/// 3 but v3's DDL had not been written yet: the ladder found nothing to do for
/// step 3 and stamped it anyway. Any migration keyed purely on a number it
/// wrote itself can be lied to that way, and the failure surfaces much later as
/// "no such column" on a route that has nothing to do with migrations.
///
/// The whole thing also runs in one transaction, so a step that fails halfway
/// cannot leave a half-built schema behind a stamp that says it is complete.
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

    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| format!("begin migration: {e}"))?;
    let applied = (|| -> Result<(), String> {
        conn.execute_batch(SCHEMA_V1)
            .map_err(|e| format!("apply schema v1: {e}"))?;
        conn.execute_batch(SCHEMA_V2)
            .map_err(|e| format!("apply schema v2: {e}"))?;
        apply_v3(conn)?;
        conn.execute_batch(SCHEMA_V4)
            .map_err(|e| format!("apply schema v4: {e}"))?;
        conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
            .map_err(|e| format!("stamp schema version: {e}"))
    })();

    match applied {
        Ok(()) => {
            conn.execute_batch("COMMIT")
                .map_err(|e| format!("commit migration: {e}"))?;
            if current < SCHEMA_VERSION {
                log::info!("database schema migrated from v{current} to v{SCHEMA_VERSION}");
            }
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// v3 by hand, because `ALTER TABLE` has no `IF NOT EXISTS`. Asks the schema
/// what it actually has rather than trusting the version stamp.
fn apply_v3(conn: &Connection) -> Result<(), String> {
    add_column(
        conn,
        "revision",
        "author_id",
        "TEXT REFERENCES user(id) ON DELETE SET NULL",
    )?;
    add_column(
        conn,
        "revision",
        "author_token_id",
        "TEXT REFERENCES token(id) ON DELETE SET NULL",
    )?;
    conn.execute_batch(SCHEMA_V3_BACKFILL)
        .map_err(|e| format!("apply schema v3: {e}"))
}

/// Add a column unless the table already has one by that name.
fn add_column(conn: &Connection, table: &str, column: &str, decl: &str) -> Result<(), String> {
    let present: i64 = conn
        .query_row(
            "SELECT count(*) FROM pragma_table_info(?1) WHERE name = ?2",
            rusqlite::params![table, column],
            |r| r.get(0),
        )
        .map_err(|e| format!("inspect {table}: {e}"))?;
    if present > 0 {
        return Ok(());
    }
    conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))
        .map_err(|e| format!("add {table}.{column}: {e}"))
}

/// Note on deletion policy: `resource`/`revision`/`rev_file` cascade from their
/// parent, but `user` deletion is intentionally NOT cascaded into `project` —
/// a disabled or removed account keeps its published work (see spec 212 edge
/// cases). Accounts are disabled via `user.disabled_at`, not deleted.
const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS user (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    disabled_at   INTEGER
);

CREATE TABLE IF NOT EXISTS session (
    id         TEXT PRIMARY KEY,      -- sha256 of the cookie value, never the value itself
    user_id    TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS session_user_idx ON session(user_id);

CREATE TABLE IF NOT EXISTS invite (
    code_hash  TEXT PRIMARY KEY,
    created_by TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_by    TEXT REFERENCES user(id) ON DELETE SET NULL,
    used_at    INTEGER
);

CREATE TABLE IF NOT EXISTS token (
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
CREATE INDEX IF NOT EXISTS token_user_idx ON token(user_id);

CREATE TABLE IF NOT EXISTS project (
    id         TEXT PRIMARY KEY,
    slug       TEXT NOT NULL UNIQUE,
    owner_id   TEXT NOT NULL REFERENCES user(id),
    is_public  INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS project_owner_idx ON project(owner_id);

CREATE TABLE IF NOT EXISTS resource (
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
CREATE INDEX IF NOT EXISTS resource_project_kind_idx ON resource(project_id, kind, updated_at DESC);

CREATE TABLE IF NOT EXISTS revision (
    id          TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL REFERENCES resource(id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    meta        TEXT NOT NULL,
    origin      TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    sealed_at   INTEGER,              -- NULL until commit; an open revision is invisible
    UNIQUE(resource_id, seq)
);
CREATE INDEX IF NOT EXISTS revision_resource_idx ON revision(resource_id, seq DESC);

CREATE TABLE IF NOT EXISTS rev_file (
    revision_id  TEXT NOT NULL REFERENCES revision(id) ON DELETE CASCADE,
    path         TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    size         INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    PRIMARY KEY(revision_id, path)
);
CREATE INDEX IF NOT EXISTS rev_file_sha_idx ON rev_file(sha256);

CREATE TABLE IF NOT EXISTS blob (
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
CREATE TABLE IF NOT EXISTS event (
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
CREATE INDEX IF NOT EXISTS event_time_idx    ON event(created_at DESC);
CREATE INDEX IF NOT EXISTS event_project_idx ON event(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS event_actor_idx   ON event(actor_id, created_at DESC);
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
/// The two `ALTER TABLE`s live in `apply_v3` because SQLite has no
/// `ADD COLUMN IF NOT EXISTS`; what remains here is idempotent on its own.
const SCHEMA_V3_BACKFILL: &str = r#"
CREATE INDEX IF NOT EXISTS revision_author_idx ON revision(author_id);

UPDATE revision SET author_id = (
    SELECT p.owner_id FROM resource r JOIN project p ON p.id = r.project_id
    WHERE r.id = revision.resource_id
) WHERE author_id IS NULL;
"#;

/// v4 — per-turn LLM usage (spec 214 in the Krypton repo).
///
/// Deliberately its own table rather than another resource kind. A resource is
/// a sealed snapshot of content-addressed files, so appending one 300-byte row
/// to a day would mean re-uploading and re-sealing the whole day; and the
/// questions asked of this data ("by model", "by lane", "last week") are
/// aggregations, which is what SQL is for and what JSON blobs in `revision.meta`
/// are not.
///
/// `id` is the CLIENT's key, and the primary key is `(project_id, id)`. That is
/// what makes ingest idempotent: a row re-sent after a timeout the client could
/// not interpret lands as a conflict, not as a second charge.
///
/// `received_at` is the server's own clock, kept beside the client's `at` for
/// the same reason `uploaded_by` sits beside `origin` on a revision — one is
/// asserted, the other observed, and merging them would launder the difference.
const SCHEMA_V4: &str = r#"
CREATE TABLE IF NOT EXISTS usage_turn (
    id              TEXT NOT NULL,
    project_id      TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    at              INTEGER NOT NULL,
    duration_ms     INTEGER,
    hostname        TEXT NOT NULL DEFAULT '',
    harness_id      TEXT NOT NULL DEFAULT '',
    lane            TEXT NOT NULL DEFAULT '',
    backend         TEXT NOT NULL DEFAULT '',
    model           TEXT,
    model_confirmed INTEGER NOT NULL DEFAULT 0,
    session_id      TEXT,
    turn_seq        INTEGER,
    stop_reason     TEXT NOT NULL DEFAULT '',
    origin          TEXT NOT NULL DEFAULT '',
    has_tokens      INTEGER NOT NULL DEFAULT 0,
    input_tokens    INTEGER,
    output_tokens   INTEGER,
    cached_read     INTEGER,
    cached_write    INTEGER,
    thought_tokens  INTEGER,
    total_tokens    INTEGER,
    context_used    INTEGER,
    context_size    INTEGER,
    cost_amount     REAL,
    cost_currency   TEXT,
    received_at     INTEGER NOT NULL,
    uploaded_by     TEXT REFERENCES user(id) ON DELETE SET NULL,
    PRIMARY KEY (project_id, id)
);
CREATE INDEX IF NOT EXISTS usage_turn_time_idx  ON usage_turn(project_id, at DESC);
CREATE INDEX IF NOT EXISTS usage_turn_model_idx ON usage_turn(project_id, model, at DESC);
CREATE INDEX IF NOT EXISTS usage_turn_lane_idx  ON usage_turn(project_id, lane, at DESC);
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
        // blob, event, usage_turn
        assert_eq!(tables, 11, "expected the 11 schema tables");
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

    /// The failure that motivated making every step idempotent: a database
    /// stamped with the current version whose schema does not actually have
    /// what that version promises. It happened for real — a rebuild-on-save
    /// loop restarted the server while `SCHEMA_VERSION` was 3 and v3's DDL was
    /// still unwritten — and the symptom was "no such column: author_id" on an
    /// ordinary read, long after boot.
    #[test]
    fn repairs_a_database_that_lies_about_its_version() {
        let conn = Connection::open_in_memory().unwrap();
        configure(&conn).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(SCHEMA_V2).unwrap();
        // The lie: stamped current, missing v3 entirely.
        conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
            .unwrap();
        conn.execute_batch(
            "INSERT INTO user (id, email, display_name, password_hash, created_at)
               VALUES ('u1','a@example.com','wk','h',0);
             INSERT INTO project (id, slug, owner_id, is_public, created_at)
               VALUES ('p1','p','u1',0,0);
             INSERT INTO resource (id, project_id, kind, slug, title, created_at, updated_at)
               VALUES ('res1','p1','doc','a','a',0,0);
             INSERT INTO revision (id, resource_id, seq, meta, origin, created_at)
               VALUES ('rev1','res1',1,'{}','{}',0);",
        )
        .unwrap();

        migrate(&conn).unwrap();

        let author: Option<String> = conn
            .query_row(
                "SELECT author_id FROM revision WHERE id = 'rev1'",
                [],
                |r| r.get(0),
            )
            .expect("the missing column must have been added despite the stamp");
        assert_eq!(author.as_deref(), Some("u1"), "and backfilled while there");
    }

    /// A failed step must leave nothing behind — no half-built schema sitting
    /// under a stamp that claims it is complete.
    #[test]
    fn a_failed_migration_rolls_back_instead_of_stamping() {
        let conn = Connection::open_in_memory().unwrap();
        configure(&conn).unwrap();
        // Tables and indexes share one namespace in SQLite, so squatting on the
        // name v3 wants for its index makes that step fail.
        conn.execute_batch("CREATE TABLE revision_author_idx (x)")
            .unwrap();

        let err = migrate(&conn).unwrap_err();
        assert!(
            err.contains("revision_author_idx"),
            "unexpected error: {err}"
        );
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 0, "a failed migration must not stamp a version");
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
