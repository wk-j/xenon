// Xenon — the activity log (spec `docs/03-activity-feed.md`).
//
// One append-only table written at the choke points that already exist:
// `api::seal_revision` for content, `account::*` for accounts and tokens. Rows
// are never updated and never rewritten.
//
// Two rules shape everything below.
//
// **Recording takes the caller's connection.** `AppState::db()` is a plain
// mutex, so a `record` that opened its own would deadlock any handler that
// already holds the guard — which is every handler that has something worth
// recording. The signature makes that impossible to get wrong.
//
// **Visibility is decided on read.** A `project` row inherits its project's
// *current* `is_public`; an `account` row belongs to its own user. Gitea freezes
// the equivalent flag into the row at write time, which is faster at their scale
// and wrong at any scale where a project can turn private later: the old rows
// keep leaking. Xenon is one SQLite file, so it joins.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::Value;
use std::sync::atomic::Ordering;

use crate::auth::Actor;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util::{new_id, now};

pub const MAX_LIMIT: i64 = 100;
pub const DEFAULT_LIMIT: i64 = 30;
/// How often the write path is allowed to spend a `DELETE` on retention.
const PRUNE_INTERVAL_SECS: i64 = 3600;
/// A frozen `subject` is display text, not a key; bound it so one enormous
/// title cannot bloat the log.
const MAX_SUBJECT: usize = 300;

// ------------------------------------------------------------------- kinds

pub const RESOURCE_PUBLISH: &str = "resource.publish";
pub const RESOURCE_REVISE: &str = "resource.revise";
pub const RESOURCE_REMOVE: &str = "resource.remove";
pub const PROJECT_CREATE: &str = "project.create";
pub const ACCOUNT_REGISTER: &str = "account.register";
pub const ACCOUNT_LOGIN: &str = "account.login";
pub const ACCOUNT_LOGIN_FAILED: &str = "account.login_failed";
pub const ACCOUNT_LOGOUT: &str = "account.logout";
pub const TOKEN_CREATE: &str = "token.create";
pub const TOKEN_REVOKE: &str = "token.revoke";
pub const INVITE_CREATE: &str = "invite.create";
pub const INVITE_CLAIM: &str = "invite.claim";
pub const ACCOUNT_DISABLE: &str = "account.disable";
pub const ACCOUNT_ENABLE: &str = "account.enable";
pub const PROJECT_VISIBILITY: &str = "project.visibility";

/// Every kind, in the order the filter row shows them.
pub const KINDS: [&str; 15] = [
    RESOURCE_PUBLISH,
    RESOURCE_REVISE,
    RESOURCE_REMOVE,
    PROJECT_CREATE,
    PROJECT_VISIBILITY,
    ACCOUNT_REGISTER,
    ACCOUNT_LOGIN,
    ACCOUNT_LOGIN_FAILED,
    ACCOUNT_LOGOUT,
    ACCOUNT_DISABLE,
    ACCOUNT_ENABLE,
    TOKEN_CREATE,
    TOKEN_REVOKE,
    INVITE_CREATE,
    INVITE_CLAIM,
];

/// Kinds that can appear on a project's own feed. Account rows have no
/// `project_slug`, so they never match a project filter — listing them as
/// chips would offer filters that are always empty.
pub const PROJECT_KINDS: [&str; 5] = [
    RESOURCE_PUBLISH,
    RESOURCE_REVISE,
    RESOURCE_REMOVE,
    PROJECT_CREATE,
    PROJECT_VISIBILITY,
];

/// Where a row's visibility comes from — not what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    /// Follows the project's current `is_public`.
    Project,
    /// The actor themselves, and an admin. Never shown in a project feed.
    Account,
}

impl Audience {
    fn as_str(self) -> &'static str {
        match self {
            Audience::Project => "project",
            Audience::Account => "account",
        }
    }
}

// ------------------------------------------------------------------ writing

/// One event to record. Everything human-readable is copied in, not referenced:
/// the row has to still read after the project or account it names is gone.
pub struct New<'a> {
    pub kind: &'a str,
    pub audience: Audience,
    pub actor_id: Option<&'a str>,
    pub actor_name: &'a str,
    /// `(project_id, project_slug)`.
    pub project: Option<(&'a str, &'a str)>,
    pub resource_id: Option<&'a str>,
    pub subject: &'a str,
    pub detail: Value,
}

impl<'a> New<'a> {
    pub fn account(kind: &'a str, actor_name: &'a str, subject: &'a str) -> Self {
        Self {
            kind,
            audience: Audience::Account,
            actor_id: None,
            actor_name,
            project: None,
            resource_id: None,
            subject,
            detail: Value::Null,
        }
    }

    pub fn project_scoped(kind: &'a str, actor_name: &'a str, subject: &'a str) -> Self {
        Self {
            kind,
            audience: Audience::Project,
            actor_id: None,
            actor_name,
            project: None,
            resource_id: None,
            subject,
            detail: Value::Null,
        }
    }

    pub fn by(mut self, actor: &'a Actor) -> Self {
        self.actor_id = Some(&actor.user_id);
        self
    }

    pub fn actor_id(mut self, id: Option<&'a str>) -> Self {
        self.actor_id = id;
        self
    }

    pub fn in_project(mut self, id: &'a str, slug: &'a str) -> Self {
        self.project = Some((id, slug));
        self
    }

    pub fn about_resource(mut self, id: &'a str) -> Self {
        self.resource_id = Some(id);
        self
    }

    pub fn detail(mut self, detail: Value) -> Self {
        self.detail = detail;
        self
    }
}

/// Append one row, on the connection the caller already holds.
///
/// A failure here fails the request rather than being swallowed. At this scale
/// the only way an insert into a local SQLite table fails is a broken database,
/// and a log that quietly drops rows under exactly those conditions is worse
/// than a 500.
pub fn record(conn: &Connection, new: New<'_>) -> AppResult<()> {
    let detail = match &new.detail {
        Value::Null => "{}".to_string(),
        other => other.to_string(),
    };
    let mut subject = new.subject.trim().to_string();
    if subject.chars().count() > MAX_SUBJECT {
        subject = subject.chars().take(MAX_SUBJECT).collect();
    }

    conn.execute(
        "INSERT INTO event
           (id, kind, audience, actor_id, actor_name, project_id, project_slug,
            resource_id, subject, detail, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            new_id("evt_").map_err(AppError::internal)?,
            new.kind,
            new.audience.as_str(),
            new.actor_id,
            new.actor_name,
            new.project.map(|(id, _)| id),
            new.project.map(|(_, slug)| slug),
            new.resource_id,
            subject,
            detail,
            now(),
        ],
    )?;
    Ok(())
}

/// Record, then enforce retention at most once an hour.
///
/// Separate from `record` so the pure insert stays testable without a state
/// handle, and so a caller that is already inside a hot loop can opt out.
pub fn record_and_prune(state: &AppState, conn: &Connection, new: New<'_>) -> AppResult<()> {
    record(conn, new)?;
    maybe_prune(state, conn)
}

fn maybe_prune(state: &AppState, conn: &Connection) -> AppResult<()> {
    let days = state.config.activity_retention_days;
    if days <= 0 {
        return Ok(());
    }
    let now = now();
    let last = state.last_activity_prune.load(Ordering::Relaxed);
    if now - last < PRUNE_INTERVAL_SECS {
        return Ok(());
    }
    // Claim the slot before doing the work: two concurrent writers should not
    // both run the DELETE, and losing a prune to a race only delays it an hour.
    if state
        .last_activity_prune
        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return Ok(());
    }
    let removed = prune(conn, now - days * 86_400)?;
    if removed > 0 {
        log::info!("activity log: pruned {removed} row(s) older than {days} days");
    }
    Ok(())
}

/// Drop every row older than `cutoff`. Returns how many went.
pub fn prune(conn: &Connection, cutoff: i64) -> AppResult<usize> {
    Ok(conn.execute("DELETE FROM event WHERE created_at < ?1", [cutoff])?)
}

// ------------------------------------------------------------------ reading

#[derive(Debug, Clone, Serialize)]
pub struct EventView {
    pub id: String,
    /// Insert order. Opaque to a client except as the paging cursor.
    pub seq: i64,
    pub kind: String,
    pub actor: String,
    pub project: Option<String>,
    pub resource_id: Option<String>,
    /// Path to the resource this event is about, when it still exists.
    pub url: Option<String>,
    pub subject: String,
    pub detail: Value,
    pub created_at: i64,
}

/// What a feed query is narrowed by. All fields optional; the default is
/// "everything this caller may see, newest first".
#[derive(Debug, Default, Clone)]
pub struct Query<'a> {
    pub project: Option<&'a str>,
    pub kind: Option<&'a str>,
    /// Keyset cursor: return rows recorded strictly before this `seq`.
    pub cursor: Option<i64>,
    pub limit: i64,
}

/// Read the feed as `viewer` may see it. `viewer` is `None` for an anonymous
/// caller, which sees nothing — this instance is not a public website.
///
/// The visibility predicate is one expression applied to every query, so there
/// is exactly one place to audit:
///
/// * `project` rows — the viewer is signed in and the project is public, or
///   the viewer owns it;
/// * `account` rows — the viewer is the actor;
/// * an admin sees everything, which is the point of an admin on a self-hosted
///   instance and the only way the security rows are useful to anyone.
pub fn query(
    conn: &Connection,
    viewer: Option<&Actor>,
    q: &Query<'_>,
) -> AppResult<Vec<EventView>> {
    let me = viewer.map(|a| a.user_id.as_str()).unwrap_or("");
    let is_admin = viewer.is_some_and(|a| a.is_admin);
    let limit = q.limit.clamp(1, MAX_LIMIT);

    // Ordering is by `rowid`, not by `created_at`, and the cursor is a rowid.
    //
    // Timestamps are seconds, and a single push writes `project.create` and
    // `resource.publish` inside the same one — so a feed sorted by time alone
    // has ties, and `id` cannot break them because it is random. Insert order
    // is both the true order of a log and strictly monotonic, which is exactly
    // what a keyset cursor needs to never repeat or skip a row.
    //
    // One statement shape whatever the filters are: each optional narrowing is
    // a sentinel comparison rather than appended SQL, so every parameter is
    // always bound and the prepared-statement cache sees a single query.
    let mut stmt = conn.prepare(
        "SELECT e.id, e.kind, e.actor_name, e.project_slug, e.resource_id, e.subject,
                e.detail, e.created_at, r.kind, r.slug, e.rowid
         FROM event e
         LEFT JOIN project p ON p.id = e.project_id
         LEFT JOIN resource r ON r.id = e.resource_id
         WHERE (
             ?3
             OR (e.audience = 'project' AND ?1 <> '' AND (p.is_public = 1 OR p.owner_id = ?1 OR p.id IS NULL))
             OR (e.audience = 'account' AND e.actor_id = ?1 AND ?1 <> '')
         )
           AND (?4 = 0  OR e.rowid < ?4)
           AND (?5 = '' OR e.project_slug = ?5)
           AND (?6 = '' OR e.kind = ?6)
         ORDER BY e.rowid DESC
         LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(
            params![
                me,
                limit,
                is_admin,
                q.cursor.unwrap_or(0),
                q.project.unwrap_or(""),
                q.kind.unwrap_or("")
            ],
            |r| {
                let resource_id: Option<String> = r.get(4)?;
                let res_kind: Option<String> = r.get(8)?;
                let res_slug: Option<String> = r.get(9)?;
                let project: Option<String> = r.get(3)?;
                let url = match (&project, &res_kind, &res_slug) {
                    (Some(p), Some(k), Some(s)) => Some(format!("/r/{p}/{k}/{s}")),
                    _ => None,
                };
                Ok(EventView {
                    id: r.get(0)?,
                    seq: r.get(10)?,
                    kind: r.get(1)?,
                    actor: r.get(2)?,
                    project,
                    resource_id,
                    url,
                    subject: r.get(5)?,
                    detail: serde_json::from_str(&r.get::<_, String>(6)?)
                        .unwrap_or(Value::Object(Default::default())),
                    created_at: r.get(7)?,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// The display name to freeze into a row for `user_id`, falling back to the
/// email and then to a placeholder. A missing name is never worth failing a
/// login over.
pub fn actor_name(conn: &Connection, user_id: &str) -> String {
    conn.query_row(
        "SELECT display_name, email FROM user WHERE id = ?1",
        [user_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )
    .optional()
    .ok()
    .flatten()
    .map(|(name, email)| if name.trim().is_empty() { email } else { name })
    .unwrap_or_else(|| "someone".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn seed(conn: &Connection) {
        conn.execute_batch(
            "INSERT INTO user (id, email, display_name, password_hash, is_admin, created_at)
               VALUES ('u1','a@example.com','wk','h',0,0),
                      ('u2','b@example.com','other','h',0,0);
             INSERT INTO project (id, slug, owner_id, is_public, created_at)
               VALUES ('p1','wk-j.krypton','u1',0,0),
                      ('p2','open','u2',1,0);",
        )
        .unwrap();
    }

    fn viewer(id: &str, admin: bool) -> Actor {
        Actor {
            user_id: id.to_string(),
            is_admin: admin,
            via: crate::auth::AuthVia::Session,
        }
    }

    #[test]
    fn a_private_projects_rows_stay_with_its_owner() {
        let conn = db::open_in_memory().unwrap();
        seed(&conn);
        record(
            &conn,
            New::project_scoped(RESOURCE_PUBLISH, "wk", "a board")
                .actor_id(Some("u1"))
                .in_project("p1", "wk-j.krypton"),
        )
        .unwrap();
        record(
            &conn,
            New::project_scoped(RESOURCE_PUBLISH, "other", "public thing")
                .actor_id(Some("u2"))
                .in_project("p2", "open"),
        )
        .unwrap();

        let q = Query {
            limit: DEFAULT_LIMIT,
            ..Default::default()
        };
        let owner = query(&conn, Some(&viewer("u1", false)), &q).unwrap();
        assert_eq!(owner.len(), 2, "the owner sees theirs and the public one");

        let stranger = query(&conn, Some(&viewer("u2", false)), &q).unwrap();
        assert_eq!(stranger.len(), 1);
        assert_eq!(stranger[0].subject, "public thing");

        let anonymous = query(&conn, None, &q).unwrap();
        assert!(
            anonymous.is_empty(),
            "nobody is signed in, so nothing is readable: {anonymous:?}"
        );
    }

    #[test]
    fn account_rows_are_private_to_their_actor_and_admins() {
        let conn = db::open_in_memory().unwrap();
        seed(&conn);
        record(
            &conn,
            New::account(ACCOUNT_LOGIN, "wk", "a@example.com").actor_id(Some("u1")),
        )
        .unwrap();
        // A failed login for an unknown email has no actor at all.
        record(
            &conn,
            New::account(ACCOUNT_LOGIN_FAILED, "someone", "ghost@example.com"),
        )
        .unwrap();

        let q = Query {
            limit: DEFAULT_LIMIT,
            ..Default::default()
        };
        assert_eq!(
            query(&conn, Some(&viewer("u1", false)), &q).unwrap().len(),
            1
        );
        assert_eq!(
            query(&conn, Some(&viewer("u2", false)), &q).unwrap().len(),
            0,
            "another user sees none of it"
        );
        assert_eq!(
            query(&conn, None, &q).unwrap().len(),
            0,
            "anonymous sees none"
        );
        assert_eq!(
            query(&conn, Some(&viewer("admin", true)), &q)
                .unwrap()
                .len(),
            2,
            "an admin sees the orphaned failure too"
        );
    }

    #[test]
    fn the_cursor_pages_without_overlap() {
        let conn = db::open_in_memory().unwrap();
        seed(&conn);
        for i in 0..5 {
            record(
                &conn,
                New::project_scoped(RESOURCE_PUBLISH, "other", &format!("r{i}"))
                    .actor_id(Some("u2"))
                    .in_project("p2", "open"),
            )
            .unwrap();
            conn.execute(
                "UPDATE event SET created_at = ?1 WHERE created_at = ?2 AND subject = ?3",
                params![1000 + i, now(), format!("r{i}")],
            )
            .unwrap();
        }

        let first = query(
            &conn,
            Some(&viewer("u1", false)),
            &Query {
                limit: 2,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            first.iter().map(|e| e.subject.as_str()).collect::<Vec<_>>(),
            ["r4", "r3"]
        );

        let next = query(
            &conn,
            Some(&viewer("u1", false)),
            &Query {
                limit: 2,
                cursor: Some(first[1].seq),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            next.iter().map(|e| e.subject.as_str()).collect::<Vec<_>>(),
            ["r2", "r1"],
            "the second page must not repeat the first"
        );
    }

    #[test]
    fn prune_drops_only_what_is_past_the_window() {
        let conn = db::open_in_memory().unwrap();
        seed(&conn);
        record(
            &conn,
            New::project_scoped(RESOURCE_PUBLISH, "other", "old")
                .actor_id(Some("u2"))
                .in_project("p2", "open"),
        )
        .unwrap();
        conn.execute("UPDATE event SET created_at = 100", [])
            .unwrap();
        record(
            &conn,
            New::project_scoped(RESOURCE_PUBLISH, "other", "new")
                .actor_id(Some("u2"))
                .in_project("p2", "open"),
        )
        .unwrap();

        assert_eq!(prune(&conn, 500).unwrap(), 1);
        let left = query(
            &conn,
            Some(&viewer("u1", false)),
            &Query {
                limit: DEFAULT_LIMIT,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].subject, "new");
    }
}
