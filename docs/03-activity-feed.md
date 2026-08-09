# Activity Feed — Implementation Spec

> Status: Implemented (2026-08-09)
> Date: 2026-08-09
>
> **Deviations from the approved design**, both found by the tests rather than by reading:
> 1. **The cursor is insert order, not a timestamp.** `?before=<epoch>` could not page: timestamps
>    are seconds and one push writes `project.create` and `resource.publish` inside the same one,
>    so the feed had ties that `id` could not break (it is random, not monotonic). Ordering and the
>    cursor are now the row's `seq` (SQLite `rowid`), exposed as `?cursor=` / `next_cursor`.
> 2. **Sign-out is recorded inside `auth::end_session`,** not in the two logout handlers. There are
>    two routes (`POST /v1/auth/logout` and the browse UI's `POST /logout`); recording in the
>    handlers logged one and silently missed the other.
> Builds on: `docs/01-protocol.md` (routes, auth), `docs/02-frontend-architecture.md` (templates, kind hues)

## Problem

Xenon records *what exists* but not *what happened*. There is no way to answer "what did my fleet
publish today", "when was this token minted", or "did anyone sign in as me last night". Every write
path — publish, revise, register, login, token mint, token revoke, invite — leaves no trace beyond
the row it mutated, and a mutated row cannot tell you it was mutated twice.

## Solution

One append-only `event` table written at the choke points that already exist, plus `GET /v1/activity`
and a server-rendered `/activity` page that reads like a GitHub dashboard feed: newest first, grouped
by day, one sentence per row.

Visibility is decided **at read time**, not frozen at write time: a content event inherits the
current visibility of its project, and an account event is visible to its own user (and to an admin).
This is the opposite of Gitea's denormalized `is_private` column and is the right trade here — Xenon
is one SQLite file with low traffic, and a join is cheaper than the class of bug where a project
flips to private and its old feed rows keep leaking.

## Research

**In-tree choke points** (verified):

- `api.rs::seal_revision` is the *only* place a revision becomes visible. Both ingest paths
  (`resources:inline` and manifest → blobs → `revisions/{id}/commit`) end there, so one call site
  covers every publish. It already knows `resource_id`, `seq`, `project_id` and the actor.
- `account.rs::resolve_or_create_project` is the only place a project is born.
- `account.rs` owns register / login / logout / token create / token revoke / invite create /
  invite claim — seven distinct account events, all already funnelling through one module.
- `state.rs::AppState::db()` is a **non-reentrant mutex**. Event recording must therefore take the
  connection the caller already holds, never open its own; a nested `db()` deadlocks rather than
  fails. (Same constraint that shaped `web.rs::viewer`.)
- `db.rs::migrate` already has the `if current < N` ladder and a `SCHEMA_VERSION` guard that refuses
  a database newer than the binary. Adding v2 is three lines plus the DDL.
- `resource.title` is capped at 300 chars on ingest, so a frozen copy in an event row is bounded.

**Alternatives ruled out.** *Derive the feed from existing tables* (`revision.created_at`,
`token.created_at`, …) — it covers publishes but can never represent a login, a logout, a revoke, or
a failed sign-in, and it produces a different query per row type. *A separate audit log file* — a
second store to back up, no join to projects, and unreadable from the browse UI. *Recording reads* —
see Design.

## Prior Art

| System | Implementation | Notes |
|---|---|---|
| GitHub Events API | `{ id, type, actor, repo, payload, public, created_at }`; timelines at `/events`, `/users/{u}/events`, `/repos/{o}/{r}/events`. **30-day retention, max 300 events**, latency 30 s–6 h, ETag + `X-Poll-Interval` polling. | The event shape is copied almost directly. The latency is a consequence of GitHub's async fan-out; Xenon writes synchronously in the same transaction, so its feed is exact rather than eventually-correct. |
| Gitea `action` table | `id, user_id, op_type, act_user_id, repo_id, is_private, content, created_unix`; `is_private` denormalized from repo visibility **at creation time**; queries filter it out unless the viewer is allowed. One table serves dashboard + heatmap + profile, which they document as a performance problem. | Source of the single-table design. Deliberately diverged on `is_private`: read-time visibility (below) avoids the stale-flag leak, and Xenon has no scale reason to denormalize. |
| GitLab | `events` table with `push_data` JSON, `/users/:id/events`, contribution calendar. | Confirms a JSON side-car column for type-specific payload rather than a column per event type. |
| Linear / Sentry activity | Reverse-chronological, grouped by day, relative timestamps, actor avatar + verb sentence. | The row grammar adopted here: **actor · verb · object · when**, one line, no card per event. |

**Xenon delta.** The feed is a *fleet* log, not a social one: there is no following, no starring, no
notification. Its rows are mostly written by machines (Krypton lanes pushing under a token), so the
actor is usually the same person and the interesting axis is the **kind** of resource — which is why
rows reuse the kind hues from `docs/02-frontend-architecture.md` instead of avatars. It also merges
what GitHub keeps in two places: the public activity feed and the account security log are one table
here, separated by audience rather than by product surface.

## Affected Files

| File | Change |
|---|---|
| `src/event.rs` | **New** — `Kind`, `Audience`, `record()`, `query()`, `prune()` |
| `src/db.rs` | `SCHEMA_VERSION = 2`; `SCHEMA_V2` DDL for `event` + indexes |
| `src/api.rs` | Record `resource.publish` / `resource.revise` inside `seal_revision` |
| `src/account.rs` | Record register, login, login_failed, logout, token create/revoke, invite create/claim, `project.create` |
| `src/web.rs` | `GET /activity` handler + `ActivityTemplate`; day grouping |
| `templates/activity.html` | **New** — feed page |
| `templates/base.html` | `activity` in the nav |
| `assets/app.css` | `.feed*` styles |
| `src/util.rs` | `time_ago()` |
| `src/config.rs` | `XENON_ACTIVITY_RETENTION_DAYS` |
| `src/state.rs` | `last_prune: AtomicI64` |
| `src/lib.rs` | `pub mod event` |
| `tests/flow.rs` | Feed tests (below) |
| `docs/01-protocol.md` | Document `/v1/activity` and `/activity` |

**Also included** (small, say so if you want it cut): the resource cards on `/p/<project>` currently
print `updated 1786245191` — a raw epoch. They switch to `time_ago()` with the real timestamp in a
`title` attribute, since the helper has to exist for the feed anyway.

## Design

### Schema v2

```sql
CREATE TABLE event (
    id           TEXT PRIMARY KEY,                                  -- evt_<base32>
    kind         TEXT NOT NULL,                                     -- 'resource.publish', ...
    audience     TEXT NOT NULL,                                     -- 'project' | 'account'
    actor_id     TEXT REFERENCES user(id) ON DELETE SET NULL,
    actor_name   TEXT NOT NULL,                                     -- frozen display name
    project_id   TEXT REFERENCES project(id) ON DELETE SET NULL,
    project_slug TEXT,                                              -- frozen
    resource_id  TEXT REFERENCES resource(id) ON DELETE SET NULL,
    subject      TEXT NOT NULL,                                     -- resource title, token label, email
    detail       TEXT NOT NULL DEFAULT '{}',                        -- JSON: seq, resource kind, ip, ua
    created_at   INTEGER NOT NULL
);
CREATE INDEX event_time_idx    ON event(created_at DESC);
CREATE INDEX event_project_idx ON event(project_id, created_at DESC);
CREATE INDEX event_actor_idx   ON event(actor_id, created_at DESC);
```

Every foreign key is `ON DELETE SET NULL` and every human-readable field is **frozen at write time**.
A feed row must still render after its project, resource, or account is gone — an append-only log
that loses rows when something is deleted is not a log.

### Event kinds

| `kind` | audience | recorded at | `subject` | `detail` |
|---|---|---|---|---|
| `resource.publish` | project | `seal_revision`, seq == 1 | resource title | `{kind, slug}` |
| `resource.revise` | project | `seal_revision`, seq > 1 | resource title | `{kind, slug, seq}` |
| `project.create` | project | `resolve_or_create_project` | project slug | `{}` |
| `account.register` | account | `register` | email | `{ip, admin}` |
| `account.login` | account | `login` | email | `{ip, user_agent}` |
| `account.login_failed` | account | `login`, on rejection | attempted email | `{ip}` |
| `account.logout` | account | `logout` | email | `{}` |
| `token.create` | account | `create_token` | token label | `{token_id, scopes, project}` |
| `token.revoke` | account | `revoke_token` | token label | `{token_id}` |
| `invite.create` | account | `create_invite` | — | `{}` |
| `invite.claim` | account | `register` with a code | email | `{}` |

**Reads are not recorded.** Every page view and every blob fetch would outnumber content events by
orders of magnitude, turn a metadata database into a web log, and bury the eleven rows above in
noise. An access log belongs in the reverse proxy. This is the one decision most worth overturning
if the intent was an audit trail rather than a feed — say so and it becomes a separate table with
its own retention, not extra rows in this one.

**`account.login_failed` with an unknown email has `actor_id = NULL`**, so only an admin can ever
see it. That is deliberate: attaching it to an account, or showing it to anyone else, would turn the
feed into the account-existence oracle that `register` already refuses to be.

### Recording

```rust
// src/event.rs — takes the caller's connection; never opens its own (db() is not reentrant).
pub struct New<'a> {
    pub kind: &'a str,
    pub audience: Audience,          // Project | Account
    pub actor: Option<&'a Actor>,
    pub actor_name: String,
    pub project: Option<(&'a str, &'a str)>,   // (id, slug)
    pub resource_id: Option<&'a str>,
    pub subject: String,
    pub detail: serde_json::Value,
}
pub fn record(conn: &Connection, new: New<'_>) -> AppResult<()>;
pub fn prune(conn: &Connection, older_than: i64) -> AppResult<usize>;
```

`record` runs on the same connection as the mutation that caused it, immediately after it succeeds,
so an event cannot exist without its cause. A failure to insert fails the request: at this scale the
only way it fails is a broken database, and silently dropping the row would be worse than a 500.

### Read API

```
GET /v1/activity?project=<slug>&kind=<kind>&cursor=<seq>&limit=<1..100, default 30>
→ { "events": [ { id, seq, kind, actor, project, resource_id, url, subject, detail, created_at } ],
    "next_cursor": <int|null> }
```

Keyset pagination on `seq` (the row's `rowid`) — no `OFFSET`, so a row inserted mid-scroll cannot
shift a page, and no ties, so it cannot repeat or skip one either. Visibility is one predicate,
applied to every query:

```sql
WHERE (e.audience = 'project' AND (p.is_public = 1 OR p.owner_id = :me))
   OR (e.audience = 'account' AND e.actor_id = :me)
   OR :is_admin
```

Anonymous callers pass `:me = ''` and match only public-project rows. An admin sees everything,
which is the norm for a self-hosted instance and the only way the security rows are useful.

### `/activity` page

Server-rendered, no JavaScript, matching the rest of the browse UI:

- **Day groups** — `today` / `yesterday` / `9 Aug 2026` as a heading per group.
- **Row grammar** — `<actor> <verb> <object> · <relative time>`, one line, no card per event.
  Resource rows carry the kind chip in its hue (`k--<kind>`); account rows carry a muted `account`
  chip, so the security log is visually distinct without a second page.
- **Filters** — `?project=` and `?kind=` render as the existing `.kinds` chip row.
- **Paging** — an `older →` link carrying `?before=`, so paging works without JS.
- **Empty state** — "no activity yet — push something from krypton with `#push`" when signed in,
  "no public activity" when not.
- Nav gains `activity` between `projects` and `tokens`, always visible (an anonymous visitor to a
  public instance sees the public slice).

### Retention

`XENON_ACTIVITY_RETENTION_DAYS`, default `90`, `0` = keep forever. `record()` calls `prune()` at most
once an hour, gated by an `AtomicI64` on `AppState` — no background task, no scheduler. Chosen over
GitHub's 30 days because a fleet log is read in weeks, not days, and 90 days of these rows is
kilobytes.

## Edge Cases

- **Unchanged push** — `create_inline` returns the existing head without sealing; no event. Re-running
  `#push` stays a genuine no-op, in the feed as well as on disk.
- **Open (unsealed) revision** — invisible everywhere else, so it records nothing until commit.
- **Deleted account** — `actor_id` goes NULL, `actor_name` survives; the row still reads.
- **Renamed / deleted project** — `project_slug` is frozen; a deleted project's rows lose their link
  but keep their text. Rows whose `project_id` is NULL are treated as public for content events
  (the project they described is gone, and the text was already published).
- **Several events in the same second** — the norm, not the exception: one push writes
  `project.create` and `resource.publish` together. Ordering is by insert order for exactly this
  reason, so a clock that steps backwards cannot reorder the log either.
- **Token-authenticated actor** — recorded as the owning user, with `detail.token_id`, so a lane's
  publish is attributed to the human whose token it used.

## Testing

New tests in `tests/flow.rs`:

1. publishing then re-publishing changed content yields exactly `resource.publish` + `resource.revise`;
2. an unchanged re-push adds no event;
3. a second user sees neither the first user's private-project events nor any of their account events;
4. anonymous sees public-project events only, and no account events at all;
5. a failed login is recorded with `actor_id` NULL and is invisible to non-admins;
6. `/activity` renders, groups by day, and `?before=` returns the next page without overlap;
7. `prune()` drops rows past the retention window and leaves the rest.

## Out of Scope

Following / notifications / RSS · per-resource event history on the resource page (the revision list
already covers it) · a contribution heatmap · webhooks on events · recording reads (see Design) ·
surfacing the feed inside Krypton (it is a `/v1/activity` consumer like any other, and can come
later without a server change).

## Resources

- [GitHub REST API — Events](https://docs.github.com/en/rest/activity/events) — event object shape,
  30-day / 300-event retention, and the async-latency caveat that motivated writing synchronously here.
- [Gitea — user dashboard and activity feeds](https://deepwiki.com/go-gitea/gitea/7.3-user-dashboard-and-activity-feeds)
  — the `action` table columns, the denormalized `is_private` flag this spec deliberately inverts,
  and their note on one table serving three surfaces.
- [go-gitea/gitea#32110 — split feed and user activities](https://github.com/go-gitea/gitea/issues/32110)
  — the performance consequence of that single table, which is why the indexes above are per-axis.
