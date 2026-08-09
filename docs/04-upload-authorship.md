# Upload Authorship — Implementation Spec

> Status: Implemented (2026-08-09)
> Date: 2026-08-09
>
> Landed as written. One shape change: `Author` is `{ name, token_label, token_revoked }` — the
> spec's draft struct carried a `name` comment debating frozen vs joined; joined won, for the
> reason already given under API.
> Builds on: `docs/01-protocol.md` (ingest, tokens), `docs/03-activity-feed.md` (the actor model)

## Problem

Nothing on a stored item says who put it there. A revision records `created_at`, its files, and an
`origin` blob the *client* sent (`hostname`, `project_dir`, `krypton_version`) — but no
server-verified identity. Open a resource and there is no answer to "who published this, from which
machine, using which credential". The activity feed added that answer for the moment of the push;
it is still absent from the item itself, which is where anyone looking at a review or an artifact
actually is.

## Solution

Record the authenticated actor on every **revision** — the account and the token that sealed it —
and surface it on the resource page, in the revision list, and in the API.

Per revision, not per resource: a resource is a chain of uploads that can come from different
machines and different lanes over time, so "who uploaded this" only has an answer at the revision
level. The resource's own answer ("last published by") derives from its head revision.

Server-verified identity is stored **beside** the client's `origin`, never merged into it. `origin`
is whatever the pushing client claimed; `author_id` is who the server authenticated. Displaying
them as one fact would launder an assertion into a verification.

## Research

**What exists** (verified in-tree):

- `revision(id, resource_id, seq, meta, origin, created_at, sealed_at)` — no identity column.
- `origin` is client-asserted. Krypton fills it in `xenon.rs::origin_value`: hostname, project dir,
  and its own version. Useful, unverifiable.
- `api.rs::seal_revision` already holds the `&Actor` and, since spec 03, already reads its
  `token_id()` for the activity row. The information is in hand at the exact moment it is needed;
  it is simply not persisted.
- **Only a project's owner can push to it.** `account.rs::resolve_or_create_project` answers
  `404` to anyone else. That makes the backfill below provable rather than a guess.
- `token` rows are never deleted, only revoked (`revoked_at`), so a stored `token_id` can still be
  joined to its label years later — the label is how the human named the machine ("krypton on this
  laptop"), which is the part worth showing.
- Some kinds already carry `meta.lane` (`"Claude-1"`) from the harness. That is the *agent* behind
  a push, distinct from the account and the token, and it is already stored — it just is not shown.

**Alternatives ruled out.** *Trust `origin`* — a client can claim anything; an authorship line that
can be forged by the uploader is worse than none. *Store the author on `resource`* — collapses a
chain of uploads into one name and loses it the moment someone else revises. *Derive the author
from the project owner at read time* — correct only while pushing is owner-only; the moment
collaborators or org projects exist, every historical row silently becomes wrong.

## Prior Art

| System | Implementation | Notes |
|---|---|---|
| Git | Separate `author` (wrote it) and `committer` (applied it), both name + email + timestamp, both unverified unless signed. | The two-identity split is the model: `origin` is the claim, `author_id` is the verification. Git's lesson is the opposite one — unsigned identity is decoration, which is why Xenon stores the authenticated actor rather than a string the client sent. |
| npm registry | Publishes record `_npmUser` (the authenticated account) separately from the `author` field in `package.json` (whatever the publisher typed). | Exactly the split adopted here, including which of the two the UI leads with. |
| GitHub Packages / container registries | Show "published by \<user\>" on the version, resolved from the token that pushed. | Confirms token → account attribution as the norm for machine pushes. |
| Docker Hub | Shows the pushing account per tag, and nothing about which credential. | The thing this spec adds beyond them: the token *label*, because one account has many machines and "which laptop" is the question a fleet operator actually asks. |

**Xenon delta.** Most registries attribute to a human. Here the pusher is usually a machine acting
for a human — a Krypton lane under an API token — so the line has three parts, in decreasing order
of trustworthiness: **account** (authenticated), **token label** (authenticated, names the machine),
**lane and host** (client-asserted, shown as such).

## Affected Files

| File | Change |
|---|---|
| `src/db.rs` | `SCHEMA_VERSION = 3`; `SCHEMA_V3` adds `revision.author_id`, `revision.author_token_id` + backfill |
| `src/api.rs` | `open_revision` stores the actor; `RevisionDetail` and the revision list gain `author`; `ResourceDetail` gains `last_author` |
| `src/web.rs` | Resolve author + token label for the resource page and the revision list |
| `templates/resource.html` | Authorship line under the title |
| `assets/app.css` | `.byline` |
| `tests/flow.rs` | Authorship tests |
| `docs/01-protocol.md` | Document the new response fields |

## Design

### Schema v3

```sql
ALTER TABLE revision ADD COLUMN author_id       TEXT REFERENCES user(id)  ON DELETE SET NULL;
ALTER TABLE revision ADD COLUMN author_token_id TEXT REFERENCES token(id) ON DELETE SET NULL;
CREATE INDEX revision_author_idx ON revision(author_id);

-- Backfill: every existing revision was pushed by its project's owner, because
-- `resolve_or_create_project` has always refused anyone else. This is a fact
-- being written down, not a default being invented.
UPDATE revision SET author_id = (
    SELECT p.owner_id FROM resource r JOIN project p ON p.id = r.project_id
    WHERE r.id = revision.resource_id
) WHERE author_id IS NULL;
```

`author_token_id` stays NULL for a session-authenticated push (a human using the browse UI or curl
with a cookie) and for backfilled rows, where the credential is genuinely unknown. NULL means "not
recorded", never "unknown human".

### Where it is written

`open_revision` — the row is created there, so the actor is stored at insert rather than patched at
seal. A revision that never seals still carries its author, which is what an operator wants when
asking why an upload is stuck.

### API

`RevisionDetail` gains:

```rust
pub author: Option<Author>,      // None only for a row whose account was deleted

pub struct Author {
    pub name: String,
    pub token_label: Option<String>,
    pub token_revoked: bool,
}
```

Joined live rather than frozen (the opposite of the activity log): an event is a historical record
of a moment, while an item's author is a live pointer to an account that can be renamed. A renamed
account should read correctly on its items and unchanged in the log of what happened.

`ResourceDetail` gains `last_author`, resolved from the head revision, so a caller listing
resources does not have to fetch each revision to know who last touched it.

`GET /v1/resources/{id}/revisions` gains `author` per row — that list is exactly the "who changed
this, when" view.

### UI

A byline under the resource title, ordered by how much the server can vouch for:

```
review · 2026-08-09-nav · revision 2 of 2
by wk · krypton on this laptop · Claude-1 from macbook
```

- **`by wk`** — the authenticated account.
- **`krypton on this laptop`** — the token label, when the push used one. A revoked token still
  shows its label, marked `(revoked)`: it says who pushed it *then*, and the revocation is part of
  the story rather than a reason to hide it.
- **`Claude-1 from macbook`** — `meta.lane` and `origin.hostname`, both client-asserted. Rendered
  in the muted voice the rest of the UI uses for metadata, and never mixed into the first two.

The revision list already exists as `← revision 1 / revision 2 →` navigation; each revision link
gains its author in a `title` attribute, so stepping through revisions shows who did each without
adding a row of chrome.

## Edge Cases

- **Deleted account** — `author_id` goes NULL; the byline falls back to "by (deleted account)"
  rather than vanishing, so the item does not silently look unattributed.
- **Backfilled rows** — no token, so the byline is just `by <owner>`. Truthful: the account is
  known, the credential is not.
- **Unsealed revision** — carries an author but is invisible to every read route, so nothing shows.
- **Renamed account** — the byline follows the rename; the activity log does not. Both are correct
  for what they are, and the spec above says why.
- **Anonymous reader on a public project** — sees the byline. A public project's authorship is
  already implied by its owner being public; hiding it would be theatre.

## Testing

1. a push under a token records the account and that token, and the resource page shows both;
2. a second push from a *different* token shows the new token on revision 2 and the old one on
   revision 1;
3. a revoked token still names itself on the revision it pushed, marked revoked;
4. a session-authenticated push records the account with no token;
5. migration: a database written before v3 backfills every existing revision to its project owner;
6. the byline never renders a client-asserted field as if it were verified (lane and host stay in
   the muted span).

## Out of Scope

Signing or verifying `origin` · per-file authorship · changing who may push (still owner-only) ·
attributing reads · showing authorship on the project-list cards (the resource page and the API are
where the question is asked).

## Resources

- [npm registry — `_npmUser` vs `author`](https://docs.npmjs.com/cli/v10/configuring-npm/package-json#people-fields-author-contributors)
  — the authenticated-publisher vs self-declared-author split this spec copies.
- [Git — author vs committer](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects) — the
  two-identity model, and the reminder that an unsigned identity string is a claim, not a fact.
