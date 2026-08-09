# Xenon wire protocol

Mechanical extract of the contract. The design, rationale, and rejected
alternatives live in the Krypton repo at `docs/212-xenon-resource-server.md`,
which is authoritative — if the two disagree, that spec wins.

All request and response bodies are JSON unless noted. Errors are
`{ "error": "<machine_code>", "message": "<human text>", "detail": {…}? }`.

## Authentication

| Credential | Header / cookie | Used by |
|---|---|---|
| API token | `Authorization: Bearer xen_<id>_<secret>` | Krypton, external integrations |
| Session | `Cookie: xenon_session=<value>` | the browse UI |

Token format is `xen_<12-char id>_<32-char secret>`, base32. The id is stored in
the clear; only the secret's sha256 is persisted. The plaintext is returned
exactly once, from `POST /v1/tokens`.

Scopes: `resource:read`, `resource:write`, `project:admin`. A session carries the
user's full authority. **A token can never mint another token** — every
`/v1/tokens` and `/v1/invites` operation requires a session.

Supplying no credential is allowed on read routes and yields anonymous access
(public projects only). Supplying a *bad* credential is always an error, never a
silent downgrade.

## Accounts

### `POST /v1/auth/register`

```json
{ "email": "wk@example.com", "password": "at least 12 chars",
  "display_name": "wk", "invite": "optional-code" }
```

The first registration on a fresh instance becomes admin and needs no invite.
After that: allowed only with a valid unused `invite`, or when
`XENON_ALLOW_SIGNUP=1`. → `201` + user, and a session cookie.

Errors: `403 signup_closed`, `403 invalid_invite`, `400 weak_password`,
`400 invalid_email`, `409 registration_failed` (deliberately generic — this
endpoint is not an account-existence oracle).

### `POST /v1/auth/login` · `POST /v1/auth/logout`

Login takes `{ email, password }` → `200` + session cookie. Rate-limited to 5
attempts per 15 minutes per (ip, email) → `429 rate_limited`. Failure is always
`401 invalid_credentials`, whether or not the account exists.

### `GET /v1/me`

→ `{ user, projects[], tokens[] }`. Token entries carry metadata only — id,
label, scopes, project, timestamps. Never the secret.

### `POST /v1/invites` *(admin, session)*

→ `{ code, expires_at }`. Single use, 7-day default.

## Tokens *(session only)*

### `POST /v1/tokens`

```json
{ "label": "krypton on this laptop", "scopes": ["resource:write"],
  "project": "krypton", "expires_in_days": 90 }
```

→ `201 { id, token, scopes, project, expires_at }`. `token` is the only time the
secret is returned. `project` restricts the token to one project the caller
already owns; omit it for all of their projects.

### `GET /v1/tokens` · `DELETE /v1/tokens/{id}`

List (metadata only) · revoke (`204`). Revocation is checked per request with no
caching, so an in-flight push starts failing at its next call.

## Push

Three steps. Blobs are content-addressed, so only bytes the server does not
already hold are transferred.

### 1. `POST /v1/projects/{project}/resources` *(`resource:write`)*

`{project}` is a **single path segment** — no slashes. Krypton derives
`<owner>.<repo>` from the git remote. The project is created on first push,
owned by the token's user.

```json
{
  "kind": "review",
  "slug": "2026-08-07-peering-guard-rewrite",
  "title": "Peering guard rewrite",
  "origin": { "hostname": "laptop", "project_dir": "/Users/wk/Source/krypton" },
  "meta": { "lane": "Claude-2" },
  "files": [
    { "path": "review.md", "sha256": "<64 lowercase hex>", "size": 1024,
      "content_type": "text/markdown" }
  ]
}
```

`kind` ∈ `artifact | review | analysis | doc | attention`. `slug` may contain
slashes (an analysis bundle is `owner/repo/number`). `files` may be empty.

→ `202 { resource_id, revision_id, missing: [...], unchanged: false, url }` —
`missing` lists only the digests to upload.

→ `200 { resource_id, revision_id: null, missing: [], unchanged: true, url }`
when the head revision already holds exactly these files and this `meta`. Stop
here; nothing needs transferring.

Errors: `400 invalid_kind | invalid_slug | invalid_title | invalid_file_path |
invalid_digest | duplicate_file_path | invalid_project`,
`403 missing_scope | project_scoped_token`, `413 payload_too_large`.

### 2. `PUT /v1/blobs/{sha256}` *(`resource:write`)*

Raw body. → `201` stored, `200` already held. The server rehashes and rejects a
lying digest with `400 digest_mismatch`; nothing is stored in that case. Over
`XENON_MAX_BLOB_MB` → `413`.

### 3. `POST /v1/revisions/{revision_id}/commit` *(`resource:write`)*

Seals the revision and makes it the resource's head. → `200 { resource_id,
revision_id, seq, url }`.

Errors: `409 missing_blobs` with `detail.missing[]` listing digests still
absent; `409 already_committed`; `404` if the revision is not yours.

### Single-shot: `POST /v1/projects/{project}/resources:inline`

For resources ≤ 1 MB total — notably `attention` records, which have no files.
Same manifest fields, plus `contents[]` carrying the bodies:

```json
{ "kind": "attention", "slug": "jdg-1786109040786-2edbd1b0",
  "title": "Server language for Xenon",
  "meta": { "reversibility": "costly" },
  "contents": [ { "path": "note.md", "content_base64": "…",
                  "content_type": "text/markdown" } ] }
```

→ `201` committed in one round trip (or `200` when unchanged). Digests are
computed server-side from the decoded bytes.

## Read

| Route | Returns |
|---|---|
| `GET /v1/projects` | projects visible to the caller |
| `GET /v1/projects/{project}/resources?kind=&since=&limit=` | committed resources, newest first |
| `GET /v1/resources/{id}` | resource + head revision + file list |
| `GET /v1/resources/{id}/revisions` | sealed revisions, newest first |
| `GET /v1/revisions/{rev}/files/{path}` | raw bytes |
| `GET /healthz` | `ok` |
| `GET /v1/activity?project=&kind=&cursor=&limit=` | the activity log the caller may see, newest first |

### Authorship

Every revision records the actor the server authenticated for that upload, and every read route
that returns one carries it:

```json
"author": { "name": "wk", "token_label": "krypton on this laptop", "token_revoked": false }
```

`GET /v1/resources/{id}` also returns `last_author`, resolved from the head revision, so listing
who last touched a resource costs no extra request. `GET /v1/resources/{id}/revisions` carries
`author` per row.

`token_label` is `null` for a session-authenticated push and for revisions written before this
existed: null means **not recorded**, never "unknown human". A revoked token still names itself,
with `token_revoked: true` — it says who pushed that revision at the time.

This is the **verified** half of an upload's identity. The `origin` object beside it (`hostname`,
`project_dir`, `krypton_version`) and `meta.lane` are whatever the pushing client asserted about
itself; the two are deliberately never merged, and the browse UI renders the claimed half in a
muted voice that says so. See `docs/04-upload-authorship.md`.

### `GET /v1/activity`

`{ "events": [ { id, seq, kind, actor, project, resource_id, url, subject, detail, created_at } ],
"next_cursor": <int|null> }`

`cursor` is opaque and comes from the previous response's `next_cursor` — **not** a timestamp.
Timestamps are seconds and a single push writes two events inside one, so seconds cannot page;
the cursor is insert order, which is both the true order of a log and strictly monotonic.
`next_cursor` is null on the last page. `limit` is 1..100, default 30.

Rows are one of two audiences. A `project` row (`resource.publish`, `resource.revise`,
`project.create`) is visible when its project is public or the caller owns it. An `account` row
(`account.register` · `login` · `login_failed` · `logout`, `token.create` · `token.revoke`,
`invite.create` · `invite.claim`) is visible only to its own actor, and to an admin. A failed
sign-in against an unknown email has no actor at all, so only an admin ever sees it — attaching it
to an account would rebuild the existence oracle `register` refuses to be.

Reads are not recorded; see `docs/03-activity-feed.md`. Rows older than
`XENON_ACTIVITY_RETENTION_DAYS` (default 90, `0` = forever) are pruned from the write path.

Read needs `resource:read` (or a session, or a public project). Uncommitted
revisions are invisible to every read route.

Raw file reads send `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, and a restrictive CSP — uploaded bytes are
agent-authored and untrusted.

## Browse

`/` the activity feed · `/projects` the project list · `/p/<project>` resources,
filterable by kind · `/p/<project>/usage` the LLM usage ledger ·
`/r/<project>/<kind>/<slug>` the resource ·
`/r/<project>/<kind>/<slug>/@<seq>` a pinned revision · `/register` · `/login` ·
`POST /logout` · `/settings/tokens`.

The feed is the home page: opening the server answers *what has happened* before
*what exists*. `/activity` was its address until then and answers `303` to `/`,
query string intact, so a bookmarked filter still lands on the rows it named.

A project has two pages — its resources and its usage — and each links to the
other. They are peers, not a filter of one another: usage is a second body of
data under the same project, not a sixth resource kind.

`/settings/tokens` is the one private page: without a session it answers `303`
to `/login` rather than rendering a shell its script would then have to empty.

`POST /logout` is the browse UI's sign-out form. It ends the same session as
`POST /v1/auth/logout` but answers `303` to `/`, since a form post that lands on
`{"ok":true}` is not a page. Both are POST-only, so `SameSite=Lax` keeps the
session cookie off a cross-site attempt to sign someone out.

The chrome is drawn per reader: signed in, the nav shows the account, `tokens`,
and `sign out`; anonymous, it shows `sign in` only.

Markdown renders server-side with raw HTML disabled. HTML artifacts render in a
`sandbox`ed iframe.

## LLM usage turns

A second ingest surface, deliberately outside the resource envelope. Krypton
posts one row per completed prompt turn, as it happens. A row is numeric —
token counts, a model id, a lane label, a stop reason — and carries no prompt or
response text; that is what makes streaming it unattended acceptable. See the
Krypton repo's `docs/214-llm-usage-statistics.md` and its ADR-0019.

`POST /v1/projects/{project}/usage/turns` — `resource:write`, project created on
first post like any resource push.

```jsonc
// request                            // 202 response
{ "turns": [ {                        { "accepted": 2,
  "v": 1,                               "duplicates": 1,
  "id": "usg-1786233600000-0f765408",   "rejected": [ { "id": "…", "reason": "…" } ] }
  "at": 1786233600000,
  "durationMs": 41230,
  "hostname": "mbp", "harnessId": "hm-1",
  "lane": "Claude-3", "backend": "claude",
  "model": "claude-opus-5", "modelConfirmed": true,
  "sessionId": "…", "turn": 7,
  "stopReason": "end_turn", "origin": "user",
  "tokens": { "input": 12043, "output": 812,
              "cachedRead": 98211, "cachedWrite": 0 },
  "context": { "used": 132000, "size": 1000000 },
  "cost": { "amount": 0.42, "currency": "USD" }
} ] }
```

`id` is the **client's** key and the primary key is `(project_id, id)`, so a row
re-sent after a timeout the client could not interpret is counted as a
`duplicate`, never as a second charge. That is the property the whole design
rests on: it is what lets the client retry blindly.

`tokens: null` means the adapter reported no counters. It is stored as
`has_tokens = 0` and counted separately in every total — a zero would be
indistinguishable from a genuinely free turn and would understate the project.

A row that cannot be stored is named in `rejected[]` and the rest of the batch
still lands; one bad row must not hold a fleet's ledger hostage. Clients ack
rejects deliberately, since a row the server will never accept would otherwise
wedge everything behind it. At most 500 turns per request. `cost` is stored only
when the *adapter* reported one; estimates are never persisted.

`GET /v1/projects/{project}/usage?from=&to=&group=` — `resource:read`, a session,
or a public project. `from`/`to` are epoch **milliseconds**, `from` inclusive and
`to` exclusive. `group` is one of `day` (default), `model`, `lane`, `backend` —
a fixed set, never interpolated into SQL.

```jsonc
{ "project": "wk-j.krypton", "group": "model", "from": null, "to": null,
  "totals": { "turns": 128, "turnsWithoutTokens": 6,
              "inputTokens": 4210331, "outputTokens": 182044,
              "cachedReadTokens": 39118220, "cachedWriteTokens": 210443,
              "reportedCost": 4.12, "reportedCostTurns": 40,
              "estimatedCost": 71.83, "currency": "USD" },
  "buckets": [ { "key": "claude-opus-5", … } ],
  "unpriced": [ "some-local-model" ] }
```

`reportedCost` and `estimatedCost` are **never summed**. One is what the
provider told the client; the other is what this server computed. `estimatedCost`
is absent — not `0` — when no model in the bucket matched a rate, and every such
model is named in `unpriced`.

### The usage page

`/p/<project>/usage?days=` renders the same aggregation the API serves, over a
window of `1`, `7`, `30`, or `0` (everything) days. It shows the range total,
then the same table grouped by `model`, `lane`, `backend`, and `day`, then the
newest 60 turns themselves.

The ledger is the part the aggregates cannot replace. A total can say a week
cost $40 and offer nothing to point at when that looks wrong, and the per-turn
facts that cannot be summed — why a turn stopped, what started it, how full the
context was, and whether the model id was one the agent confirmed — appear
nowhere else. It carries no estimated-cost column on purpose: an estimate is a
rate table applied to a bucket of tokens, and one per row would invite adding it
to the reported column.

A bucket in which **no** turn carried counters prints `—` in every token cell
and `none reported` beside its turn count. Its sums are zero by construction,
and printing them would say the lane was free when the truth is that nobody
measured it.

### Model prices

Cost is computed on **read**, from `$XENON_DATA_DIR/prices.json` — by default
`~/.config/xenon/prices.json` (`XENON_PRICES_FILE` overrides) — so correcting a
rate corrects history. Copy
`assets/prices.example.json` and replace its zeros with the figures from each
provider's price page.

```jsonc
[ { "match": "claude-opus-*",   // case-insensitive, `*` is the only wildcard,
    "input": 15.0,              // FIRST match wins, so overrides go above families
    "output": 75.0,
    "cached_read": 1.5,         // optional; absent ⇒ priced at the input rate,
    "cached_write": 18.75,      //   which overstates rather than zeroes
    "currency": "USD",
    "source": "https://…" } ]   // provenance, never used in arithmetic
```

Rates are USD per **million** tokens. An entry whose rates are all zero is
treated as *unfilled*, not as free — the example file ships exactly that shape.
A missing file is not an error; the page simply shows tokens without estimates.
The table is read once at boot, so editing it takes effect on restart.
