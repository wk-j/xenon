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

Read needs `resource:read` (or a session, or a public project). Uncommitted
revisions are invisible to every read route.

Raw file reads send `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, and a restrictive CSP — uploaded bytes are
agent-authored and untrusted.

## Browse

`/` projects · `/p/<project>` resources, filterable by kind ·
`/r/<project>/<kind>/<slug>` the resource · `/r/<project>/<kind>/<slug>/@<seq>`
a pinned revision · `/register` · `/login` · `/settings/tokens`.

Markdown renders server-side with raw HTML disabled. HTML artifacts render in a
`sandbox`ed iframe.
