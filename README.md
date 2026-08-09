# Xenon

Central resource server for [Krypton](https://github.com/wk-j/krypton)-generated
work product — HTML artifacts, review bundles, issue analyses, docs, and
attention flags.

Everything Krypton's ACP Harness produces lives in one machine's working tree
under a gitignored `.krypton/` directory, viewable only through loopback
endpoints of the running app. Xenon is where that work goes to become durable,
shareable, and readable when Krypton is not running.

Single static binary. SQLite for metadata, a content-addressed directory for
file bytes. No external services.

## Quick start

```sh
make dev
```

That runs `scripts/dev.sh`, which generates a session secret on first run
(persisted at `data/.session-secret`, mode 0600, gitignored), allows non-`Secure`
cookies so plain HTTP works on localhost, and serves on `:8787`.

```sh
make dev                  # debug build
make release              # optimized build
make reset                # wipe ./data (prompts first), then start fresh
PORT=9000 scripts/dev.sh  # different port
```

**Development only** — `scripts/dev.sh` sets `XENON_INSECURE_COOKIES=1`. Real
deployments terminate TLS at a reverse proxy and must not set it; see
[Deployment](#deployment).

Then open <http://localhost:8787/register>. **The first account to register
becomes the admin** — do this immediately, before the instance is reachable from
anywhere else. After that, registration requires an admin-issued invite code
unless you set `XENON_ALLOW_SIGNUP=1`.

Mint a token at `/settings/tokens`, then point Krypton at it:

```toml
# ~/.config/krypton/krypton.toml
[xenon]
enabled  = true
base_url = "https://xenon.example.com"
```

The token goes in the OS keychain, never in the TOML — Krypton writes it there
when you paste it in.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `XENON_PORT` | `8787` | listen port (binds `0.0.0.0`) |
| `XENON_DATA_DIR` | `./data` | holds `xenon.db` and `blobs/` |
| `XENON_SESSION_SECRET` | — | **required**, ≥32 chars; refuses to start without it |
| `XENON_MAX_BLOB_MB` | `64` | per-file upload cap |
| `XENON_ALLOW_SIGNUP` | `0` | `1` opens registration to anyone |
| `XENON_INSECURE_COOKIES` | `0` | `1` drops `Secure` from the session cookie — local HTTP development only |
| `XENON_ACTIVITY_RETENTION_DAYS` | `90` | how long `/activity` keeps a row; `0` keeps everything |

There is deliberately **no admin token and no seeded admin password**, so there
is no long-lived credential to leak from a compose file or shell history.

## Deployment

Xenon speaks plain HTTP and expects TLS to terminate at a reverse proxy. Put it
behind nginx/Caddy/Traefik and forward `X-Forwarded-Proto`.

```sh
docker build -t xenon .
docker run -d --name xenon -p 8787:8787 \
  -e XENON_SESSION_SECRET="$(openssl rand -hex 32)" \
  -e XENON_DATA_DIR=/data \
  -v xenon-data:/data \
  xenon
```

Back up the whole `XENON_DATA_DIR` — the SQLite database alone is not enough,
because file bytes live beside it in `blobs/`.

## Concepts

A **resource** is one publishable thing: `{ project, kind, slug, title, meta,
files[] }`. Five kinds — `artifact`, `review`, `analysis`, `doc`, `attention`.
Bundles and single files differ only in file count; an `attention` record has no
files at all and carries everything in `meta`.

Blobs are **immutable** and content-addressed by sha256. Resources are
**mutable through revisions**: each push appends a sealed revision, and the
latest becomes the head. Nothing is ever silently overwritten, and every
revision keeps its own permalink at `/r/<project>/<kind>/<slug>/@<seq>`.

A revision is invisible until it is committed, so an interrupted push never
exposes a half-uploaded resource.

## Security posture

- Sessions are server-side rows; logout and revocation take effect immediately.
- Passwords are argon2id. Login is rate-limited and reports one generic failure
  for both unknown-email and wrong-password.
- **A token can never mint another token** — minting requires a session, so a
  leaked integration token cannot escalate into a permanent foothold.
- Token secrets are stored only as sha256; the plaintext exists once, in the
  creation response.
- Uploaded HTML is agent-authored and is framed `sandbox`ed. Uploaded markdown
  renders with raw HTML disabled. Raw file reads send `nosniff`, `no-store`,
  `no-referrer`, and a restrictive CSP.
- A caller who may not read a project is told it does not exist, so project
  names are not enumerable.

## LLM usage

Besides resources, Xenon stores **per-turn LLM usage** streamed live by Krypton:
token counts, model, lane, and the cost the provider reported. Rows are numeric
only — no prompt or response text ever reaches this server.

Browse them at `/p/<project>/usage`, reachable from the `llm usage` tab on any
project page. Pick a window (today · 7 days · 30 days · all) and the page shows
the range total, the same figures grouped by model, lane, backend, and day, and
then the newest 60 turns themselves — the rows the sums are made of, with the
per-turn facts that cannot be summed: why each turn stopped, what started it,
how full its context was, and whether the model id was one the agent confirmed.

Cost estimates need a rate table. Xenon ships **no prices of its own**: copy
`assets/prices.example.json` to `$XENON_DATA_DIR/prices.json` and replace its
zeros with the figures from each provider's price page. Until you do, the page
shows token counts and names each model as unpriced — a blank column is honest,
an invented total is not. Prices are applied on read, so fixing a rate fixes
every past report.

## API

See [`docs/01-protocol.md`](docs/01-protocol.md) for the wire contract. The full
design and its rationale live in the Krypton repo at
`docs/212-xenon-resource-server.md`.

## Development

```sh
make test    # 88 unit + 46 end-to-end tests
make lint    # clippy, warnings denied
make fmt     # rustfmt in place
make check   # fmt --check + lint + test
make help    # every target
```
