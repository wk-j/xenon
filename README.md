# Xenon

Central resource server for [Krypton](https://github.com/wk-j/krypton) work
product — HTML artifacts, review bundles, issue analyses, docs, attention flags,
and daily notes.

Krypton keeps that work in a gitignored `.krypton/` tree, reachable only on
loopback while the app is running. Xenon makes it durable and readable when
Krypton is not. Single static binary; SQLite for metadata, content-addressed
blobs for files; no external services.

## Install

```sh
brew install wk-j/tap/xenon
brew services start xenon
```

Homebrew builds from source (`rust` is build-only) and installs `xenon` (server),
`xenon-serve` (mints the session secret on first run — what `brew services`
runs), and `xen` (CLI). Track `master` with `brew install --HEAD wk-j/tap/xenon`.

Plain `http://localhost` will not keep a login — the session cookie keeps its
`Secure` flag. Run in the foreground instead; `xenon-serve` will not set this
for you, and behind [TLS](#deployment) it is not needed:

```sh
XENON_INSECURE_COOKIES=1 xenon-serve
```

## First account

Open <http://localhost:8787/register>. **The first account becomes the admin** —
do this before the instance is reachable from anywhere else. After that,
registration needs an admin-issued invite unless `XENON_ALLOW_SIGNUP=1`.

`/` is the activity feed, `/projects` the project list, `/p/<project>` that
project's activity, and `/admin` — first account only — users, projects,
resources, and the next invite.

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
| `XENON_DATA_DIR` | `~/.config/xenon` | `xenon.db`, `blobs/`, `prices.json`, `.session-secret` |
| `XENON_SESSION_SECRET` | — | **required**, ≥32 chars |
| `XENON_MAX_BLOB_MB` | `64` | per-file upload cap |
| `XENON_ALLOW_SIGNUP` | `0` | `1` opens registration to anyone |
| `XENON_INSECURE_COOKIES` | `0` | `1` drops `Secure` from the session cookie — local HTTP only |
| `XENON_ACTIVITY_RETENTION_DAYS` | `90` | activity feed retention; `0` keeps everything |

No admin token and no seeded admin password — nothing long-lived to leak from a
compose file or shell history.

## Deployment

Xenon speaks HTTP. Terminate TLS at a reverse proxy (nginx/Caddy/Traefik),
forward `X-Forwarded-Proto`, and do **not** set `XENON_INSECURE_COOKIES`.

### Docker Compose + Caddy (automatic HTTPS)

Point DNS `A`/`AAAA` at the server, open **80** and **443**, then:

```sh
cp .env.example .env
# set XENON_DOMAIN, ACME_EMAIL, and:
#   openssl rand -hex 32   → XENON_SESSION_SECRET
docker compose up -d
```

[`docker-compose.yml`](docker-compose.yml), [`Caddyfile`](Caddyfile),
[`.env.example`](.env.example) — only Caddy is published. Then register at
`https://$XENON_DOMAIN/register`.

### Docker only (no TLS)

```sh
docker run -d --name xenon -p 8787:8787 \
  -e XENON_SESSION_SECRET="$(openssl rand -hex 32)" \
  -e XENON_DATA_DIR=/data \
  -v xenon-data:/data \
  ghcr.io/wk-j/xenon:latest
```

Put a reverse proxy in front of `:8787` before exposing this. Images are also
tagged `0.1.17` / `0.1` — pin an exact version instead of `latest` when
repeatable deployments matter. To build locally: `docker build -t xenon .`

### Backups

Back up the whole `XENON_DATA_DIR` (the `xenon_data` volume in Compose) — SQLite
alone is not enough; file bytes live in `blobs/`. Back up `caddy_data` too, to
keep issued certificates across reinstalls.

## Concepts

A **resource** is `{ project, kind, slug, title, meta, files[] }`. Kinds:
`artifact`, `review`, `analysis`, `doc`, `attention`, `daily`. Bundles and single
files differ only in file count; `attention` has no files and carries everything
in `meta`, and `daily` is one developer day — `note.md` derived from records plus
an optional `brief.md` a lane narrated from it.

Blobs are **immutable** (sha256). Resources change by **revision**: each push
appends a sealed revision, the latest is head, and an interrupted push never
exposes a half-uploaded resource. Permalink: `/r/<project>/<kind>/<slug>/@<seq>`.

## Security

- Sessions are server-side; logout and revocation take effect immediately.
- Passwords are argon2id; login is rate-limited and reports one generic failure.
- **A token can never mint another token** — minting requires a session. Token
  secrets are stored only as sha256; the plaintext exists once, in the creation
  response.
- Uploaded HTML is framed `sandbox`ed, markdown renders with raw HTML disabled,
  and raw file reads send `nosniff`, `no-store`, `no-referrer` and a restrictive
  CSP.
- The browse UI and every data API require a login; `/healthz`, `/register` and
  `/assets/*` stay reachable.
- **Public** means every account on this instance may read the project, not the
  open internet. A caller who may not read a private project is told it does not
  exist.

## LLM usage

Xenon stores **per-turn LLM usage** streamed by Krypton (token counts, model,
lane, provider-reported cost — no prompt or response text). Browse at
`/p/<project>/usage`: today · 7 days · 30 days · all, totalled by model, lane,
backend and day, plus the newest 60 turns.

Cost estimates need a rate table: copy `assets/prices.example.json` to
`~/.config/xenon/prices.json` and fill in provider rates; until then models show
as unpriced. Prices are applied on read, so fixing a rate fixes every past
report.

## CLI

`xen` speaks the same `/v1` protocol as the UI and Krypton. Config:
`~/.config/xenon/cli.toml` (mode 0600), overridden by `--url` / `--token` or
`XENON_URL` / `XENON_TOKEN`. Minting or revoking a token still needs a session.
`--json` prints the server body instead of a table.

```sh
xen --help
xen login --email you@example.com
xen invite
xen token create --label 'this laptop' --save
xen push my.project --kind doc --slug notes --title Notes --file README.md
xen resource list my.project
xen activity
```

## API

Wire contract: [`docs/01-protocol.md`](docs/01-protocol.md). Design and rationale
live in the Krypton repo at `docs/212-xenon-resource-server.md`.

## Development

From a checkout. **State lives in `~/.config/xenon`**, not here, so a dev build
and an installed binary are one server with one set of accounts
(`XENON_DATA_DIR` overrides). `scripts/dev.sh` mints the session secret on first
run (`.session-secret`, mode 0600) and sets `XENON_INSECURE_COOKIES=1`.

```sh
make dev                  # debug build on :8787
make watch                # rebuild and restart on save
make release              # optimized build
make reset                # wipe ~/.config/xenon (prompts first), then start fresh
PORT=9000 scripts/dev.sh  # different port

make check                # fmt --check + lint + test — what CI runs
make test                 # unit + end-to-end (server and xen CLI)
make docker               # build the deployment image
make help                 # every target

cargo run -p xen -- --help        # the CLI, from this checkout
cargo install --path cli --locked
```
