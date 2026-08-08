# Frontend Architecture — Implementation Spec

> Status: Stage 1 Implemented · Stage 2 assets Implemented · Stage 3 Retired (no framework) · `maud` still Draft
> Date: 2026-08-08
> Reviewed: 2026-08-08 by Grok-1 (architecture & correctness) — 4 blockers, 10 warnings.
> Synthesis: `.krypton/reviews/2026-08-08-xenon-frontend-architecture-review-synthesis/`.
> Two blockers were factual errors in this document and are corrected below; both were
> independently verified against the source before editing.
> Repo: xenon
> Related: `docs/01-protocol.md` · Krypton `docs/212-xenon-resource-server.md` + ADR-0016

## Problem

Xenon's browse UI is HTML assembled with `format!` inside `src/web.rs` — one `STYLE` const, a
handful of inline `<script>` blocks, no asset directory, no build step. That was right for six
read-only pages, and it is already the ceiling.

The gap is visible today, not hypothetical. `render_file` (`src/web.rs:400`) has exactly four
cases: HTML → sandboxed iframe, image → `<img>`, markdown → comrak, else → download link. So a
Review Board pushed from Krypton — a document whose meaning lives in typed fences
(`review:walkthrough`, `review:finding`, `review:decision`, `review:chart`, `review:svg`) — lands
on Xenon as **raw fence source in a grey code block**. The same is true of issue analyses. A
teammate opening a Board on Xenon sees strictly less than the person who has Krypton running,
which inverts the entire point of publishing.

Anything richer — searching resources, filtering a project by kind, stepping a walkthrough,
diffing two revisions — has nowhere to live in the current structure.

## Solution

Three stages, ordered so each is independently shippable and the cheap one lands first. The
governing constraint is that **Xenon stays one static binary with no external services** (README,
`Dockerfile`), so every stage embeds its assets at compile time rather than adding a runtime
dependency or a separate frontend server.

1. **Typed-block rendering** — port Krypton's fence-aware post-pass so Boards and analyses render
   as semantic HTML. No new dependencies, no frontend machinery, closes the visible gap.
2. **A real asset pipeline** — CSS and JS as files in `assets/`, embedded at compile time and
   served with content-hashed URLs. This is the "complex frontend" capability, and it is done.
   `maud` for compile-time-checked, auto-escaping Rust templates is still proposed, separately.
3. ~~Islands~~ — **retired**. No framework, no build step; see Stage 3.

Chosen over a full SPA (see Research). Stage 2 is the load-bearing decision; stages 1 and 3 are a
prelude and an escape hatch.

## Research

- **The typed-block problem is already solved in-tree.** Krypton's `render_review_blocks`
  (`src-tauri/src/hook_server.rs:6311`) is a string-level post-pass over comrak output: comrak
  emits a fence as `<pre><code class="language-review:finding">`, and the pass rewrites known
  fences into semantic markup while leaving unknown ones as plain code blocks. It needs no
  client-side code at all. Xenon already depends on comrak, so the *rendering logic* is a port.
  The **security posture is not** — see the next point. An earlier draft of this spec called
  stage 1 "a port, not a design"; that was wrong and the review caught it.
- **Stage 1 crosses a trust boundary Krypton's version never had.** Krypton's post-pass runs on a
  loopback surface for the one local user who already owns the machine. Xenon serves the same
  agent-authored markup from an origin holding session cookies for multiple accounts. Identical
  code, different blast radius: an escaping omission that is cosmetic on loopback is
  session-stealing XSS here. Stage 1 is therefore gated on porting Krypton's refusal corpus as
  Xenon tests, not on visual parity.
- **Security posture must survive intact.** Bundle text is agent-authored and untrusted:
  `markdown_to_html` keeps `render.unsafe_ = false` so an embedded `<script>` renders as text, and
  agent HTML is framed `sandbox="allow-scripts"` with `referrerpolicy="no-referrer"` so it never
  runs with this origin's authority. Any templating choice must preserve escape-by-default —
  which is why `maud` (auto-escaping, compile-time checked) is preferred over string `format!`,
  where a single missed `escape()` call is an XSS.
- **htmx introduces a specific new risk** that does not exist today: it swaps server HTML into the
  live, authenticated DOM. That is safe only for **server-generated** fragments. Agent-authored
  bytes must continue to reach the browser only via the sandboxed iframe or comrak-with-unsafe-off
  — never as an htmx swap target. This is the sharpest constraint in the spec.
- **Embedding assets is a solved problem in this stack.** `rust-embed` bakes a directory into the
  binary at compile time; `axum-embed`'s `ServeEmbed` serves it and will serve precompressed
  `br`/`gzip` variants when the client supports them. The known caveat is binary size for
  image-heavy sites — irrelevant here, where assets are CSS, one JS library, and a font-free
  design.
- **Prior art says hypermedia is the right shape for this workload.** Reported migrations to htmx
  for internal tools and admin panels cut frontend code 40–60% with no framework build step; the
  documented case *against* htmx is consumer-facing apps with complex client state. Xenon's pages
  are documents: read-mostly, permalink-critical, deep-linked, with interactivity that is mostly
  "fetch and swap a region".

**Alternatives ruled out:**

- **Full SPA (React/Svelte/Solid) + JSON API.** Adds a Node toolchain and a second build stage to
  a Rust repo that currently builds with `cargo build` alone; duplicates the session/auth model on
  the client; pays hydration cost on pages that are 95% static prose; and would make the
  `Dockerfile` multi-toolchain. It buys client-state management that Xenon's pages do not need.
- **Keep `format!` and add more inline `<script>`.** This is the status quo extended, and it is
  what makes the current code unable to grow: no escaping guarantee, no reuse, no caching story,
  and CSS/JS that cannot be linted or served with cache headers.
- **CDN-loaded htmx/Tailwind.** Rejected outright: an external runtime dependency contradicts "no
  external services", and a self-hosted Xenon may run on a network with no internet egress.

## Prior Art

| Project | Approach | Notes |
|---------|----------|-------|
| Krypton loopback surfaces | Server-rendered HTML from Rust + a fence-aware comrak post-pass; Binance-dark identity in `DESIGN.binance.md` | The visual and structural sibling — Xenon should read as the same family |
| Gitea / Forgejo | Server-rendered Go templates + embedded assets, htmx-style progressive enhancement, single binary | Closest analogue: a self-hosted, single-binary artifact/code browser |
| Grafana, Sentry | Full SPA over a JSON API | What Xenon is deliberately *not* — their client state (live dashboards, query builders) justifies the cost; a resource browser's does not |
| GitHub Actions Artifacts | Server-rendered listing + direct blob download; no client app | Already the model `docs/01-protocol.md` follows for the API |

**Xenon delta** — matches convention on server-rendered documents with embedded assets and a
single binary. Diverges from the mainstream SPA default deliberately, and diverges from plain
server rendering by vendoring htmx rather than reaching for a CDN.

## Affected Files

| File | Change |
|------|--------|
| `src/web.rs` | Split: `format!` HTML → `maud` templates; extract page modules as it grows past one file |
| `src/render.rs` | **New** — typed-block post-pass (stage 1), ported from Krypton's `render_review_blocks` |
| `assets/` | **New** — `app.css`, `app.js`, `login.js`, `register.js`, `tokens.js`; plain JS, no framework, no build step |
| `src/assets.rs` | **New** — `include_str!` table + `/assets/{name}` route, content-hashed URL helper |
| `src/api.rs` | Unchanged — `/v1/` is the only API; the browse UI fetches JSON from it |
| `Cargo.toml` | `+ maud` (templates). **No asset crate**: see the Design note — `include_str!` covers five files with zero dependencies |
| `Dockerfile` | **Done** — `COPY assets ./assets` before the second `cargo build`. An earlier draft said "unchanged"; that was wrong, and `include_str!` would have failed the image build after passing locally |
| `docs/01-protocol.md` | Note that fragment routes are UI-only and not part of the published API contract |
| `README.md` | Frontend section: no Node toolchain, assets embedded, how to add one |

## Design

### Stage 1 — Typed-block rendering

Port `render_review_blocks` into `src/render.rs` and call it from `render_file`'s markdown branch.
Renders `review:walkthrough`, `review:finding`, `review:decision`, `review:metrics`,
`review:chart`, `review:svg`, and plain `diff` fences into semantic HTML; an unknown fence stays a
plain code block.

`review:svg` is the one place agent-authored markup is allowed into the trusted origin, so its
model must be stated exactly. Krypton's `render_rv_svg` is **not** an allowlist, despite what its
own doc comment claims and what an earlier draft of this spec repeated. It is
**refuse-whole-on-denylist**: the body is rejected outright if it does not start with `<svg`, or
contains any of `<script`, `<foreignobject`, `<iframe`, `javascript:`, `data:text/html`,
`xlink:href`, `url(http`, `url(//`, or an `on*=` event-handler attribute. Two of those checks run
on different forms of the text on purpose — the substring checks run on whitespace-compacted text
(so `java\tscript:` cannot slip through), while the handler check runs on un-compacted text (so
`onload` cannot be glued onto a preceding tag name). If nothing matches, **the original body is
emitted verbatim**; if anything matches, the whole diagram degrades to escaped source in a code
block.

**Residual risk, stated plainly:** a denylist is sound only to the extent its list is complete. An
SVG feature that is dangerous and not on the list passes through untouched. This is accepted for
now because the input is produced by our own agents rather than by anonymous users, and because
refusal degrades safely; it is *not* the by-construction guarantee an element/attribute allowlist
would give. Do not describe it as one. If Xenon later accepts resources from untrusted publishers,
this decision must be revisited before that lands.

No new dependency. No client-side code. Ships alone.

### Stage 2 — Assets (done) and templates (proposed)

**The asset half is done (2026-08-08), ahead of the rest of stage 2.** Deferring it was a mistake:
stage 1 added ~60 lines of CSS to the very `STYLE` const this spec exists to dismantle, which moved
the codebase *away* from the goal. CSS and JS now live in `assets/` as real files:

```
assets/app.css      the whole stylesheet, formerly a 139-line STYLE const
assets/app.js       shared fetch helpers, formerly inline in shell()
assets/login.js     formerly inline in login_page()
assets/register.js  formerly inline in register_page()
assets/tokens.js    formerly inline in tokens_page()
```

`src/assets.rs` bakes them in with `include_str!` and serves `/assets/{name}` with a content hash
in the query string. **`include_str!` rather than `rust-embed`/`axum-embed`**: five files and no
directory walk do not justify two dependencies, and swapping the crate in later changes no URL.
The single-binary property is unaffected. `Dockerfile` gained `COPY assets ./assets`.

This also removes every inline `<script>` from the browse UI, which is the precondition for a real
Content-Security-Policy — the one blocker that had no cheap fix while the scripts were inline.

**htmx and the `/f/` fragment routes are dropped.** With plain JS, a page that needs fresh data
calls the existing `/v1/...` JSON API with `fetch` and updates the DOM itself — no second HTML API,
no swap-target invariant to enforce, no new prefix to keep out of the published contract. That
single decision retires four of the review's findings outright (auth on `/f/*`, cache policy on
`/f/*`, `/f/` vs `/v1/` as a real boundary, and the htmx swap-target invariant).

**`maud` is still proposed, and is a separate question.** It is a Rust templating crate, unrelated
to the frontend-framework decision: it replaces `format!`-concatenated HTML in `src/web.rs`, where a
single missed `escape()` call is an XSS. Worth doing on its own merits; not required by anything
above.

```rust
// src/assets.rs
#[derive(rust_embed::RustEmbed, Clone)]
#[folder = "assets/"]
pub struct Assets;

// mounted at /assets, served by axum_embed::ServeEmbed<Assets>,
// with immutable cache headers on content-hashed paths
```

Templates move to `maud`'s inline macro — Rust-native, compile-time checked, auto-escaping, no
separate template files to keep in sync, and no runtime template errors. `escape()` stays for the
few places that build strings by hand, but stops being the only thing between an agent-authored
title and an XSS.

Interactivity is plain `fetch` against the **existing** `/v1/...` JSON API, with the page updating
its own DOM — the pattern `assets/app.js` (`xreq`/`xfail`) and `assets/tokens.js` already use:

```js
const r = await xreq('GET', `/v1/projects/${project}/resources?kind=review`);
```

**Agent-authored bytes keep their existing two paths** — the sandboxed iframe, or comrak with
`unsafe_` off — and page JS must never inject them into the trusted DOM. That constraint survives
the framework decision unchanged; only the mechanism it used to be phrased against (htmx swaps) is
gone.

### Stage 3 — RETIRED (2026-08-08)

There is no stage 3. The user's decision: **no framework, plain JavaScript is enough.** No React,
no Svelte, no htmx, no esbuild islands, no build step. Interactivity is `fetch` plus direct DOM
work in `assets/*.js`, which is already the pattern `app.js` and `tokens.js` use.

This is consistent with how Krypton itself is built (vanilla TypeScript by explicit constraint;
the Raycast extension uses React only because Raycast requires it), and it retires a large part of
this document — see Out of Scope.

An earlier revision recommended Svelte on the grounds of bundle size and less ceremony. That was
weak reasoning: for an internal tool the bundle difference is unobservable, and the criterion that
actually matters here is who maintains the code. Recorded so the argument is not re-run.

### Configuration

None. No new environment variables; assets are compile-time.

## Edge Cases

- **Binary size** — assets are text and currently ~250 lines total. Budget: keep embedded assets
  under 200 KB uncompressed.
- **Cache busting** — content-hashed `/assets/*` URLs may use `immutable`. No other route may:
  everything else carries project data and stays `no-store`.
- **Search load** — any list or search endpoint the UI calls needs a hard `LIMIT` and pagination.
  A search box firing per keystroke against an uncapped query is a self-inflicted DoS on a
  SQLite-backed server, worst exactly where a project has the most resources.
- **No-JS / a script fails to load** — every page must render its content server-side and use JS
  only to enhance, so the UI degrades to plain navigation rather than blanking.
- **Agent-authored SVG** (`review:svg`) — refuse-whole-on-denylist (see Stage 1); a refused
  diagram renders as escaped source in a code block rather than being injected.
- **Offline / air-gapped deployment** — nothing loads from a CDN, by construction.
- **Existing permalinks** — `/p/{project}` and `/r/{project}/{kind}/{*slug}` keep their **URLs**
  stable; the fragment routes are additive. Rendered markup is *not* byte-stable — changing the
  HTML body of a `review.md` is the entire point of stage 1. An earlier draft promised
  byte-for-byte, which contradicted the feature.
- **CSP** — `src/web.rs` used to carry eight inline `<script>` blocks, which is why no useful
  `Content-Security-Policy` could be set. Stage 2 **deleted** them when extracting assets rather
  than supplementing them, and lands a CSP at the same time. **The extraction is done**, so a CSP
  is now writable — it is the obvious next piece of work.
- **Page JS must never inject agent bytes into the trusted DOM** — they keep their two existing
  paths (sandboxed iframe, or comrak with `unsafe_` off). This survives the framework decision; only
  the htmx phrasing of it is gone.
- **`maud::PreEscaped`** — the one hole in escape-by-default. Confine it to a single audited seam.

## Open Questions

**Which new feature is driving this?** Still unanswered, and it blocks **stages 2–3 only**. The
concrete feature decides whether stage 3 is needed at all and what the first fragment routes
should be — "render Review Boards properly" needs only stage 1, "search across all resources"
needs stage 2, "step a walkthrough with the keyboard" needs stage 3.

**Stage 1 is unblocked by this question** and was approved on 2026-08-08: its motivation (Boards
currently render as raw fence source) is independent of whatever comes next, and the reviewer
agreed stage 1's logic will not have to be rewritten by stage 2. The one carry-over it creates is
CSS: the ported renderers emit `rv-*` classes into the `STYLE` const in `src/web.rs`, which stage 2
then moves to `assets/app.css`. That churn is expected, not a surprise.

**Stage 1 acceptance criteria:**

1. Every `render_rv_*` re-escapes after `html_unescape`; `markdown_to_html` keeps
   `render.unsafe_ = false`.
2. Krypton's SVG refusal corpus ports as Xenon tests — XSS fixtures, not visual parity.
3. A canary test pins comrak's `<pre><code class="language-…">` fence output shape, so an upgrade
   fails loudly instead of silently reverting every Board to grey code blocks.
4. An unknown `review:*` fence renders as a labelled code block, never disappears.

## Out of Scope

- **Any JavaScript framework — React, Svelte, Solid, Vue — permanently, not just for now.**
  Decided 2026-08-08. Also no htmx, no esbuild islands, and no Node build step: `assets/*.js` is
  plain JavaScript served as written.
- **A second, HTML-returning API for the browse UI.** `/v1/` is the only API; the page fetches JSON
  from it. There is no `/f/` prefix.
- Real-time updates (SSE/WebSocket) — still out of scope per Krypton spec 212.
- Editing resources through the browse UI; Xenon remains a sink.
- Theming beyond the existing Binance-dark identity.

## Resources

- [axum-embed docs](https://docs.rs/axum-embed/latest/axum_embed/) — `ServeEmbed` + `rust-embed`,
  and the precompressed `br`/`gzip` serving that makes embedding cheap
- [axum-embed on crates.io](https://crates.io/crates/axum-embed) — current API surface
- [Hosting single-page applications in Rust](https://www.marending.dev/notes/rust-spa/) — the
  performance argument for embedding assets, and the binary-size caveat that bounds it
- [Building a fast website with the MASH stack in Rust](https://emschwartz.me/building-a-fast-website-with-the-mash-stack-in-rust/)
  — Axum + Maud + htmx in practice, and why the templating layer is where escaping is won
- [Back to the server with Rust, Axum, and htmx](https://joeymckenzie.tech/blog/back-to-the-server-with-rust-axum-and-htmx)
  — fragment-route shape and how it coexists with a versioned JSON API
- [htmx in 2026: when you don't need React (and when you absolutely do)](https://pockit.tools/blog/htmx-vs-react-2026-when-you-dont-need-spa/)
  — the internal-tools-vs-consumer-app dividing line this spec sits on
- In-tree: Krypton `src-tauri/src/hook_server.rs:6311` (`render_review_blocks`, the stage-1 port
  source) and `DESIGN.binance.md` (shared visual identity)
