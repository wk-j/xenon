// Xenon — the browser surface.
//
// Styling follows Krypton's DESIGN.binance.md so a resource looks identical
// whether it is read locally through Krypton's loopback surfaces or here, on
// the server. House rules that apply: data is mono / prose is sans, no nested
// cards, no left-accent rails, and paths keep their own case.

use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use rusqlite::{Connection, OptionalExtension};
use serde::Deserialize;
use std::sync::Arc;

use crate::api::{load_resource_detail, readable_project, RESOURCE_KINDS};
use crate::assets;
use crate::auth::{self, Actor};
use crate::error::{AppError, AppResult};
use crate::event;
use crate::state::AppState;

/// Rows per feed page. Enough to fill a screen, short enough that the "older"
/// link is reachable without a long scroll.
const FEED_PAGE: i64 = 40;

// ─── templates ──────────────────────────────────────────────────────────────
//
// HTML lives in `templates/*.html`, not in this file. askama compiles each one
// into a checked Rust struct, so a typo in a field name is a build error rather
// than a blank spot in a rendered page, and every `{{ … }}` is escaped by
// default. `escape()` survives only for the few places that still hand-build a
// string.

#[derive(askama::Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    crumbs: Vec<Crumb>,
    nav: Nav,
    projects: Vec<ProjectCard>,
}

/// One step of the breadcrumb. `href` is `None` for the current page — a link
/// to yourself looks live and goes nowhere.
#[derive(askama::Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    page_js_url: String,
    crumbs: Vec<Crumb>,
    nav: Nav,
}

#[derive(askama::Template)]
#[template(path = "register.html")]
struct RegisterTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    page_js_url: String,
    crumbs: Vec<Crumb>,
    nav: Nav,
}

#[derive(askama::Template)]
#[template(path = "tokens.html")]
struct TokensTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    page_js_url: String,
    crumbs: Vec<Crumb>,
    nav: Nav,
}

struct Crumb {
    label: String,
    href: Option<String>,
}

/// Who the chrome is being drawn for. Every page carries one, because the nav
/// is the part of the page that has to know: it was a static block that offered
/// "sign in" to a reader who was already signed in, and a `tokens` link that
/// only bounced an anonymous reader back to the login form.
struct Nav {
    signed_in: bool,
    /// Display name, falling back to the email. Empty when anonymous.
    who: String,
}

#[derive(askama::Template)]
#[template(path = "activity.html")]
struct ActivityTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    crumbs: Vec<Crumb>,
    nav: Nav,
    kinds: &'static [&'static str],
    kind_filter: Option<String>,
    project_filter: Option<String>,
    signed_in: bool,
    days: Vec<FeedDay>,
    /// Cursor for the next (older) page; `None` when this is the last one.
    older: Option<i64>,
    query_base: String,
}

/// One day heading and the rows under it. Grouping is done server-side because
/// the page has no JavaScript and the heading is part of the document.
struct FeedDay {
    label: String,
    rows: Vec<FeedRow>,
}

struct FeedRow {
    /// `resource.publish` → `publish`; drives the chip text.
    kind: String,
    /// The kind of *resource* for content rows, so the row can wear its hue.
    resource_kind: Option<String>,
    actor: String,
    verb: String,
    subject: String,
    href: Option<String>,
    project: Option<String>,
    when: String,
    exact: String,
}

#[derive(askama::Template)]
#[template(path = "project.html")]
struct ProjectTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    crumbs: Vec<Crumb>,
    nav: Nav,
    project: String,
    kinds: Vec<KindTab>,
    /// Sum over `kinds`, for the "all" chip.
    total: i64,
    kind_filter: Option<String>,
    resources: Vec<ResourceCard>,
}

/// One chip in the kind filter row, carrying how much it would show. The count
/// is over the whole project, not the current filter, so the row reads the same
/// no matter which chip is on — it is a table of contents, not a result count.
struct KindTab {
    name: &'static str,
    count: i64,
}

struct ResourceCard {
    kind: String,
    slug: String,
    title: String,
    revisions: i64,
    /// "3 h ago". The card used to print the raw epoch, which is not a time to
    /// anyone; the exact value rides along in a `title` attribute.
    updated: String,
    updated_exact: String,
}

#[derive(askama::Template)]
#[template(path = "resource.html")]
struct ResourceTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    crumbs: Vec<Crumb>,
    nav: Nav,
    byline: Option<Byline>,
    project: String,
    kind: String,
    slug: String,
    seq: i64,
    revisions: i64,
    pinned: bool,
    files: Vec<FileTab>,
    content: String,
}

struct FileTab {
    path: String,
    href: String,
    selected: bool,
}

/// Who uploaded the revision being read, in decreasing order of how much the
/// server can vouch for it. `who` and `token` are authenticated; `claimed` is
/// what the pushing client said about itself and is rendered as such — the
/// whole point of the split is that the page never presents an assertion with
/// the same weight as a verification.
struct Byline {
    who: String,
    token: Option<String>,
    token_revoked: bool,
    claimed: Option<String>,
}

struct ProjectCard {
    slug: String,
    is_public: bool,
    resource_count: i64,
}

// ─── LLM usage (Krypton spec 214) ───────────────────────────────────────────

#[derive(askama::Template)]
#[template(path = "usage.html")]
struct UsageTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    crumbs: Vec<Crumb>,
    nav: Nav,
    project: String,
    days: i64,
    ranges: &'static [RangeChoice],
    /// The only number the template branches on. Everything else it prints is
    /// already a string.
    turns: i64,
    /// Currency of every money column, named once in the headings so no cell
    /// has to carry a symbol.
    currency: String,
    total: UsageRow,
    sections: Vec<UsageSection>,
    /// The per-turn ledger. The aggregates say what a range cost; this says
    /// which turns it was made of, and is the only place the fields that
    /// cannot be summed (stop reason, origin, context level) are visible.
    recent: Vec<TurnLine>,
    /// True when `recent` is one page of a longer list — the page says so
    /// rather than implying these are all the turns there were.
    recent_truncated: bool,
    unpriced: Vec<String>,
}

/// A page of the ledger. Long enough to cover a working session, short enough
/// that the page stays one document rather than an endless scroll.
const RECENT_TURNS: i64 = 60;

struct RangeChoice {
    days: i64,
    label: &'static str,
}

const USAGE_RANGES: [RangeChoice; 4] = [
    RangeChoice {
        days: 1,
        label: "today",
    },
    RangeChoice {
        days: 7,
        label: "7 days",
    },
    RangeChoice {
        days: 30,
        label: "30 days",
    },
    RangeChoice {
        days: 0,
        label: "all",
    },
];

struct UsageSection {
    /// The column heading, which is also what the grouping means: `model`,
    /// `lane`, `backend`, `day`.
    group: &'static str,
    rows: Vec<UsageRow>,
}

/// One line of a usage table, entirely pre-formatted — including the em dash
/// for "nothing reported". The template does no arithmetic and makes no
/// rounding decision; a figure printed two different ways on one page is how a
/// report stops being trusted.
struct UsageRow {
    key: String,
    /// `Some("4 unreported")` when some turns in this row carried no counters.
    /// Named rather than folded into the count, because a turn nobody measured
    /// and a turn that cost nothing are not the same fact.
    unmeasured: Option<String>,
    turns: String,
    input: String,
    output: String,
    cached_read: String,
    cached_write: String,
    reported: String,
    estimated: String,
}

/// One turn in the ledger. Same rule as `UsageRow`: strings only.
struct TurnLine {
    when: String,
    lane: String,
    backend: String,
    model: String,
    /// False when Krypton recorded the *configured* model rather than one the
    /// agent confirmed. Shown, because an unconfirmed id is an intent and may
    /// not be what actually ran — silently printing it as fact would put a
    /// wrong model name next to a real charge.
    model_confirmed: bool,
    input: String,
    output: String,
    cached_read: String,
    /// Context window at the end of the turn, as a percentage. This is a level,
    /// not a spend, which is why it is never summed into a column above.
    context: String,
    duration: String,
    stop_reason: String,
    origin: String,
    /// The adapter's own figure, or an em dash. Never an estimate: an estimate
    /// is a property of a rate table applied to a whole bucket, and printing
    /// one per row would invite adding a column that must not be added.
    cost: String,
}

/// Digits in groups of three. The page's rule is exact figures over rounded
/// ones, and `4210331` is exact but unreadable — `4,210,331` is both.
fn group_digits(n: i64) -> String {
    let (sign, mut rest) = if n < 0 {
        ("-", n.unsigned_abs().to_string())
    } else {
        ("", n.to_string())
    };
    let mut out = String::with_capacity(rest.len() + rest.len() / 3 + 1);
    while rest.len() > 3 {
        let head = rest.split_off(rest.len() - 3);
        out.insert_str(0, &head);
        out.insert(0, ',');
    }
    out.insert_str(0, &rest);
    out.insert_str(0, sign);
    out
}

/// Four decimal places, everywhere, or an em dash. A per-turn charge is often
/// under a cent, and rounding it to two would print a stream of `0.00` next to
/// a total that is plainly not zero.
fn fmt_money(amount: Option<f64>) -> String {
    match amount {
        Some(a) => format!("{a:.4}"),
        None => "—".to_string(),
    }
}

/// A turn's wall time, at the precision a person compares turns with.
fn fmt_duration(ms: Option<i64>) -> String {
    match ms {
        Some(ms) if ms >= 60_000 => format!("{}m {:02}s", ms / 60_000, (ms % 60_000) / 1000),
        Some(ms) if ms >= 1_000 => format!("{:.1}s", ms as f64 / 1000.0),
        Some(ms) if ms >= 0 => format!("{ms}ms"),
        _ => "—".to_string(),
    }
}

/// How full the context window was when the turn ended. A percentage, because
/// the raw pair means nothing without the size beside it and the size is the
/// same for every turn of a session.
fn fmt_context(used: Option<i64>, size: Option<i64>) -> String {
    match (used, size) {
        (Some(used), Some(size)) if size > 0 => {
            format!("{}%", (used * 100).saturating_add(size / 2) / size)
        }
        _ => "—".to_string(),
    }
}

/// The bucket totals, formatted. `key` is whatever names the row — a model id,
/// a lane, or the range label on the summary line.
fn usage_row(key: String, totals: &crate::usage::UsageTotals) -> UsageRow {
    // When NO turn in the bucket carried counters, its token sums are zero by
    // construction — and printing `0` there says the bucket was free, which is
    // the one thing the whole design refuses to say. A lane whose adapter never
    // reports is unmeasured, not idle, so the cells go blank and the turn count
    // carries the fact instead.
    let measured = totals.turns_without_tokens < totals.turns;
    let tokens = |n: i64| {
        if measured {
            group_digits(n)
        } else {
            "—".to_string()
        }
    };
    UsageRow {
        key,
        unmeasured: match totals.turns_without_tokens {
            0 => None,
            n if n == totals.turns => Some("none reported".to_string()),
            n => Some(format!("{n} unreported")),
        },
        turns: group_digits(totals.turns),
        input: tokens(totals.input_tokens),
        output: tokens(totals.output_tokens),
        cached_read: tokens(totals.cached_read_tokens),
        cached_write: tokens(totals.cached_write_tokens),
        // A bucket where no adapter reported a cost prints a dash, not `0.0000`
        // — the same distinction the estimate column already makes.
        reported: fmt_money((totals.reported_cost_turns > 0).then_some(totals.reported_cost)),
        estimated: fmt_money(totals.estimated_cost),
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct UsageQuery {
    #[serde(default)]
    days: Option<i64>,
}

/// `GET /p/{project}/usage` — what a range cost, grouped four ways, over the
/// ledger of the turns it was made of.
///
/// Xenon does not push to browsers (SSE is out of scope in spec 212), so this
/// is current as of its last load. "Realtime" in spec 214 means Krypton→Xenon:
/// a turn is on the server within a second of ending, and a reload sees it.
async fn usage_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Query(query): Query<UsageQuery>,
) -> AppResult<Html<String>> {
    let (actor, nav) = viewer(&state, &headers);
    let conn = state.db();
    let project_id = readable_project(&conn, actor.as_ref(), &project)?;

    let days = query.days.unwrap_or(7).clamp(0, 3650);
    // `days = 0` is "everything"; any other value is a window ending now. The
    // bound is in epoch MILLISECONDS because that is the unit a turn carries.
    let from = if days == 0 {
        None
    } else {
        Some((crate::util::now() - days * 86_400) * 1000)
    };
    let range_label = USAGE_RANGES
        .iter()
        .find(|r| r.days == days)
        .map(|r| r.label.to_string())
        .unwrap_or_else(|| format!("{days} days"));

    // The four axes a spend question is ever asked along: which model ate the
    // budget, which lane is hot, which backend, and when. `backend` was already
    // a grouping the API served and the page did not offer, so the one question
    // a mixed fleet asks first — "is Codex or Claude costing me this?" — had no
    // answer in the browser.
    let mut sections = Vec::new();
    let mut unpriced = Vec::new();
    let mut totals = crate::usage::UsageTotals::default();
    for group in ["model", "lane", "backend", "day"] {
        let out = crate::usage::aggregate(
            &conn,
            &state.prices,
            &project,
            &project_id,
            &crate::usage::UsageQuery {
                from,
                to: None,
                group: Some(group.to_string()),
            },
        )?;
        // Every grouping sums the same rows, so the totals are identical; take
        // them (and the unpriced list) from the first pass only.
        if sections.is_empty() {
            totals = out.totals.clone();
            unpriced = out.unpriced.clone();
        }
        sections.push(UsageSection {
            group,
            rows: out
                .buckets
                .into_iter()
                .map(|b| {
                    let key = if b.key.is_empty() {
                        "(unreported)".to_string()
                    } else {
                        b.key
                    };
                    usage_row(key, &b.totals)
                })
                .collect(),
        });
    }

    // One row more than a page, so "there are older turns" is a fact rather
    // than a guess from a full page.
    let mut recent = crate::usage::recent_turns(&conn, &project_id, from, RECENT_TURNS + 1)?;
    let recent_truncated = recent.len() as i64 > RECENT_TURNS;
    recent.truncate(RECENT_TURNS as usize);

    let (title, css_url, app_js_url) = chrome(&format!("{project} usage"));
    render(&UsageTemplate {
        title,
        css_url,
        app_js_url,
        crumbs: vec![
            Crumb {
                label: "projects".to_string(),
                href: Some("/projects".to_string()),
            },
            Crumb {
                label: project.clone(),
                href: Some(format!("/p/{project}")),
            },
            Crumb {
                label: "usage".to_string(),
                href: None,
            },
        ],
        nav,
        project,
        days,
        turns: totals.turns,
        currency: totals.currency.clone(),
        // The summary line names the range it sums, so the table stands alone
        // if it is copied out of the page.
        total: usage_row(range_label, &totals),
        ranges: &USAGE_RANGES,
        sections,
        recent: recent
            .into_iter()
            .map(|t| TurnLine {
                when: crate::util::format_ymd_hms(t.at / 1000),
                lane: if t.lane.is_empty() {
                    "—".to_string()
                } else {
                    t.lane
                },
                backend: if t.backend.is_empty() {
                    "—".to_string()
                } else {
                    t.backend
                },
                model: t
                    .model
                    .filter(|m| !m.is_empty())
                    .unwrap_or_else(|| "—".to_string()),
                model_confirmed: t.model_confirmed,
                // An unmeasured turn shows a dash in all three token columns.
                // Zero would be a claim about spend that the adapter never
                // made, and would read as a free turn.
                input: if t.has_tokens {
                    group_digits(t.input)
                } else {
                    "—".to_string()
                },
                output: if t.has_tokens {
                    group_digits(t.output)
                } else {
                    "—".to_string()
                },
                cached_read: if t.has_tokens {
                    group_digits(t.cached_read + t.cached_write)
                } else {
                    "—".to_string()
                },
                context: fmt_context(t.context_used, t.context_size),
                duration: fmt_duration(t.duration_ms),
                stop_reason: if t.stop_reason.is_empty() {
                    "—".to_string()
                } else {
                    t.stop_reason
                },
                origin: t.origin,
                cost: fmt_money(t.cost_amount),
            })
            .collect(),
        recent_truncated,
        unpriced,
    })
}

/// The two asset URLs every page needs. Kept in one place so a template cannot
/// be added without them.
fn chrome(title: &str) -> (String, String, String) {
    (
        title.to_string(),
        assets::url("app.css"),
        assets::url("app.js"),
    )
}

fn render<T: askama::Template>(t: &T) -> AppResult<Html<String>> {
    t.render()
        .map(Html)
        .map_err(|e| AppError::internal(format!("render template: {e}")))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // The feed is the home page: opening xenon should answer "what has
        // happened" before "what exists". The project list is one click away and
        // is the same page it always was, now at its own URL.
        .route("/", get(activity_page))
        .route("/projects", get(index))
        // `/activity` was the feed's address for its whole life — in bookmarks,
        // in docs, and in every link already published. Redirect rather than
        // serve, so the feed has exactly one canonical URL and filter chips
        // cannot drift between two copies of the same page.
        .route("/activity", get(activity_moved))
        .route("/login", get(login_page))
        .route("/logout", post(logout))
        .route("/register", get(register_page))
        .route("/settings/tokens", get(tokens_page))
        .route("/p/{project}", get(project_page))
        .route("/p/{project}/usage", get(usage_page))
        .route("/r/{project}/{kind}/{*slug}", get(resource_page))
}

pub fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Authenticate once for both the page body and its chrome. One call, one lock:
/// `AppState::db()` is a plain mutex, so a second nested `db()` inside a handler
/// that already holds the guard would deadlock rather than fail.
fn viewer(state: &AppState, headers: &HeaderMap) -> (Option<Actor>, Nav) {
    let conn = state.db();
    let actor = auth::authenticate(&conn, headers).ok().flatten();
    // Only a session gets a signed-in nav. A bearer token is a machine
    // credential — there is no browser session behind it to sign out of, and it
    // reaches these pages only when someone is driving them with curl.
    let nav = match actor.as_ref().filter(|a| a.is_session()) {
        Some(actor) => Nav {
            signed_in: true,
            who: display_name(&conn, &actor.user_id),
        },
        None => Nav {
            signed_in: false,
            who: String::new(),
        },
    };
    (actor, nav)
}

/// The name to show in the nav. A missing row is not worth failing a page over:
/// the reader gets an unlabelled but otherwise correct signed-in nav.
fn display_name(conn: &Connection, user_id: &str) -> String {
    conn.query_row(
        "SELECT display_name, email FROM user WHERE id = ?1",
        [user_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )
    .optional()
    .ok()
    .flatten()
    .map(|(name, email)| if name.trim().is_empty() { email } else { name })
    .unwrap_or_default()
}

// ------------------------------------------------------------------- pages

async fn index(State(state): State<Arc<AppState>>, headers: HeaderMap) -> AppResult<Html<String>> {
    let (actor, nav) = viewer(&state, &headers);
    let conn = state.db();
    let mut stmt = conn.prepare(
        "SELECT p.slug, p.is_public, (SELECT count(*) FROM resource r WHERE r.project_id = p.id)
         FROM project p WHERE p.is_public = 1 OR p.owner_id = ?1 ORDER BY p.slug",
    )?;
    let owner = actor
        .as_ref()
        .map(|a| a.user_id.clone())
        .unwrap_or_default();
    let rows = stmt
        .query_map([owner], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)? != 0,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let (title, css_url, app_js_url) = chrome("projects");
    render(&IndexTemplate {
        title,
        css_url,
        app_js_url,
        crumbs: Vec::new(),
        nav,
        projects: rows
            .into_iter()
            .map(|(slug, is_public, resource_count)| ProjectCard {
                slug,
                is_public,
                resource_count,
            })
            .collect(),
    })
}

#[derive(Deserialize)]
pub struct ActivityPageQuery {
    project: Option<String>,
    kind: Option<String>,
    cursor: Option<i64>,
}

/// `/activity` → `/`, carrying the query string so a bookmarked filter or a
/// pasted "older" link lands where it meant to.
///
/// 303 rather than 301: a permanent redirect is cached by the browser until it
/// is cleared by hand, which would make putting the feed back at `/activity`
/// look broken on exactly the machines that had visited it.
async fn activity_moved(RawQuery(query): RawQuery) -> Redirect {
    match query.filter(|q| !q.is_empty()) {
        Some(q) => Redirect::to(&format!("/?{q}")),
        None => Redirect::to("/"),
    }
}

/// The feed, as a document. Reads through `event::query` so the page and
/// `/v1/activity` can never disagree about who may see what.
async fn activity_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ActivityPageQuery>,
) -> AppResult<Html<String>> {
    let (actor, nav) = viewer(&state, &headers);
    let kind_filter = query
        .kind
        .as_deref()
        .filter(|k| event::KINDS.contains(k))
        .map(str::to_string);
    let project_filter = query.project.clone().filter(|p| !p.is_empty());

    let conn = state.db();
    let events = event::query(
        &conn,
        actor.as_ref(),
        &event::Query {
            project: project_filter.as_deref(),
            kind: kind_filter.as_deref(),
            cursor: query.cursor,
            limit: FEED_PAGE,
        },
    )?;
    drop(conn);

    let older = (events.len() as i64 >= FEED_PAGE)
        .then(|| events.last().map(|e| e.seq))
        .flatten();

    let now = crate::util::now();
    let today = now.div_euclid(86_400);
    let mut days: Vec<FeedDay> = Vec::new();
    for e in &events {
        let day = e.created_at.div_euclid(86_400);
        let label = match today - day {
            0 => "today".to_string(),
            1 => "yesterday".to_string(),
            _ => crate::util::format_ymd(e.created_at),
        };
        let row = feed_row(e, now);
        match days.last_mut() {
            Some(last) if last.label == label => last.rows.push(row),
            _ => days.push(FeedDay {
                label,
                rows: vec![row],
            }),
        }
    }

    // Filters have to survive paging, so the "older" link rebuilds them.
    let mut query_base = String::new();
    if let Some(p) = &project_filter {
        query_base.push_str(&format!("project={}&", urlencode(p)));
    }
    if let Some(k) = &kind_filter {
        query_base.push_str(&format!("kind={}&", urlencode(k)));
    }

    let (title, css_url, app_js_url) = chrome("activity");
    render(&ActivityTemplate {
        title,
        css_url,
        app_js_url,
        crumbs: Vec::new(),
        signed_in: nav.signed_in,
        nav,
        kinds: &event::KINDS,
        kind_filter,
        project_filter,
        days,
        older,
        query_base,
    })
}

/// One event as a sentence: actor, verb, object. The verb is the only place the
/// eleven kinds differ, so it is the only thing that switches on kind.
fn feed_row(e: &event::EventView, now: i64) -> FeedRow {
    let (verb, resource_kind) = match e.kind.as_str() {
        event::RESOURCE_PUBLISH => ("published", detail_str(e, "kind")),
        event::RESOURCE_REVISE => ("revised", detail_str(e, "kind")),
        event::PROJECT_CREATE => ("created project", None),
        event::ACCOUNT_REGISTER => ("registered", None),
        event::ACCOUNT_LOGIN => ("signed in as", None),
        event::ACCOUNT_LOGIN_FAILED => ("failed to sign in as", None),
        event::ACCOUNT_LOGOUT => ("signed out of", None),
        event::TOKEN_CREATE => ("minted token", None),
        event::TOKEN_REVOKE => ("revoked token", None),
        event::INVITE_CREATE => ("created", None),
        event::INVITE_CLAIM => ("joined with an invite as", None),
        _ => ("did", None),
    };
    FeedRow {
        // A row about a resource is chipped with the *resource's* kind, the
        // same word and hue the project page uses — the verb beside it already
        // says whether this was a first publish or a revision. Everything else
        // is chipped with its event kind, minus the `account.` prefix: `login`
        // and `register` need no qualifier, while `token.create` and
        // `project.create` would both collapse to a bare `create` without one.
        kind: match &resource_kind {
            Some(kind) => kind.clone(),
            None => e
                .kind
                .strip_prefix("account.")
                .unwrap_or(&e.kind)
                .to_string(),
        },
        resource_kind,
        actor: e.actor.clone(),
        verb: verb.to_string(),
        subject: e.subject.clone(),
        href: e.url.clone(),
        project: e.project.clone(),
        when: crate::util::time_ago(e.created_at, now),
        exact: crate::util::format_ymd(e.created_at),
    }
}

fn detail_str(e: &event::EventView, key: &str) -> Option<String> {
    e.detail
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

#[derive(Deserialize)]
pub struct ProjectQuery {
    kind: Option<String>,
}

async fn project_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Query(query): Query<ProjectQuery>,
) -> AppResult<Html<String>> {
    let (actor, nav) = viewer(&state, &headers);
    let conn = state.db();
    let project_id = readable_project(&conn, actor.as_ref(), &project)?;

    let kind_filter = query.kind.as_deref().filter(|k| RESOURCE_KINDS.contains(k));

    // Counted separately from the listing below because the listing is filtered
    // and capped: the chips must report the project, not the page.
    let mut counts = std::collections::HashMap::<String, i64>::new();
    let mut count_stmt = conn.prepare(
        "SELECT kind, count(*) FROM resource
         WHERE project_id = ?1 AND head_revision IS NOT NULL
         GROUP BY kind",
    )?;
    for row in count_stmt.query_map(rusqlite::params![project_id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })? {
        let (kind, n) = row?;
        counts.insert(kind, n);
    }
    let kinds: Vec<KindTab> = RESOURCE_KINDS
        .iter()
        .map(|k| KindTab {
            name: k,
            count: counts.get(*k).copied().unwrap_or(0),
        })
        .collect();
    let total = kinds.iter().map(|k| k.count).sum();

    let mut stmt = conn.prepare(
        "SELECT kind, slug, title, updated_at,
                (SELECT count(*) FROM revision v
                 WHERE v.resource_id = resource.id AND v.sealed_at IS NOT NULL)
         FROM resource WHERE project_id = ?1 AND head_revision IS NOT NULL
           AND (?2 IS NULL OR kind = ?2)
         ORDER BY updated_at DESC LIMIT 500",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![project_id, kind_filter], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let now = crate::util::now();
    let (title, css_url, app_js_url) = chrome(&project);
    render(&ProjectTemplate {
        title,
        css_url,
        app_js_url,
        crumbs: vec![
            Crumb {
                label: "projects".to_string(),
                href: Some("/projects".to_string()),
            },
            Crumb {
                label: project.clone(),
                href: None,
            },
        ],
        nav,
        project: project.clone(),
        kinds,
        total,
        kind_filter: kind_filter.map(|k| k.to_string()),
        resources: rows
            .into_iter()
            .map(|(kind, slug, title, updated_at, revisions)| ResourceCard {
                kind,
                slug,
                title,
                revisions,
                updated: crate::util::time_ago(updated_at, now),
                updated_exact: crate::util::format_ymd(updated_at),
            })
            .collect(),
    })
}

#[derive(Deserialize)]
pub struct ResourceQuery {
    file: Option<String>,
}

async fn resource_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((project, kind, raw_slug)): Path<(String, String, String)>,
    Query(query): Query<ResourceQuery>,
) -> AppResult<Html<String>> {
    // `/r/<project>/<kind>/<slug>` and `/r/<project>/<kind>/<slug>/@<seq>` —
    // the pinned-revision permalink is a trailing segment so the slug itself
    // may still contain slashes (an analysis bundle is `owner/repo/number`).
    let (slug, seq) = match raw_slug.rsplit_once("/@") {
        Some((head, tail)) => match tail.parse::<i64>() {
            Ok(seq) => (head.to_string(), Some(seq)),
            Err(_) => (raw_slug.clone(), None),
        },
        None => (raw_slug.clone(), None),
    };

    let (actor, nav) = viewer(&state, &headers);
    let conn = state.db();
    let project_id = readable_project(&conn, actor.as_ref(), &project)?;

    let resource_id: String = conn
        .query_row(
            "SELECT id FROM resource WHERE project_id = ?1 AND kind = ?2 AND slug = ?3",
            rusqlite::params![project_id, kind, slug],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| AppError::not_found("no such resource"))?;

    let detail = load_resource_detail(&conn, actor.as_ref(), &resource_id, seq)?;
    drop(conn);

    let crumbs = vec![
        Crumb {
            label: "projects".to_string(),
            href: Some("/projects".to_string()),
        },
        Crumb {
            label: project.clone(),
            href: Some(format!("/p/{}", urlencode(&project))),
        },
        Crumb {
            label: detail.summary.title.clone(),
            href: None,
        },
    ];
    let (title, css_url, app_js_url) = chrome(&detail.summary.title);

    let Some(revision) = detail.revision else {
        return render(&ResourceTemplate {
            title,
            css_url,
            app_js_url,
            crumbs,
            nav,
            byline: None,
            project,
            kind: detail.summary.kind,
            slug: detail.summary.slug,
            seq: 0,
            revisions: 0,
            pinned: false,
            files: Vec::new(),
            content: "<p class=\"empty\">no committed revision</p>".to_string(),
        });
    };

    let selected = query
        .file
        .as_deref()
        .and_then(|want| revision.files.iter().find(|f| f.path == want))
        .or_else(|| revision.files.first());

    // A resource with no files is not an empty resource. `attention` has no
    // on-disk form at all — its question, the option the lane chose, and the
    // rationale all live in the revision's `meta` — so a file-only renderer
    // showed such a resource as a title over "this revision has no files",
    // withholding the entire payload from the reader. Files still win when
    // there are any; meta is what fills the page when there are none.
    let content = match selected {
        Some(file) => render_file(&state, &revision.id, &file.path, &file.content_type)?,
        None => {
            crate::meta::render_meta(&detail.summary.kind, &revision.meta, &detail.summary.title)
                .unwrap_or_else(|| "<p class=\"empty\">this revision has no files</p>".to_string())
        }
    };

    let files = revision
        .files
        .iter()
        .map(|f| FileTab {
            path: f.path.clone(),
            href: urlencode(&f.path),
            selected: selected.is_some_and(|s| s.path == f.path),
        })
        .collect();

    render(&ResourceTemplate {
        title,
        css_url,
        app_js_url,
        crumbs,
        nav,
        byline: byline_for(&revision),
        project,
        kind: detail.summary.kind,
        slug: detail.summary.slug,
        seq: revision.seq,
        revisions: detail.summary.revisions,
        pinned: seq.is_some(),
        files,
        content,
    })
}

/// Build the byline for a revision, keeping the verified and the claimed halves
/// apart. `meta.lane` and `origin.hostname` both come from the pushing client,
/// so they are folded into one muted "claimed" phrase rather than sitting
/// beside the account as if the server had checked them.
fn byline_for(revision: &crate::api::RevisionDetail) -> Option<Byline> {
    let author = revision.author.as_ref();
    let lane = revision
        .meta
        .get("lane")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty());
    let host = revision
        .origin
        .get("hostname")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty());
    let claimed = match (lane, host) {
        (Some(lane), Some(host)) => Some(format!("{lane} from {host}")),
        (Some(lane), None) => Some(lane.to_string()),
        (None, Some(host)) => Some(format!("from {host}")),
        (None, None) => None,
    };

    // An item whose account was deleted still says so, rather than quietly
    // looking like nobody ever uploaded it.
    let who = author
        .map(|a| a.name.clone())
        .unwrap_or_else(|| "(deleted account)".to_string());

    if author.is_none() && claimed.is_none() {
        return None;
    }
    Some(Byline {
        who,
        token: author.and_then(|a| a.token_label.clone()),
        token_revoked: author.is_some_and(|a| a.token_revoked),
        claimed,
    })
}

fn render_file(
    state: &AppState,
    revision_id: &str,
    path: &str,
    content_type: &str,
) -> AppResult<String> {
    let src = format!("/v1/revisions/{}/files/{}", revision_id, urlencode(path));

    // An HTML artifact opens in its own tab rather than being embedded. It is a
    // complete page, and nesting one page inside another only produced chrome
    // inside chrome and a frame whose height this page could not know. Isolation
    // is carried by the CSP `sandbox` header on the file route (see api.rs
    // `get_file`), so the artifact still cannot reach this origin's cookies.
    if content_type.contains("html") || path.ends_with(".html") {
        return Ok(format!(
            "<p class=\"artifact-open\"><a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">open artifact \u{2197}</a></p>\
             <p class=\"meta\">opens in a new tab, sandboxed — it cannot read your session</p>",
            escape(&src)
        ));
    }
    if content_type.starts_with("image/") {
        return Ok(format!(
            "<p><img src=\"{}\" alt=\"{}\"></p>",
            escape(&src),
            escape(path)
        ));
    }
    if path.ends_with(".md") || content_type.contains("markdown") {
        let Some((sha, _)) = file_blob(state, revision_id, path)? else {
            return Ok("<p class=\"empty\">file not found</p>".to_string());
        };
        let bytes = state.blobs.read(&sha)?;
        let text = String::from_utf8_lossy(&bytes);
        // A Review Board / analysis carries typed fences (```review:finding …)
        // that comrak renders as anonymous grey code blocks. The post-pass turns
        // the ones we know into semantic markup and leaves the rest alone, so a
        // Board read here shows what it shows inside Krypton.
        return Ok(format!(
            "<article class=\"doc\">{}</article>",
            crate::render::render_review_blocks(&markdown_to_html(&text))
        ));
    }
    // Anything else that is text — JSON evidence, a log, a config, a source
    // file — is laid out in place. It used to fall straight through to the
    // download link below, so the one file a reviewer opened the page to read
    // was the one file the page refused to show.
    if let Some(lang) = text_language(content_type, path) {
        let Some((sha, size)) = file_blob(state, revision_id, path)? else {
            return Ok("<p class=\"empty\">file not found</p>".to_string());
        };
        if size > INLINE_TEXT_LIMIT {
            return Ok(download_only(
                &src,
                path,
                Some(&format!(
                    "{} — too large to lay out here",
                    human_size(size as u64)
                )),
            ));
        }
        let bytes = state.blobs.read(&sha)?;
        // The content type is whatever the pushing client declared, and it
        // defaults to application/octet-stream, so neither it nor the extension
        // is proof of anything. The bytes decide: only a clean UTF-8 decode with
        // no NUL in it is shown as text, and everything else stays a download
        // rather than becoming a page full of replacement characters.
        match String::from_utf8(bytes) {
            Ok(text) if !text.contains('\0') => {
                return Ok(render_text_file(&text, lang, path, &src));
            }
            _ => {
                return Ok(download_only(&src, path, Some("not text after all")));
            }
        }
    }

    Ok(download_only(&src, path, None))
}

/// Largest text body laid out on the page. Above this the file stays a download
/// link: the body is escaped and split into one element per line, so a
/// multi-megabyte log would cost more DOM than any reader gets value from, and
/// nothing above the fold reads better for having 40k siblings below it.
const INLINE_TEXT_LIMIT: i64 = 512 * 1024;

fn download_only(src: &str, path: &str, note: Option<&str>) -> String {
    let note = match note {
        Some(note) => format!(" · {}", escape(note)),
        None => String::new(),
    };
    format!(
        "<p class=\"meta\"><a href=\"{}\">download {}</a>{}</p>",
        escape(src),
        escape(path),
        note
    )
}

/// Digest and byte size of one file in a revision, without reading the body —
/// so an oversized file is turned away before it is pulled into memory.
fn file_blob(state: &AppState, revision_id: &str, path: &str) -> AppResult<Option<(String, i64)>> {
    let conn = state.db();
    let row = conn
        .query_row(
            "SELECT sha256, size FROM rev_file WHERE revision_id = ?1 AND path = ?2",
            rusqlite::params![revision_id, path],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(row)
}

/// The language label for a file that should be read as text, or `None` for one
/// that should not.
///
/// The path is consulted before the declared content type on purpose: a client
/// that says nothing gets `application/octet-stream` by default, and that
/// default is what sent every `.json` to the download link. An extension we
/// recognise is the stronger signal of the two; the content type is the
/// fallback for a file that has no extension worth reading.
fn text_language(content_type: &str, path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let ext = match name.rsplit_once('.') {
        // A leading dot is the whole name (`.gitignore`), not an extension.
        Some((stem, ext)) if !stem.is_empty() => ext.to_ascii_lowercase(),
        _ => String::new(),
    };
    let by_ext = match ext.as_str() {
        "json" | "jsonl" | "ndjson" | "jsonc" | "map" => Some("json"),
        "yaml" | "yml" => Some("yaml"),
        "toml" => Some("toml"),
        "xml" | "xsd" | "xsl" | "plist" => Some("xml"),
        "csv" => Some("csv"),
        "tsv" => Some("tsv"),
        "txt" | "text" | "log" | "out" | "err" | "lock" | "license" => Some("text"),
        "ini" | "cfg" | "conf" | "properties" | "env" | "editorconfig" => Some("ini"),
        "sh" | "bash" | "zsh" | "fish" | "bat" | "cmd" | "ps1" => Some("shell"),
        "sql" => Some("sql"),
        "diff" | "patch" => Some("diff"),
        "rs" => Some("rust"),
        "go" => Some("go"),
        "py" => Some("python"),
        "rb" => Some("ruby"),
        "java" => Some("java"),
        "kt" | "kts" => Some("kotlin"),
        "ts" | "tsx" => Some("typescript"),
        "js" | "mjs" | "cjs" | "jsx" => Some("javascript"),
        "css" | "scss" | "less" => Some("css"),
        "c" | "h" => Some("c"),
        "cc" | "cpp" | "cxx" | "hpp" => Some("cpp"),
        "cs" => Some("csharp"),
        "php" => Some("php"),
        "swift" => Some("swift"),
        "hurl" => Some("text"),
        _ => None,
    };
    if by_ext.is_some() {
        return by_ext;
    }
    // Files whose whole name is the type.
    let by_name = match name.to_ascii_lowercase().as_str() {
        "dockerfile" | "containerfile" => Some("dockerfile"),
        "makefile" | "justfile" => Some("makefile"),
        "readme" | "license" | "licence" | "notice" | "changelog" | "authors" => Some("text"),
        ".gitignore" | ".dockerignore" | ".gitattributes" | ".env" | ".editorconfig" => {
            Some("text")
        }
        _ => None,
    };
    if by_name.is_some() {
        return by_name;
    }
    let ct = content_type.to_ascii_lowercase();
    let ct = ct.split(';').next().unwrap_or("").trim();
    if ct.starts_with("text/") {
        return Some("text");
    }
    // `application/vnd.foo+json`, `application/yaml`, and friends.
    match ct {
        _ if ct.contains("json") => Some("json"),
        _ if ct.contains("yaml") => Some("yaml"),
        _ if ct.contains("xml") => Some("xml"),
        _ if ct.contains("javascript") => Some("javascript"),
        _ if ct.contains("toml") => Some("toml"),
        _ if ct.contains("x-sh") || ct.contains("shellscript") => Some("shell"),
        _ => None,
    }
}

/// Lay out a text file: a header line naming it, then the body, one element per
/// line so the gutter number can live in `::before` — generated content is not
/// picked up when the block is selected, so copying gives back the file and not
/// the numbering. Same trick `pre.rv-diff` already uses.
///
/// The body is shown byte-for-byte. It is evidence as often as it is source, so
/// nothing here re-indents it or pretty-prints JSON: what the page shows is what
/// the download gives you.
fn render_text_file(text: &str, lang: &str, path: &str, src: &str) -> String {
    // A file ends with a newline; that terminator is not an extra empty line.
    let body_text = text.strip_suffix('\n').unwrap_or(text);
    let body_text = body_text.strip_suffix('\r').unwrap_or(body_text);

    let mut lines = 0usize;
    let mut body = String::with_capacity(text.len() + text.len() / 4 + 128);
    for line in body_text.split('\n') {
        lines += 1;
        body.push_str("<span>");
        body.push_str(&escape(line.strip_suffix('\r').unwrap_or(line)));
        body.push_str("</span>");
    }

    format!(
        "<div class=\"filetext\">\
           <p class=\"filetext__bar\">\
             <span class=\"filetext__path\">{path}</span>\
             <span class=\"filetext__lang\">{lang}</span>\
             <span class=\"filetext__size\">{lines} {noun} · {size}</span>\
             <a href=\"{src}\">download</a>\
           </p>\
           <pre class=\"filetext__body\"><code class=\"language-{lang}\">{body}</code></pre>\
         </div>",
        path = escape(path),
        lang = escape(lang),
        lines = lines,
        noun = if lines == 1 { "line" } else { "lines" },
        size = escape(&human_size(text.len() as u64)),
        src = escape(src),
        body = body
    )
}

fn human_size(bytes: u64) -> String {
    match bytes {
        b if b < 1024 => format!("{b} B"),
        b if b < 1024 * 1024 => format!("{:.1} KB", b as f64 / 1024.0),
        b => format!("{:.1} MB", b as f64 / (1024.0 * 1024.0)),
    }
}

/// Renders markdown with raw HTML disabled. Bundle text is agent-authored and
/// therefore untrusted; comrak's `unsafe_` option stays off so an embedded
/// `<script>` renders as text instead of executing on this origin.
pub fn markdown_to_html(source: &str) -> String {
    let mut options = comrak::Options::default();
    options.extension.table = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    options.extension.front_matter_delimiter = Some("---".to_string());
    options.render.r#unsafe = false;
    comrak::markdown_to_html(source, &options)
}

fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// ------------------------------------------------------------- auth screens

async fn login_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> AppResult<Html<String>> {
    let (_, nav) = viewer(&state, &headers);
    let (title, css_url, app_js_url) = chrome("sign in");
    render(&LoginTemplate {
        title,
        css_url,
        app_js_url,
        page_js_url: assets::url("login.js"),
        crumbs: Vec::new(),
        nav,
    })
}

async fn register_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> AppResult<Html<String>> {
    let (_, nav) = viewer(&state, &headers);
    let (title, css_url, app_js_url) = chrome("register");
    render(&RegisterTemplate {
        title,
        css_url,
        app_js_url,
        page_js_url: assets::url("register.js"),
        crumbs: Vec::new(),
        nav,
    })
}

async fn tokens_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let (actor, nav) = viewer(&state, &headers);
    // The page is a shell that `tokens.js` fills from `/v1/tokens`; without a
    // session that fetch 401s and the script sends the reader here anyway.
    // Deciding it server-side means no empty token table flashes first, and it
    // matches every other private page on this surface.
    if !actor.is_some_and(|a| a.is_session()) {
        return Ok(redirect_to_login());
    }
    let (title, css_url, app_js_url) = chrome("tokens");
    Ok(render(&TokensTemplate {
        title,
        css_url,
        app_js_url,
        page_js_url: assets::url("tokens.js"),
        crumbs: Vec::new(),
        nav,
    })?
    .into_response())
}

/// Sign-out for the browser. `POST /v1/auth/logout` answers JSON, which is right
/// for a client and wrong for a nav control: posting the form there would leave
/// the reader looking at `{"ok":true}`. This ends the same session and sends
/// them back to the project list.
///
/// It is a POST, not a link: `SameSite=Lax` withholds the session cookie from a
/// cross-site POST, so a hostile page cannot sign someone out by embedding an
/// image or a redirect.
async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> AppResult<Response> {
    {
        let conn = state.db();
        auth::end_session(&conn, &headers)?;
    }
    Ok((
        StatusCode::SEE_OTHER,
        [
            (
                header::SET_COOKIE,
                auth::clear_session_cookie(state.config.insecure_cookies),
            ),
            (header::LOCATION, "/".to_string()),
        ],
        (),
    )
        .into_response())
}

/// Web pages answer an unauthenticated read with a redirect to sign-in rather
/// than a JSON error, so a bookmarked private URL lands somewhere useful.
pub fn redirect_to_login() -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, "/login")], ()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_neutralises_html() {
        assert_eq!(
            escape("<script>x</script>"),
            "&lt;script&gt;x&lt;/script&gt;"
        );
        assert_eq!(escape("a & b"), "a &amp; b");
        assert_eq!(escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn markdown_does_not_pass_through_raw_html() {
        let rendered = markdown_to_html("# hi\n\n<script>alert(1)</script>\n");
        assert!(rendered.contains("<h1>"));
        assert!(
            !rendered.contains("<script>"),
            "raw html must not survive rendering: {rendered}"
        );
    }

    #[test]
    fn markdown_renders_tables() {
        let rendered = markdown_to_html("| a | b |\n|---|---|\n| 1 | 2 |\n");
        assert!(
            rendered.contains("<table>"),
            "table extension should be on: {rendered}"
        );
    }

    #[test]
    fn extension_beats_the_declared_content_type() {
        // The default type for a pushed file is application/octet-stream, and
        // trusting it is exactly what used to send every .json to a download
        // link instead of the page.
        assert_eq!(
            text_language("application/octet-stream", "evidence-node.json"),
            Some("json")
        );
        assert_eq!(
            text_language("application/octet-stream", "run.log"),
            Some("text")
        );
        assert_eq!(
            text_language("application/octet-stream", "Dockerfile"),
            Some("dockerfile")
        );
        assert_eq!(text_language("text/plain", "notes"), Some("text"));
        assert_eq!(
            text_language("application/vnd.api+json", "payload"),
            Some("json")
        );
    }

    #[test]
    fn binary_files_stay_a_download() {
        assert_eq!(text_language("application/pdf", "report.pdf"), None);
        assert_eq!(text_language("application/octet-stream", "trace.bin"), None);
        assert_eq!(text_language("application/zip", "bundle.zip"), None);
    }

    #[test]
    fn text_file_is_escaped_one_span_per_line() {
        let html = render_text_file("{\"a\": \"<script>\"}\nsecond\n", "json", "e.json", "/f");
        assert!(
            !html.contains("<script>"),
            "file bytes must not reach the page as markup: {html}"
        );
        assert!(html.contains("&lt;script&gt;"));
        // Two lines, not three: the terminating newline is not a line of its own.
        assert_eq!(html.matches("<span>").count(), 2);
        assert!(html.contains("2 lines"));
    }

    #[test]
    fn crlf_does_not_leave_a_stray_carriage_return() {
        let html = render_text_file("a\r\nb\r\n", "text", "a.txt", "/f");
        assert_eq!(html.matches("<span>").count(), 2);
        assert!(!html.contains('\r'));
    }

    #[test]
    fn human_size_reads_at_a_glance() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KB");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0 MB");
    }

    #[test]
    fn urlencode_keeps_paths_readable_but_escapes_specials() {
        assert_eq!(urlencode("assets/diagram.png"), "assets/diagram.png");
        assert_eq!(urlencode("a b.md"), "a%20b.md");
        assert_eq!(urlencode("q?x=1"), "q%3Fx%3D1");
    }
}
