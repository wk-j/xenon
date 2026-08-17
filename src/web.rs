// Xenon — the browser surface.
//
// Styling follows Krypton's DESIGN.binance.md so a resource looks identical
// whether it is read locally through Krypton's loopback surfaces or here, on
// the server. House rules that apply: data is mono / prose is sans, no nested
// cards, no left-accent rails, and paths keep their own case.

use axum::extract::{Form, Path, Query, RawQuery, State};
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
/// Browse-only: `?kind=all` is the unfiltered feed. A missing `kind` now
/// means the default chip (`resource.publish`), so the unfiltered view
/// has to name itself or paging would snap back to the default.
const FEED_KIND_ALL: &str = "all";

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

#[derive(askama::Template)]
#[template(path = "admin.html")]
struct AdminTemplate {
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
    /// The admin link is instance-wide; only the first account sees it.
    is_admin: bool,
    /// Dark or light. A browser cookie, not an account field: the same person
    /// can prefer light on a desk and dark on a phone, and the login screen
    /// has to honour it before anyone is signed in.
    theme: Theme,
    /// Cards or rows, for the pages that list items. A browser cookie for the
    /// same reason the theme is one: it is how this screen is being read, not
    /// a fact about the account, and it is chosen on one list page for all of
    /// them.
    view: View,
    /// Path and query of the page being drawn. The theme form posts it back
    /// as `next` because every page sends `Referrer-Policy: no-referrer`, so
    /// the browser will not tell us where to return on its own.
    here: String,
}

impl Nav {
    /// Path only, so a filtered feed (`/?kind=`) still counts as the feed.
    fn path(&self) -> &str {
        self.here
            .split_once('?')
            .map(|(p, _)| p)
            .unwrap_or(self.here.as_str())
    }

    fn on_activity(&self) -> bool {
        self.path() == "/"
    }

    /// The project list and everything under a project — resources, usage,
    /// a single resource — are the same destination in the chrome.
    fn on_projects(&self) -> bool {
        let p = self.path();
        p == "/projects" || p.starts_with("/p/") || p.starts_with("/r/")
    }

    fn on_tokens(&self) -> bool {
        self.path() == "/settings/tokens"
    }

    fn on_admin(&self) -> bool {
        self.path() == "/admin"
    }

    fn on_login(&self) -> bool {
        self.path() == "/login" || self.path() == "/register"
    }
}

/// The two modes the browse UI can paint. Anything else in the cookie is
/// treated as dark, which is the identity the pages were designed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Theme {
    Dark,
    Light,
}

const THEME_COOKIE: &str = "xenon_theme";
const VIEW_COOKIE: &str = "xenon_view";
/// How long a chrome preference (theme, view mode) rides on this browser.
const PREF_TTL_SECS: i64 = 60 * 60 * 24 * 365;

impl Theme {
    fn from_cookie(raw: Option<&str>) -> Self {
        match raw {
            Some("light") => Self::Light,
            _ => Self::Dark,
        }
    }

    fn from_headers(headers: &HeaderMap) -> Self {
        Self::from_cookie(auth::read_cookie(headers, THEME_COOKIE).as_deref())
    }

    /// A form post names a mode. Unknown values are refused rather than
    /// silently becoming dark, so a typo does not overwrite a real choice.
    fn from_form(raw: &str) -> Option<Self> {
        match raw {
            "dark" => Some(Self::Dark),
            "light" => Some(Self::Light),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::Light => "light",
        }
    }

    fn is_dark(&self) -> bool {
        matches!(self, Self::Dark)
    }

    /// The mode a click will switch to. The chrome is one button, not two
    /// named ones, so the posted value has to be the other mode.
    fn other(self) -> Self {
        match self {
            Self::Dark => Self::Light,
            Self::Light => Self::Dark,
        }
    }

    /// What the control does, not what the page currently is — a toggle
    /// that announced "dark" while already dark would read as a status.
    fn toggle_label(self) -> &'static str {
        match self {
            Self::Dark => "use light theme",
            Self::Light => "use dark theme",
        }
    }
}

impl std::fmt::Display for Theme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Deserialize)]
struct ThemeForm {
    theme: String,
    next: Option<String>,
}

/// How a page that lists items lays them out. Cards is the default because it
/// is the shape both list pages were designed in; list trades the boxes for
/// rows, which fits far more of a long project on one screen.
///
/// Both modes render the SAME markup — only the layout class on the container
/// changes — so the switch can never alter what a page says, and a field added
/// to a card cannot go missing from a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    Card,
    List,
}

impl View {
    fn from_cookie(raw: Option<&str>) -> Self {
        match raw {
            Some("list") => Self::List,
            _ => Self::Card,
        }
    }

    fn from_headers(headers: &HeaderMap) -> Self {
        Self::from_cookie(auth::read_cookie(headers, VIEW_COOKIE).as_deref())
    }

    /// Unknown values are refused rather than silently becoming cards, so a
    /// typo does not overwrite a real choice — same rule as the theme form.
    fn from_form(raw: &str) -> Option<Self> {
        match raw {
            "card" => Some(Self::Card),
            "list" => Some(Self::List),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Card => "card",
            Self::List => "list",
        }
    }

    fn is_card(&self) -> bool {
        matches!(self, Self::Card)
    }

    fn is_list(&self) -> bool {
        matches!(self, Self::List)
    }
}

#[derive(Deserialize)]
struct ViewForm {
    view: String,
    next: Option<String>,
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
    days: Vec<FeedDay>,
    /// Cursor for the next (older) page; `None` when this is the last one.
    older: Option<i64>,
    query_base: String,
    /// Path the pager and (on the project feed) the kind chips address.
    feed_path: String,
    /// The fleet feed names the project on each row; a project's own feed
    /// does not — the reader is already there.
    show_project: bool,
}

#[derive(askama::Template)]
#[template(path = "project_activity.html")]
struct ProjectActivityTemplate {
    title: String,
    css_url: String,
    app_js_url: String,
    crumbs: Vec<Crumb>,
    nav: Nav,
    project: String,
    initial: String,
    hue: u16,
    github_repo: Option<String>,
    tab: &'static str,
    kinds: &'static [&'static str],
    kind_filter: Option<String>,
    days: Vec<FeedDay>,
    older: Option<i64>,
    query_base: String,
    feed_path: String,
    show_project: bool,
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
    /// The monogram "logo" beside the project name.
    initial: String,
    hue: u16,
    /// `owner/repo` when the project is linked to GitHub.
    github_repo: Option<String>,
    /// Which of the project's pages this is, for the tab row.
    tab: &'static str,
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
    page_js_url: String,
    crumbs: Vec<Crumb>,
    nav: Nav,
    byline: Option<Byline>,
    project: String,
    kind: String,
    slug: String,
    /// Opaque id, for the admin remove button. Not shown.
    resource_id: String,
    seq: i64,
    revisions: i64,
    pinned: bool,
    files: Vec<FileTab>,
    content: String,
    /// External destinations mentioned in `content`, for the references
    /// section. Empty renders no section.
    references: Vec<RefItem>,
    /// Cited work gathered so the reader can open the next thing without
    /// hunting the project. Empty when the body names nothing we can resolve.
    followups: Vec<FollowItem>,
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
    /// The monogram "logo": see `logo_initial` / `logo_hue`.
    initial: String,
    hue: u16,
}

/// The letter a project wears as its logo: the first alphanumeric character of
/// the slug, uppercased. `#` for a slug with none, so the tile never renders
/// blank.
fn logo_initial(name: &str) -> String {
    name.chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "#".to_string())
}

/// The logo's hue, hashed (FNV-1a) from the whole slug — not just the initial,
/// so `krypton` and `kappa` don't wear the same colour. Derived rather than
/// stored: the same name gets the same face on every page and every restart.
fn logo_hue(name: &str) -> u16 {
    let mut h: u32 = 0x811c_9dc5;
    for b in name.as_bytes() {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x0100_0193);
    }
    (h % 360) as u16
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
    /// The monogram "logo" beside the project name.
    initial: String,
    hue: u16,
    /// Which of the project's pages this is, for the tab row.
    tab: &'static str,
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
    uri: axum::http::Uri,
    Path(project): Path<String>,
    Query(query): Query<UsageQuery>,
) -> AppResult<Response> {
    let (actor, nav) = viewer(&state, &headers, &uri);
    if !has_browser_session(&actor) {
        return Ok(redirect_to_login());
    }
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
    Ok(render(&UsageTemplate {
        title,
        css_url,
        app_js_url,
        crumbs: project_crumbs(&project, Some("usage")),
        nav,
        initial: logo_initial(&project),
        hue: logo_hue(&project),
        project,
        tab: "usage",
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
    })?
    .into_response())
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
        .route("/theme", post(set_theme))
        .route("/view", post(set_view))
        .route("/register", get(register_page))
        .route("/settings/tokens", get(tokens_page))
        .route("/admin", get(admin_page))
        .route("/p/{project}", get(project_page))
        .route("/p/{project}/resources", get(project_resources_page))
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
fn viewer(state: &AppState, headers: &HeaderMap, uri: &axum::http::Uri) -> (Option<Actor>, Nav) {
    let conn = state.db();
    let actor = auth::authenticate(&conn, headers).ok().flatten();
    let theme = Theme::from_headers(headers);
    let view = View::from_headers(headers);
    let here = match uri.query() {
        Some(q) => format!("{}?{q}", uri.path()),
        None => uri.path().to_string(),
    };
    // Only a session gets a signed-in nav. A bearer token is a machine
    // credential — there is no browser session behind it to sign out of, and it
    // reaches these pages only when someone is driving them with curl.
    let nav = match actor.as_ref().filter(|a| a.is_session()) {
        Some(actor) => Nav {
            signed_in: true,
            who: display_name(&conn, &actor.user_id),
            is_admin: actor.is_admin,
            theme,
            view,
            here,
        },
        None => Nav {
            signed_in: false,
            who: String::new(),
            is_admin: false,
            theme,
            view,
            here,
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

async fn index(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> AppResult<Response> {
    let (actor, nav) = viewer(&state, &headers, &uri);
    if !has_browser_session(&actor) {
        return Ok(redirect_to_login());
    }
    let conn = state.db();
    // Most recently touched project first. A project has no updated_at of its
    // own, so the latest resource update stands in for it; a project with no
    // resources yet falls back to its creation time rather than sinking to the
    // bottom of the list.
    let mut stmt = conn.prepare(
        "SELECT p.slug, p.is_public, (SELECT count(*) FROM resource r WHERE r.project_id = p.id)
         FROM project p WHERE p.is_public = 1 OR p.owner_id = ?1
         ORDER BY coalesce(
             (SELECT max(r.updated_at) FROM resource r WHERE r.project_id = p.id),
             p.created_at) DESC, p.slug",
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
    Ok(render(&IndexTemplate {
        title,
        css_url,
        app_js_url,
        crumbs: Vec::new(),
        nav,
        projects: rows
            .into_iter()
            .map(|(slug, is_public, resource_count)| ProjectCard {
                initial: logo_initial(&slug),
                hue: logo_hue(&slug),
                slug,
                is_public,
                resource_count,
            })
            .collect(),
    })?
    .into_response())
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
    uri: axum::http::Uri,
    Query(query): Query<ActivityPageQuery>,
) -> AppResult<Response> {
    let (actor, nav) = viewer(&state, &headers, &uri);
    if !has_browser_session(&actor) {
        return Ok(redirect_to_login());
    }
    let kind_filter = browse_kind_filter(query.kind.as_deref(), &event::KINDS);
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

    let (days, older) = group_feed(&events);
    // Filters have to survive paging, so the "older" link rebuilds them.
    // The kind is always named: a missing one would be read as the default
    // chip, which is wrong for `?kind=all`.
    let query_base = feed_query_base(
        project_filter.as_deref(),
        Some(kind_filter.as_deref().unwrap_or(FEED_KIND_ALL)),
    );

    let (title, css_url, app_js_url) = chrome("activity");
    Ok(render(&ActivityTemplate {
        title,
        css_url,
        app_js_url,
        crumbs: Vec::new(),
        nav,
        kinds: &event::KINDS,
        kind_filter,
        project_filter,
        days,
        older,
        query_base,
        feed_path: "/".to_string(),
        show_project: true,
    })?
    .into_response())
}

/// Day groups and the "older" cursor, shared by the fleet feed and a project's
/// own feed so the two pages cannot disagree about where a day starts.
fn group_feed(events: &[event::EventView]) -> (Vec<FeedDay>, Option<i64>) {
    let older = (events.len() as i64 >= FEED_PAGE)
        .then(|| events.last().map(|e| e.seq))
        .flatten();
    let now = crate::util::now();
    let today = now.div_euclid(86_400);
    let mut days: Vec<FeedDay> = Vec::new();
    for e in events {
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
    (days, older)
}

fn feed_query_base(project: Option<&str>, kind: Option<&str>) -> String {
    let mut query_base = String::new();
    if let Some(p) = project {
        query_base.push_str(&format!("project={}&", urlencode(p)));
    }
    if let Some(k) = kind {
        query_base.push_str(&format!("kind={}&", urlencode(k)));
    }
    query_base
}

/// Which event kind the browse feed is narrowed to.
///
/// A missing `?kind=` is `resource.publish`, not "everything": the home
/// page answers what was published. `?kind=all` is the unfiltered log —
/// it has to be named because a missing param now means the default chip.
/// An unknown value falls back to the default rather than silently
/// becoming the full log.
fn browse_kind_filter(raw: Option<&str>, allowed: &[&str]) -> Option<String> {
    match raw {
        Some(FEED_KIND_ALL) => None,
        Some(k) if allowed.contains(&k) => Some(k.to_string()),
        _ => Some(event::RESOURCE_PUBLISH.to_string()),
    }
}

/// Breadcrumb trail under a project. The project itself is the last crumb on
/// its home page (activity); a deeper page links back to that home.
fn project_crumbs(project: &str, here: Option<&str>) -> Vec<Crumb> {
    let mut crumbs = vec![Crumb {
        label: "projects".to_string(),
        href: Some("/projects".to_string()),
    }];
    match here {
        None => crumbs.push(Crumb {
            label: project.to_string(),
            href: None,
        }),
        Some(leaf) => {
            crumbs.push(Crumb {
                label: project.to_string(),
                href: Some(format!("/p/{}", urlencode(project))),
            });
            crumbs.push(Crumb {
                label: leaf.to_string(),
                href: None,
            });
        }
    }
    crumbs
}

/// One event as a sentence: actor, verb, object. The verb is the only place the
/// event kinds differ, so it is the only thing that switches on kind.
fn feed_row(e: &event::EventView, now: i64) -> FeedRow {
    let (verb, resource_kind) = match e.kind.as_str() {
        event::RESOURCE_PUBLISH => ("published", detail_str(e, "kind")),
        event::RESOURCE_REVISE => ("revised", detail_str(e, "kind")),
        event::RESOURCE_REMOVE => ("removed", detail_str(e, "kind")),
        event::PROJECT_CREATE => ("created project", None),
        event::ACCOUNT_REGISTER => ("registered", None),
        event::ACCOUNT_LOGIN => ("signed in as", None),
        event::ACCOUNT_LOGIN_FAILED => ("failed to sign in as", None),
        event::ACCOUNT_LOGOUT => ("signed out of", None),
        event::TOKEN_CREATE => ("minted token", None),
        event::TOKEN_REVOKE => ("revoked token", None),
        event::INVITE_CREATE => ("created", None),
        event::INVITE_CLAIM => ("joined with an invite as", None),
        event::ACCOUNT_DISABLE => ("disabled", None),
        event::ACCOUNT_ENABLE => ("enabled", None),
        event::PROJECT_VISIBILITY => {
            let verb = match e.detail.get("is_public").and_then(|v| v.as_bool()) {
                Some(true) => "made public",
                Some(false) => "made private",
                None => "changed visibility of",
            };
            (verb, None)
        }
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
    cursor: Option<i64>,
}

/// Opening a project answers *what happened here* the same way `/` answers
/// that for the fleet. Resources live one click away at `/resources`.
///
/// A leftover `?kind=` of a resource kind (the old filter on this URL)
/// answers 303 to `/resources?kind=`, so a bookmarked chip still lands on
/// the list it named.
async fn project_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(project): Path<String>,
    Query(query): Query<ProjectQuery>,
) -> AppResult<Response> {
    let (actor, nav) = viewer(&state, &headers, &uri);
    if !has_browser_session(&actor) {
        return Ok(redirect_to_login());
    }
    if let Some(kind) = query.kind.as_deref() {
        if RESOURCE_KINDS.contains(&kind) {
            return Ok(Redirect::to(&format!(
                "/p/{}/resources?kind={}",
                urlencode(&project),
                urlencode(kind)
            ))
            .into_response());
        }
    }

    let kind_filter = browse_kind_filter(query.kind.as_deref(), &event::PROJECT_KINDS);

    let conn = state.db();
    let project_id = readable_project(&conn, actor.as_ref(), &project)?;
    let github_repo = project_github_repo(&conn, &project_id)?;
    let events = event::query(
        &conn,
        actor.as_ref(),
        &event::Query {
            project: Some(&project),
            kind: kind_filter.as_deref(),
            cursor: query.cursor,
            limit: FEED_PAGE,
        },
    )?;
    drop(conn);

    let (days, older) = group_feed(&events);
    let query_base = feed_query_base(None, Some(kind_filter.as_deref().unwrap_or(FEED_KIND_ALL)));
    let feed_path = format!("/p/{}", urlencode(&project));
    let (title, css_url, app_js_url) = chrome(&project);
    Ok(render(&ProjectActivityTemplate {
        title,
        css_url,
        app_js_url,
        crumbs: project_crumbs(&project, None),
        nav,
        initial: logo_initial(&project),
        hue: logo_hue(&project),
        github_repo,
        project: project.clone(),
        tab: "activity",
        kinds: &event::PROJECT_KINDS,
        kind_filter,
        days,
        older,
        query_base,
        feed_path,
        show_project: false,
    })?
    .into_response())
}

async fn project_resources_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(project): Path<String>,
    Query(query): Query<ProjectQuery>,
) -> AppResult<Response> {
    let (actor, nav) = viewer(&state, &headers, &uri);
    if !has_browser_session(&actor) {
        return Ok(redirect_to_login());
    }
    let conn = state.db();
    let project_id = readable_project(&conn, actor.as_ref(), &project)?;
    let github_repo = project_github_repo(&conn, &project_id)?;

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
    let (title, css_url, app_js_url) = chrome(&format!("{project} resources"));
    Ok(render(&ProjectTemplate {
        title,
        css_url,
        app_js_url,
        crumbs: project_crumbs(&project, Some("resources")),
        nav,
        initial: logo_initial(&project),
        hue: logo_hue(&project),
        github_repo,
        project: project.clone(),
        tab: "resources",
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
    })?
    .into_response())
}

/// The file a bundle should open on, per kind. First match wins.
///
/// Krypton names these deliberately and they are not the alphabetical first:
/// `daily` carries `brief.md` (a lane's narration) beside `note.md` (derived
/// from records), and the record has to be what a reader lands on. `review`
/// bundles carry an `assets/` directory that sorts ahead of both markdown files.
const ENTRY_FILES: [(&str, &[&str]); 3] = [
    ("daily", &["note.md"]),
    ("review", &["review.md", "response.md"]),
    ("analysis", &["root-cause.md", "fix-plan.md"]),
];

/// Which file the resource page shows when the reader has not named one.
///
/// Files arrive `ORDER BY path`, so a blind `.first()` opens a review bundle on
/// `assets/diagram.png` and a day on its narration rather than its record.
/// Preference order: the kind's own entry file, then any top-level markdown,
/// then whatever is first — never nothing when the revision has files.
fn entry_file<'a>(
    kind: &str,
    files: &'a [crate::api::FileEntry],
) -> Option<&'a crate::api::FileEntry> {
    if let Some((_, wanted)) = ENTRY_FILES.iter().find(|(k, _)| *k == kind) {
        for want in *wanted {
            if let Some(hit) = files.iter().find(|f| f.path == *want) {
                return Some(hit);
            }
        }
    }
    files
        .iter()
        .find(|f| f.path.ends_with(".md") && !f.path.contains('/'))
        .or_else(|| files.first())
}

#[derive(Deserialize)]
pub struct ResourceQuery {
    file: Option<String>,
}

async fn resource_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path((project, kind, raw_slug)): Path<(String, String, String)>,
    Query(query): Query<ResourceQuery>,
) -> AppResult<Response> {
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

    let (actor, nav) = viewer(&state, &headers, &uri);
    if !has_browser_session(&actor) {
        return Ok(redirect_to_login());
    }
    let conn = state.db();
    let project_id = readable_project(&conn, actor.as_ref(), &project)?;
    let github_repo =
        repo_from_analysis_slug(&kind, &slug).or(project_github_repo(&conn, &project_id)?);

    let resource_id: String = conn
        .query_row(
            "SELECT id FROM resource WHERE project_id = ?1 AND kind = ?2 AND slug = ?3",
            rusqlite::params![project_id, kind, slug],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| AppError::not_found("no such resource"))?;

    let detail = load_resource_detail(&conn, actor.as_ref(), &resource_id, seq)?;
    // Sibling resources in this project are what a cited #N or `repo#N` can
    // resolve to. Loaded here while the connection is still open, matched
    // later against the rendered HTML so the section cannot disagree with
    // the body. The page itself is not a sibling of itself.
    let follow_siblings = load_sibling_resources(
        &conn,
        &project_id,
        &detail.summary.kind,
        &detail.summary.slug,
    )?;
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
    let page_js_url = assets::url("resource.js");

    let Some(revision) = detail.revision else {
        return Ok(render(&ResourceTemplate {
            title,
            css_url,
            app_js_url,
            page_js_url,
            crumbs,
            nav,
            byline: None,
            project,
            kind: detail.summary.kind,
            slug: detail.summary.slug,
            resource_id,
            seq: 0,
            revisions: 0,
            pinned: false,
            files: Vec::new(),
            content: "<p class=\"empty\">no committed revision</p>".to_string(),
            references: Vec::new(),
            followups: Vec::new(),
        })?
        .into_response());
    };

    let selected = query
        .file
        .as_deref()
        .and_then(|want| revision.files.iter().find(|f| f.path == want))
        .or_else(|| entry_file(&detail.summary.kind, &revision.files));

    // A resource with no files is not an empty resource. `attention` has no
    // on-disk form at all — its question, the option the lane chose, and the
    // rationale all live in the revision's `meta` — so a file-only renderer
    // showed such a resource as a title over "this revision has no files",
    // withholding the entire payload from the reader. Files still win when
    // there are any; meta is what fills the page when there are none.
    let content = match selected {
        Some(file) => render_file(
            &state,
            &revision.id,
            &file.path,
            &file.content_type,
            github_repo.as_deref(),
        )?,
        None => {
            match crate::meta::render_meta(
                &detail.summary.kind,
                &revision.meta,
                &detail.summary.title,
            ) {
                // Meta text cites issues the way a document does — an attention
                // flag's rationale saying "see #12" — so it gets the same pass,
                // and with it a place in the references section below.
                Some(html) => match github_repo.as_deref() {
                    Some(repo) => link_issue_refs(&html, repo),
                    None => html,
                },
                None => "<p class=\"empty\">this revision has no files</p>".to_string(),
            }
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

    let followups = collect_followups(
        &content,
        &detail.summary.title,
        &project,
        github_repo_for_project(&project, github_repo.as_deref()).as_deref(),
        &follow_siblings,
    );
    // A GitHub issue that the follow-up section already lists stays out of
    // references so the two indexes do not repeat each other.
    let references = collect_references(&content)
        .into_iter()
        .filter(|r| !followups.iter().any(|f| f.href == r.href))
        .collect();

    Ok(render(&ResourceTemplate {
        title,
        css_url,
        app_js_url,
        page_js_url,
        crumbs,
        nav,
        byline: byline_for(&revision),
        project,
        kind: detail.summary.kind,
        slug: detail.summary.slug,
        resource_id,
        seq: revision.seq,
        revisions: detail.summary.revisions,
        pinned: seq.is_some(),
        files,
        content,
        references,
        followups,
    })?
    .into_response())
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

/// The project's linked GitHub repository, if any. Small enough to ask for
/// wherever a page is about to render markdown.
fn project_github_repo(conn: &Connection, project_id: &str) -> AppResult<Option<String>> {
    Ok(conn.query_row(
        "SELECT github_repo FROM project WHERE id = ?1",
        [project_id],
        |r| r.get(0),
    )?)
}

/// The repository an analysis bundle names in its own slug. Krypton publishes
/// the analysis of issue N in owner/repo under the slug `owner/repo/N`, so
/// that page resolves `#M` against the repo the conversation is actually
/// about — which the project's linked repo may not be: a backend project
/// legitimately holds analyses of UI-repo issues. More specific wins; every
/// other page falls back to the project setting.
fn repo_from_analysis_slug(kind: &str, slug: &str) -> Option<String> {
    if kind != "analysis" {
        return None;
    }
    let (repo, n) = slug.rsplit_once('/')?;
    if n.is_empty() || !n.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    // Also rejects a deeper slug: its head is not a plain owner/repo.
    crate::util::normalize_github_repo(repo)
}

fn render_file(
    state: &AppState,
    revision_id: &str,
    path: &str,
    content_type: &str,
    github_repo: Option<&str>,
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
        let mut html = crate::render::render_review_blocks(&markdown_to_html(&text));
        // After the review pass, so an issue mentioned inside a finding's own
        // prose gets its link too.
        if let Some(repo) = github_repo {
            html = link_issue_refs(&html, repo);
        }
        return Ok(format!("<article class=\"doc\">{html}</article>"));
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

/// Turns `#123` in rendered markdown into a link to that issue in the
/// project's GitHub repository. String-level over comrak output — the same
/// stance as `render::render_review_blocks` — walking tags so that text inside
/// `<pre>`, `<code>` and existing `<a>` elements is never rewritten: a `#7` in
/// a diff hunk or a code sample is code, not a reference.
///
/// `repo` is the stored, normalized `owner/repo` (see
/// `util::normalize_github_repo`), so it splices into the href unescaped.
pub fn link_issue_refs(html: &str, repo: &str) -> String {
    // <a> needs the boundary check so it does not swallow <article>.
    const OPAQUE: [(&str, &str); 3] = [("pre", "</pre>"), ("code", "</code>"), ("a", "</a>")];

    let mut out = String::with_capacity(html.len() + 64);
    let mut rest = html;
    while let Some(at) = rest.find('<') {
        link_issue_text(&mut out, &rest[..at], repo);
        rest = &rest[at..];

        let opaque_close = OPAQUE.iter().find_map(|(name, close)| {
            let boundary = rest.as_bytes().get(1 + name.len());
            (rest[1..].starts_with(name) && matches!(boundary, Some(b' ' | b'>'))).then_some(*close)
        });
        let copied = match opaque_close {
            // The whole element, verbatim. An unclosed one is comrak output we
            // do not recognize; leave everything from here untouched.
            Some(close) => rest.find(close).map(|i| i + close.len()),
            // Any other tag: copy just the tag, text scanning resumes after it.
            None => rest.find('>').map(|i| i + 1),
        };
        match copied {
            Some(end) => {
                out.push_str(&rest[..end]);
                rest = &rest[end..];
            }
            None => {
                out.push_str(rest);
                return out;
            }
        }
    }
    link_issue_text(&mut out, rest, repo);
    out
}

/// One row of a resource page's references section: an external destination
/// the rendered content points at.
struct RefItem {
    href: String,
    label: String,
    /// The pill text: "issue" for a GitHub issue or pull request, "link"
    /// otherwise.
    kind: &'static str,
}

/// One row of a day's follow-up section: a cited issue or a Xenon resource
/// that issue (or a distinctive token) resolves to. `internal` rows stay on
/// this origin; the others are GitHub.
#[derive(Debug)]
struct FollowItem {
    href: String,
    label: String,
    kind: String,
    internal: bool,
}

/// A committed sibling in the same project. Loaded once per daily page and
/// matched in memory — the set is the same 500-row cap the project listing
/// uses, and LIKE-matching `#12` against `#120` in SQL is the bug this
/// avoids.
struct Sibling {
    kind: String,
    slug: String,
    title: String,
}

/// A `#N`, `repo#N`, or `owner/repo#N` the day's prose named.
struct IssueMention {
    /// `owner/repo`, a short repo name, or `None` for a bare `#N`.
    repo: Option<String>,
    number: String,
}

/// Gathers the external destinations out of rendered content, in document
/// order, one row per URL however often it is mentioned. Internal hrefs (file
/// tabs, revisions, other resources) are navigation, not references, so only
/// `http(s)://` destinations qualify. Runs over the same server-rendered HTML
/// the page shows, so it can never disagree with the content about where a
/// link goes.
fn collect_references(html: &str) -> Vec<RefItem> {
    let mut refs: Vec<RefItem> = Vec::new();
    let mut rest = html;
    while let Some(at) = rest.find("<a ") {
        rest = &rest[at..];
        let Some(tag_end) = rest.find('>') else { break };
        let tag = &rest[..tag_end];

        let href = tag
            .find("href=\"")
            .map(|h| &tag[h + 6..])
            .and_then(|v| v.split('"').next())
            .map(crate::render::unescape)
            .unwrap_or_default();

        let Some(close) = rest.find("</a>") else {
            break;
        };
        let text = strip_tags(&rest[tag_end + 1..close]);
        rest = &rest[close + 4..];

        if !href.starts_with("https://") && !href.starts_with("http://") {
            continue;
        }
        if refs.iter().any(|r| r.href == href) {
            continue;
        }

        let (kind, label) = match github_issue_label(&href) {
            Some(label) => ("issue", label),
            // The link's own text names the destination best; a bare autolink
            // repeats its URL, which reads better without the scheme.
            None => {
                let text = text.trim();
                let label = if text.is_empty() || text == href {
                    href.trim_start_matches("https://")
                        .trim_start_matches("http://")
                        .to_string()
                } else {
                    text.to_string()
                };
                ("link", truncate_label(&label))
            }
        };
        refs.push(RefItem { href, label, kind });
    }
    refs
}

fn load_sibling_resources(
    conn: &Connection,
    project_id: &str,
    skip_kind: &str,
    skip_slug: &str,
) -> AppResult<Vec<Sibling>> {
    let mut stmt = conn.prepare(
        "SELECT kind, slug, title FROM resource
         WHERE project_id = ?1 AND head_revision IS NOT NULL
           AND NOT (kind = ?2 AND slug = ?3)
         ORDER BY updated_at DESC LIMIT 500",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![project_id, skip_kind, skip_slug], |r| {
            Ok(Sibling {
                kind: r.get(0)?,
                slug: r.get(1)?,
                title: r.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// The GitHub `owner/repo` a bare `#N` should resolve against: the project's
/// stored link if it has one, otherwise the `owner.repo` slug Krypton
/// derives from a git remote.
fn github_repo_for_project(project_slug: &str, stored: Option<&str>) -> Option<String> {
    if let Some(repo) = stored.filter(|s| !s.is_empty()) {
        return Some(repo.to_string());
    }
    let (owner, repo) = project_slug.split_once('.')?;
    crate::util::normalize_github_repo(&format!("{owner}/{repo}"))
}

/// Issues and Xenon resources the page names, in document order, one row
/// per destination. A page that cites nothing resolvable returns empty —
/// the section is not a listing of the project. `title` is scanned too:
/// an artifact's only citation is often the `#N` in its heading.
fn collect_followups(
    html: &str,
    title: &str,
    project: &str,
    github_repo: Option<&str>,
    siblings: &[Sibling],
) -> Vec<FollowItem> {
    let mut mentions = extract_issue_mentions(html);
    scan_issue_mentions(title, &mut mentions);
    let text = format!("{title} {}", strip_tags(html));
    let mut items = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for mention in &mentions {
        let mut matched: Vec<&Sibling> = siblings
            .iter()
            .filter(|s| resource_matches(s, mention))
            .collect();
        matched.sort_by_key(|s| kind_rank(&s.kind));

        if let Some((href, label)) = github_issue_href(mention, github_repo, &matched) {
            push_followup(
                &mut items,
                &mut seen,
                FollowItem {
                    href,
                    label,
                    kind: "issue".into(),
                    internal: false,
                },
            );
        }
        for sib in matched {
            push_followup(
                &mut items,
                &mut seen,
                FollowItem {
                    href: format!("/r/{project}/{}/{}", sib.kind, sib.slug),
                    label: sib.title.clone(),
                    kind: sib.kind.clone(),
                    internal: true,
                },
            );
        }
    }

    // An attention flag the day names by a distinctive token (`pol_id`)
    // rather than an issue number still belongs in the index.
    for sib in siblings
        .iter()
        .filter(|s| s.kind == "attention" && attention_token_hit(&s.title, &text))
    {
        push_followup(
            &mut items,
            &mut seen,
            FollowItem {
                href: format!("/r/{project}/{}/{}", sib.kind, sib.slug),
                label: sib.title.clone(),
                kind: sib.kind.clone(),
                internal: true,
            },
        );
    }
    items
}

fn push_followup(
    items: &mut Vec<FollowItem>,
    seen: &mut std::collections::HashSet<String>,
    item: FollowItem,
) {
    if seen.insert(item.href.clone()) {
        items.push(item);
    }
}

fn kind_rank(kind: &str) -> u8 {
    match kind {
        "analysis" => 0,
        "review" => 1,
        "artifact" => 2,
        "attention" => 3,
        "doc" => 4,
        _ => 9,
    }
}

fn github_issue_href(
    mention: &IssueMention,
    default_repo: Option<&str>,
    matches: &[&Sibling],
) -> Option<(String, String)> {
    let repo = match mention.repo.as_deref() {
        Some(named) if named.contains('/') => crate::util::normalize_github_repo(named)?,
        Some(_) => matches
            .iter()
            .find_map(|s| analysis_repo_and_number(&s.slug).map(|(repo, _)| repo.to_string()))
            .or_else(|| {
                let owner = default_repo?.split('/').next()?;
                let short = mention.repo.as_deref()?;
                crate::util::normalize_github_repo(&format!("{owner}/{short}"))
            })?,
        None => default_repo?.to_string(),
    };
    Some((
        format!("https://github.com/{repo}/issues/{}", mention.number),
        format!("{repo}#{}", mention.number),
    ))
}

fn resource_matches(sib: &Sibling, mention: &IssueMention) -> bool {
    if let Some(repo) = mention.repo.as_deref() {
        if sib.kind == "analysis" {
            if let Some((slug_repo, n)) = analysis_repo_and_number(&sib.slug) {
                if n == mention.number && repo_fits(slug_repo, repo) {
                    return true;
                }
            }
        }
        return title_cites(&sib.title, &mention.number)
            && (sib.slug.contains(repo)
                || sib
                    .title
                    .to_ascii_lowercase()
                    .contains(&repo.to_ascii_lowercase()));
    }
    if sib.kind == "analysis" {
        if let Some((_, n)) = analysis_repo_and_number(&sib.slug) {
            if n == mention.number {
                return true;
            }
        }
    }
    title_cites(&sib.title, &mention.number)
}

/// `owner/repo/N` — the analysis slug shape. Anything else is not an issue
/// permalink and must not steal a `#N` match.
fn analysis_repo_and_number(slug: &str) -> Option<(&str, &str)> {
    let (repo, n) = slug.rsplit_once('/')?;
    if n.is_empty() || !n.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    repo.contains('/').then_some((repo, n))
}

fn repo_fits(slug_repo: &str, mention_repo: &str) -> bool {
    if slug_repo == mention_repo {
        return true;
    }
    if mention_repo.contains('/') {
        return false;
    }
    let last = slug_repo.rsplit('/').next().unwrap_or(slug_repo);
    last == mention_repo || (mention_repo.len() >= 6 && last.ends_with(&format!("-{mention_repo}")))
}

fn title_cites(title: &str, number: &str) -> bool {
    let needle = format!("#{number}");
    let bytes = title.as_bytes();
    let mut from = 0;
    while let Some(at) = title[from..].find(&needle) {
        let i = from + at;
        let after = i + needle.len();
        let next_ok = after >= bytes.len() || !bytes[after].is_ascii_alphanumeric();
        if next_ok {
            return true;
        }
        from = after;
    }
    false
}

fn attention_token_hit(title: &str, haystack: &str) -> bool {
    snake_case_tokens(title)
        .into_iter()
        .any(|tok| tok.len() >= 5 && haystack.contains(tok))
}

fn snake_case_tokens(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < bytes.len() {
        if bytes[i].is_ascii_alphabetic() {
            let start = i;
            let mut has_us = false;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                if bytes[i] == b'_' {
                    has_us = true;
                }
                i += 1;
            }
            if has_us && i - start >= 5 {
                out.push(&text[start..i]);
            }
        } else {
            i += 1;
        }
    }
    out
}

/// `#N` / `repo#N` / `owner/repo#N` in document order, skipping fenced and
/// inline code so a path like `docs/cr/…/1048/…` or a `#define` is not a
/// citation. Deduped by (repo, number).
fn extract_issue_mentions(html: &str) -> Vec<IssueMention> {
    let mut out = Vec::new();
    for_each_visible_text(html, |text| scan_issue_mentions(text, &mut out));
    out
}

fn for_each_visible_text(html: &str, mut visit: impl FnMut(&str)) {
    // `<a>` stays visible: a cited `#12` that `link_issue_refs` already
    // wrapped is still a mention the follow-up section should list.
    const OPAQUE: [(&str, &str); 2] = [("pre", "</pre>"), ("code", "</code>")];
    let mut rest = html;
    while let Some(at) = rest.find('<') {
        if at > 0 {
            visit(&rest[..at]);
        }
        rest = &rest[at..];
        let opaque_close = OPAQUE.iter().find_map(|(name, close)| {
            let boundary = rest.as_bytes().get(1 + name.len());
            (rest[1..].starts_with(name) && matches!(boundary, Some(b' ' | b'>'))).then_some(*close)
        });
        let copied = match opaque_close {
            Some(close) => rest.find(close).map(|i| i + close.len()),
            None => rest.find('>').map(|i| i + 1),
        };
        match copied {
            Some(end) => rest = &rest[end..],
            None => return,
        }
    }
    if !rest.is_empty() {
        visit(rest);
    }
}

fn scan_issue_mentions(text: &str, out: &mut Vec<IssueMention>) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'#' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            let nlen = j - i - 1;
            let next_ok = j >= bytes.len() || !bytes[j].is_ascii_alphanumeric();
            if (1..=10).contains(&nlen) && next_ok {
                if let Some((repo, start)) = repo_prefix_before(&text[..i]) {
                    let prev_ok = start == 0 || {
                        let p = bytes[start - 1];
                        !p.is_ascii_alphanumeric() && p != b'&' && p != b'#' && p != b'/'
                    };
                    if prev_ok {
                        let mention = IssueMention {
                            repo,
                            number: text[i + 1..j].to_string(),
                        };
                        if !out
                            .iter()
                            .any(|m| m.repo == mention.repo && m.number == mention.number)
                        {
                            out.push(mention);
                        }
                        i = j;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
}

/// The repo name glued to the `#`, if any, and the byte index where that
/// name starts. A one-letter prefix (`C#`) is a language, not a repo.
fn repo_prefix_before(before: &str) -> Option<(Option<String>, usize)> {
    let bytes = before.as_bytes();
    let mut k = bytes.len();
    while k > 0 && is_repo_char(bytes[k - 1]) {
        k -= 1;
    }
    if k == bytes.len() {
        return Some((None, bytes.len()));
    }
    let tail = &before[k..];
    let first = tail.chars().next()?;
    if !first.is_ascii_alphabetic() {
        return Some((None, bytes.len()));
    }
    if tail.len() == 1 {
        // `C#12` is not a repository citation.
        return None;
    }
    if k > 0 && bytes[k - 1] == b'/' {
        let mut o = k - 1;
        while o > 0 && is_repo_char(bytes[o - 1]) {
            o -= 1;
        }
        let owner = &before[o..k - 1];
        if !owner.is_empty() && owner.chars().next()?.is_ascii_alphabetic() {
            return Some((Some(format!("{owner}/{tail}")), o));
        }
    }
    Some((Some(tail.to_string()), k))
}

fn is_repo_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
}

/// `owner/repo#123` for a GitHub issue or pull-request URL, or None for
/// anything else. A query string or fragment (a comment permalink) still
/// counts; a deeper path segment (`/pull/5/files`) does not — that page is
/// about the files, and the plain-link label keeps that visible.
fn github_issue_label(href: &str) -> Option<String> {
    let path = href.strip_prefix("https://github.com/")?;
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let mut parts = path.trim_end_matches('/').split('/');
    let (owner, repo, kind, number) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let simple = parts.next().is_none()
        && matches!(kind, "issues" | "pull")
        && !number.is_empty()
        && number.chars().all(|c| c.is_ascii_digit());
    simple.then(|| format!("{owner}/{repo}#{number}"))
}

/// Anchor text may carry inline markup (`<code>`, entities); the reference row
/// wants the words alone.
fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(at) = rest.find('<') {
        out.push_str(&rest[..at]);
        match rest[at..].find('>') {
            Some(end) => rest = &rest[at + end + 1..],
            None => return crate::render::unescape(&out),
        }
    }
    out.push_str(rest);
    crate::render::unescape(&out)
}

/// A reference row is an index entry, not a place to lay out a paragraph-long
/// link text.
fn truncate_label(label: &str) -> String {
    const MAX: usize = 90;
    if label.chars().count() <= MAX {
        return label.to_string();
    }
    let cut: String = label.chars().take(MAX - 1).collect();
    format!("{cut}…")
}

/// The text-node half of `link_issue_refs`. A reference is `#` plus 1..=10
/// digits on its own word boundary; the `&`/`#` look-behind keeps numeric
/// character entities (`&#39;`) and `##` intact.
fn link_issue_text(out: &mut String, text: &str, repo: &str) {
    let b = text.as_bytes();
    let (mut i, mut copied) = (0, 0);
    while i < b.len() {
        if b[i] == b'#' {
            let prev_ok = i == 0 || {
                let p = b[i - 1];
                !p.is_ascii_alphanumeric() && p != b'&' && p != b'#'
            };
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            let next_ok = j >= b.len() || !b[j].is_ascii_alphanumeric();
            if prev_ok && next_ok && (2..=11).contains(&(j - i)) {
                let n = &text[i + 1..j];
                out.push_str(&text[copied..i]);
                out.push_str(&format!(
                    "<a href=\"https://github.com/{repo}/issues/{n}\">#{n}</a>"
                ));
                copied = j;
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&text[copied..]);
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
    uri: axum::http::Uri,
) -> AppResult<Html<String>> {
    let (_, nav) = viewer(&state, &headers, &uri);
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
    uri: axum::http::Uri,
) -> AppResult<Html<String>> {
    let (_, nav) = viewer(&state, &headers, &uri);
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
    uri: axum::http::Uri,
) -> AppResult<Response> {
    let (actor, nav) = viewer(&state, &headers, &uri);
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

async fn admin_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> AppResult<Response> {
    let (actor, nav) = viewer(&state, &headers, &uri);
    if !actor.as_ref().is_some_and(|a| a.is_session()) {
        return Ok(redirect_to_login());
    }
    // Not-found rather than forbidden: a signed-in non-admin should not learn
    // that this surface exists from the status code. The nav already hid the
    // link; typing the URL is the remaining path.
    if !actor.is_some_and(|a| a.is_admin) {
        return Err(AppError::not_found("no such page"));
    }
    let (title, css_url, app_js_url) = chrome("admin");
    Ok(render(&AdminTemplate {
        title,
        css_url,
        app_js_url,
        page_js_url: assets::url("admin.js"),
        crumbs: Vec::new(),
        nav,
    })?
    .into_response())
}

/// Theme for the browser. A POST, like sign-out: a GET would be cacheable and
/// a link a crawler could follow, and neither should paint the next reader's
/// page. The cookie is a preference, not a credential — `HttpOnly` still, so
/// page JS cannot be talked into rewriting it, and `SameSite=Lax` so a
/// cross-site form can at worst flip the colours, not read anything.
async fn set_theme(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ThemeForm>,
) -> Response {
    let location = return_path(form.next.as_deref(), &headers);
    let Some(theme) = Theme::from_form(&form.theme) else {
        return (StatusCode::SEE_OTHER, [(header::LOCATION, location)], ()).into_response();
    };
    (
        StatusCode::SEE_OTHER,
        [
            (
                header::SET_COOKIE,
                theme_cookie(theme, state.config.insecure_cookies),
            ),
            (header::LOCATION, location),
        ],
        (),
    )
        .into_response()
}

/// Display mode for the pages that list items. Same shape as `set_theme` — a
/// POST, a refused unknown value, and a same-origin return — because it is the
/// same kind of thing: a preference this browser holds, carrying nothing an
/// attacker could want and nothing a crawler should be able to trip.
async fn set_view(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ViewForm>,
) -> Response {
    let location = return_path(form.next.as_deref(), &headers);
    let Some(view) = View::from_form(&form.view) else {
        return (StatusCode::SEE_OTHER, [(header::LOCATION, location)], ()).into_response();
    };
    (
        StatusCode::SEE_OTHER,
        [
            (
                header::SET_COOKIE,
                view_cookie(view, state.config.insecure_cookies),
            ),
            (header::LOCATION, location),
        ],
        (),
    )
        .into_response()
}

fn theme_cookie(theme: Theme, insecure: bool) -> String {
    pref_cookie(THEME_COOKIE, theme.as_str(), insecure)
}

fn view_cookie(view: View, insecure: bool) -> String {
    pref_cookie(VIEW_COOKIE, view.as_str(), insecure)
}

/// One recipe for every chrome preference cookie, so a second one cannot end up
/// with weaker flags than the first. `HttpOnly` because no page script reads
/// these, and `SameSite=Lax` so a cross-site form can at worst change how this
/// browser paints a page it was already allowed to see.
fn pref_cookie(name: &str, value: &str, insecure: bool) -> String {
    let secure = if insecure { "" } else { " Secure;" };
    format!("{name}={value}; Path=/; HttpOnly;{secure} SameSite=Lax; Max-Age={PREF_TTL_SECS}")
}

/// Where to send the reader after a chrome form. Prefer `next` from the form
/// (every page has `Referrer-Policy: no-referrer`, so the browser will not
/// send a Referer). Either way only a same-origin path is kept — a crafted
/// `next` or a cross-site Referer must not send anyone off this host.
fn return_path(next: Option<&str>, headers: &HeaderMap) -> String {
    if let Some(path) = next.and_then(safe_return_to) {
        return path;
    }
    let Some(raw) = headers.get(header::REFERER).and_then(|v| v.to_str().ok()) else {
        return "/".to_string();
    };
    let Ok(uri) = raw.parse::<axum::http::Uri>() else {
        return "/".to_string();
    };
    let path = uri.path();
    if !path.starts_with('/') || path.starts_with("//") {
        return "/".to_string();
    }
    match uri.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    }
}

fn safe_return_to(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty()
        || !raw.starts_with('/')
        || raw.starts_with("//")
        || raw.contains("://")
        || raw.contains('\\')
        || raw.bytes().any(|b| b < 0x20)
    {
        return None;
    }
    Some(raw.to_string())
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
/// than a JSON error, so a bookmarked URL lands somewhere useful.
pub fn redirect_to_login() -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, "/login")], ()).into_response()
}

/// The browse UI is for people, not tokens. A missing or token-only caller
/// is sent to sign in rather than shown an empty shell.
fn has_browser_session(actor: &Option<Actor>) -> bool {
    actor.as_ref().is_some_and(|a| a.is_session())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nav_at(here: &str) -> Nav {
        Nav {
            signed_in: true,
            who: "wk".into(),
            is_admin: true,
            theme: Theme::Dark,
            view: View::Card,
            here: here.into(),
        }
    }

    fn files(paths: &[&str]) -> Vec<crate::api::FileEntry> {
        paths
            .iter()
            .map(|p| crate::api::FileEntry {
                path: (*p).to_string(),
                sha256: "0".repeat(64),
                size: 1,
                content_type: "text/markdown".into(),
            })
            .collect()
    }

    /// Files arrive sorted by path, which is the wrong default twice over: a
    /// day would open on the lane's narration and a review on an asset image.
    #[test]
    fn a_bundle_opens_on_its_record_not_on_whatever_sorts_first() {
        // `brief.md` < `note.md`, but the record is what a reader lands on.
        let day = files(&["brief.md", "note.md"]);
        assert_eq!(entry_file("daily", &day).unwrap().path, "note.md");
        // A day with no narration still opens on its note.
        let bare = files(&["note.md"]);
        assert_eq!(entry_file("daily", &bare).unwrap().path, "note.md");

        // `assets/…` sorts ahead of both markdown files in a review bundle.
        let review = files(&["assets/diagram.png", "response.md", "review.md"]);
        assert_eq!(entry_file("review", &review).unwrap().path, "review.md");
        // A review the human has not answered yet has no `review.md`? It does —
        // but if a bundle is ever missing it, the next named file wins.
        let partial = files(&["assets/diagram.png", "response.md"]);
        assert_eq!(entry_file("review", &partial).unwrap().path, "response.md");

        // An unlisted kind falls back to top-level markdown, then to anything.
        let doc = files(&["assets/x.png", "guide.md"]);
        assert_eq!(entry_file("doc", &doc).unwrap().path, "guide.md");
        let html = files(&["page.html"]);
        assert_eq!(entry_file("artifact", &html).unwrap().path, "page.html");
        assert!(entry_file("daily", &[]).is_none());
    }

    #[test]
    fn project_crumbs_link_back_to_the_project_home() {
        let home = project_crumbs("krypton", None);
        assert_eq!(home.len(), 2);
        assert_eq!(home[0].href.as_deref(), Some("/projects"));
        assert!(home[1].href.is_none());
        assert_eq!(home[1].label, "krypton");

        let leaf = project_crumbs("krypton", Some("resources"));
        assert_eq!(leaf[1].href.as_deref(), Some("/p/krypton"));
        assert!(leaf[2].href.is_none());
        assert_eq!(leaf[2].label, "resources");
    }

    #[test]
    fn the_browse_feed_defaults_to_publish_and_all_is_explicit() {
        assert_eq!(
            browse_kind_filter(None, &event::KINDS).as_deref(),
            Some(event::RESOURCE_PUBLISH)
        );
        assert_eq!(browse_kind_filter(Some("all"), &event::KINDS), None);
        assert_eq!(
            browse_kind_filter(Some("token.create"), &event::KINDS).as_deref(),
            Some("token.create")
        );
        assert_eq!(
            browse_kind_filter(Some("nonsense"), &event::KINDS).as_deref(),
            Some(event::RESOURCE_PUBLISH),
            "unknown kind falls back to the default, not the full log"
        );
        assert_eq!(
            browse_kind_filter(Some("token.create"), &event::PROJECT_KINDS).as_deref(),
            Some(event::RESOURCE_PUBLISH),
            "a kind that cannot appear on a project feed falls back to the default"
        );
    }

    #[test]
    fn nav_marks_the_section_the_page_belongs_to() {
        let feed = nav_at("/?kind=resource.publish");
        assert!(feed.on_activity());
        assert!(!feed.on_projects() && !feed.on_tokens() && !feed.on_admin());

        let project = nav_at("/p/krypton/usage");
        assert!(project.on_projects());
        assert!(!project.on_activity());

        let permalink = nav_at("/r/krypton/doc/notes/@1");
        assert!(permalink.on_projects());

        assert!(nav_at("/settings/tokens").on_tokens());
        assert!(nav_at("/admin").on_admin());
        assert!(nav_at("/login").on_login());
        assert!(nav_at("/register").on_login());
        assert!(!nav_at("/projects").on_login());
    }

    #[test]
    fn theme_cookie_only_accepts_the_two_modes() {
        assert_eq!(Theme::from_cookie(None), Theme::Dark);
        assert_eq!(Theme::from_cookie(Some("dark")), Theme::Dark);
        assert_eq!(Theme::from_cookie(Some("light")), Theme::Light);
        assert_eq!(Theme::from_cookie(Some("neon")), Theme::Dark);
        assert_eq!(Theme::from_form("light"), Some(Theme::Light));
        assert_eq!(Theme::from_form("dark"), Some(Theme::Dark));
        assert_eq!(Theme::from_form("neon"), None);
    }

    #[test]
    fn theme_toggle_posts_the_other_mode() {
        assert_eq!(Theme::Dark.other(), Theme::Light);
        assert_eq!(Theme::Light.other(), Theme::Dark);
        assert_eq!(Theme::Dark.toggle_label(), "use light theme");
        assert_eq!(Theme::Light.toggle_label(), "use dark theme");
    }

    #[test]
    fn theme_cookie_matches_the_session_cookie_flags() {
        let secure = theme_cookie(Theme::Light, false);
        assert!(secure.contains("xenon_theme=light"), "{secure}");
        assert!(secure.contains("HttpOnly"), "{secure}");
        assert!(secure.contains("Secure"), "{secure}");
        assert!(secure.contains("SameSite=Lax"), "{secure}");
        assert!(!theme_cookie(Theme::Dark, true).contains("Secure"));
    }

    #[test]
    fn view_cookie_only_accepts_the_two_modes() {
        assert_eq!(View::from_cookie(None), View::Card);
        assert_eq!(View::from_cookie(Some("card")), View::Card);
        assert_eq!(View::from_cookie(Some("list")), View::List);
        assert_eq!(View::from_cookie(Some("table")), View::Card);
        assert_eq!(View::from_form("card"), Some(View::Card));
        assert_eq!(View::from_form("list"), Some(View::List));
        assert_eq!(View::from_form("table"), None);
    }

    /// Both preference cookies come off `pref_cookie`, so guard the flags on the
    /// newer one too: a second cookie minted by hand is how one ends up without
    /// `HttpOnly`.
    #[test]
    fn view_cookie_matches_the_theme_cookie_flags() {
        let secure = view_cookie(View::List, false);
        assert!(secure.contains("xenon_view=list"), "{secure}");
        assert!(secure.contains("HttpOnly"), "{secure}");
        assert!(secure.contains("Secure"), "{secure}");
        assert!(secure.contains("SameSite=Lax"), "{secure}");
        assert!(!view_cookie(View::Card, true).contains("Secure"));
    }

    #[test]
    fn return_path_keeps_only_a_same_host_path() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::REFERER,
            "https://evil.example/phish".parse().unwrap(),
        );
        assert_eq!(return_path(Some("/projects"), &headers), "/projects");
        assert_eq!(
            return_path(Some("/?kind=review"), &HeaderMap::new()),
            "/?kind=review"
        );
        // Off-site or broken `next` is dropped; a same-host Referer path is
        // the fallback, and nothing at all lands on `/`.
        assert_eq!(
            return_path(Some("https://evil.example/"), &headers),
            "/phish"
        );
        assert_eq!(
            return_path(Some("https://evil.example/"), &HeaderMap::new()),
            "/"
        );
        assert_eq!(return_path(Some("//evil.example"), &headers), "/phish");
        assert_eq!(
            return_path(Some("/theme\nLocation: https://x"), &headers),
            "/phish"
        );
        assert_eq!(return_path(None, &headers), "/phish");
        assert_eq!(return_path(None, &HeaderMap::new()), "/");
    }

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
    fn issue_refs_link_into_the_projects_github_repo() {
        let html = link_issue_refs("<p>fixes #12 and #345.</p>", "wk-j/xenon");
        assert_eq!(
            html,
            "<p>fixes <a href=\"https://github.com/wk-j/xenon/issues/12\">#12</a> \
             and <a href=\"https://github.com/wk-j/xenon/issues/345\">#345</a>.</p>"
        );
    }

    #[test]
    fn issue_refs_inside_code_pre_and_links_stay_text() {
        // Real comrak shapes: inline code, a fenced block, an existing link.
        for html in [
            "<p><code>#12</code></p>",
            "<pre><code>fixes #12\n</code></pre>",
            "<p><a href=\"https://x.test/#12\">see #12</a></p>",
        ] {
            assert_eq!(link_issue_refs(html, "o/r"), html, "{html}");
        }
        // <a> matching must not swallow <article>.
        let article = "<article class=\"doc\"><p>#7</p></article>";
        assert!(
            link_issue_refs(article, "o/r").contains("issues/7"),
            "text inside <article> is still linkable"
        );
    }

    #[test]
    fn issue_ref_needs_a_word_boundary() {
        for html in [
            "<p>&#39;quoted&#39;</p>", // numeric character entity
            "<p>a#1</p>",              // glued to a word
            "<p>#12abc</p>",           // digits running into letters
            "<p>## heading marker</p>",
            "<p>#</p>",
        ] {
            let out = link_issue_refs(html, "o/r");
            assert_eq!(out, html, "{html}");
        }
        assert!(link_issue_refs("<p>(#12)</p>", "o/r").contains("issues/12"));
    }

    #[test]
    fn references_collect_external_links_once_each_and_skip_internal_ones() {
        let html = concat!(
            "<p><a href=\"?file=other.md\">tab</a>",
            " <a href=\"/r/p/doc/x\">sibling</a>",
            " <a href=\"https://example.com/docs\">the <code>docs</code></a>",
            " <a href=\"https://example.com/docs\">https://example.com/docs</a>",
            " <a href=\"https://github.com/wk-j/xenon/issues/12\">#12</a>",
            " <a href=\"https://github.com/wk-j/xenon/pull/5/files\">diff</a></p>",
        );
        let refs = collect_references(html);
        let rows: Vec<(&str, &str, &str)> = refs
            .iter()
            .map(|r| (r.kind, r.label.as_str(), r.href.as_str()))
            .collect();
        assert_eq!(
            rows,
            vec![
                // First mention wins the label; nested markup is stripped.
                ("link", "the docs", "https://example.com/docs"),
                (
                    "issue",
                    "wk-j/xenon#12",
                    "https://github.com/wk-j/xenon/issues/12"
                ),
                // A deeper PR path is about its files, so it stays a plain link.
                ("link", "diff", "https://github.com/wk-j/xenon/pull/5/files"),
            ]
        );
    }

    #[test]
    fn issue_mentions_come_from_prose_not_code() {
        let html = concat!(
            "<p>see #12, mapping-tool#18, and bcircle/tli-api-service#1101.</p>",
            "<p>again #12</p>",
            "<code>#99</code><pre><code>other-tool#7\n</code></pre>",
            "<p>C#12 and a#3 stay text, (#21) counts.</p>",
        );
        let mentions = extract_issue_mentions(html);
        let found: Vec<(Option<&str>, &str)> = mentions
            .iter()
            .map(|m| (m.repo.as_deref(), m.number.as_str()))
            .collect();
        assert_eq!(
            found,
            vec![
                (None, "12"),
                (Some("mapping-tool"), "18"),
                (Some("bcircle/tli-api-service"), "1101"),
                (None, "21"),
            ]
        );
    }

    #[test]
    fn a_days_citations_resolve_to_followups() {
        let html = concat!(
            "<p>closed #77 and mapping-tool#18, leftover #1099,</p>",
            "<p>still need to resolve the pol_id attention flag</p>",
        );
        let siblings = vec![
            Sibling {
                kind: "analysis".into(),
                slug: "acme/tli-mapping-tool/18".into(),
                title: "Lombok pin".into(),
            },
            Sibling {
                kind: "analysis".into(),
                slug: "acme/widgets/1".into(),
                title: "unrelated".into(),
            },
            Sibling {
                kind: "artifact".into(),
                slug: "hm-1/art-1".into(),
                title: "#1099 — leftover".into(),
            },
            Sibling {
                kind: "attention".into(),
                slug: "jdg-1".into(),
                title: "ช่องโหว่ pol_id หาย".into(),
            },
        ];
        let rows = collect_followups(html, "", "acme.widgets", Some("acme/widgets"), &siblings);
        let view: Vec<(&str, &str, &str)> = rows
            .iter()
            .map(|r| (r.kind.as_str(), r.label.as_str(), r.href.as_str()))
            .collect();
        assert_eq!(
            view,
            vec![
                (
                    "issue",
                    "acme/widgets#77",
                    "https://github.com/acme/widgets/issues/77"
                ),
                (
                    "issue",
                    "acme/tli-mapping-tool#18",
                    "https://github.com/acme/tli-mapping-tool/issues/18"
                ),
                (
                    "analysis",
                    "Lombok pin",
                    "/r/acme.widgets/analysis/acme/tli-mapping-tool/18"
                ),
                (
                    "issue",
                    "acme/widgets#1099",
                    "https://github.com/acme/widgets/issues/1099"
                ),
                (
                    "artifact",
                    "#1099 — leftover",
                    "/r/acme.widgets/artifact/hm-1/art-1"
                ),
                (
                    "attention",
                    "ช่องโหว่ pol_id หาย",
                    "/r/acme.widgets/attention/jdg-1"
                ),
            ]
        );
        assert!(rows.iter().all(|r| r.internal == (r.kind != "issue")));
        // A #N does not steal a longer number, and an uncited analysis stays out.
        assert!(!view.iter().any(|(_, label, _)| *label == "unrelated"));

        // An artifact often cites only in its title, with no body links at all.
        let from_title = collect_followups(
            "<p>open artifact</p>",
            "#1099 — leftover",
            "acme.widgets",
            Some("acme/widgets"),
            &siblings,
        );
        assert!(
            from_title
                .iter()
                .any(|r| r.href.ends_with("/artifact/hm-1/art-1")),
            "title #N still resolves: {from_title:?}"
        );
    }

    #[test]
    fn a_project_slug_from_a_git_remote_names_its_github_repo() {
        assert_eq!(
            github_repo_for_project("bcircle.tli-api-service", None).as_deref(),
            Some("bcircle/tli-api-service")
        );
        assert_eq!(
            github_repo_for_project("krypton", None),
            None,
            "a bare slug is not owner/repo"
        );
        assert_eq!(
            github_repo_for_project("krypton", Some("wk-j/krypton")).as_deref(),
            Some("wk-j/krypton"),
            "a stored link wins"
        );
    }

    #[test]
    fn title_cites_needs_the_whole_number() {
        assert!(title_cites("#1099 — leftover", "1099"));
        assert!(!title_cites("#1099 — leftover", "109"));
        assert!(!title_cites("#1099 — leftover", "10990"));
        assert!(title_cites("see (#7)", "7"));
    }

    #[test]
    fn a_bare_autolink_is_labelled_by_its_url_without_the_scheme() {
        let rendered = markdown_to_html("see https://example.com/a?b=1&c=2\n");
        let refs = collect_references(&rendered);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].label, "example.com/a?b=1&c=2");
        // comrak escaped the href; collection undoes that exactly once.
        assert_eq!(refs[0].href, "https://example.com/a?b=1&c=2");
    }

    #[test]
    fn an_analysis_slug_names_the_repo_its_refs_resolve_against() {
        assert_eq!(
            repo_from_analysis_slug("analysis", "bcircle/tli-dim-custom-ui/448").as_deref(),
            Some("bcircle/tli-dim-custom-ui")
        );
        // Only an analysis carries its repo in the slug; a doc's path is a path.
        assert_eq!(repo_from_analysis_slug("doc", "a/b/448"), None);
        // Non-numeric tail or a deeper slug is not the owner/repo/N shape.
        assert_eq!(repo_from_analysis_slug("analysis", "a/b/adhoc"), None);
        assert_eq!(repo_from_analysis_slug("analysis", "a/b/c/448"), None);
        assert_eq!(repo_from_analysis_slug("analysis", "448"), None);
    }

    #[test]
    fn a_pr_comment_permalink_still_labels_as_its_pull_request() {
        assert_eq!(
            github_issue_label("https://github.com/o/r/pull/7#issuecomment-1"),
            Some("o/r#7".to_string())
        );
        assert_eq!(
            github_issue_label("https://github.com/o/r/issues/7?q=x"),
            Some("o/r#7".to_string())
        );
        assert_eq!(github_issue_label("https://github.com/o/r"), None);
        assert_eq!(github_issue_label("https://github.com/o/r/issues/x7"), None);
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
