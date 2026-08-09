// Xenon — per-turn LLM usage ingest and aggregation (Krypton spec 214).
//
// Krypton posts one row the moment a prompt turn ends. Rows are numeric: token
// counts, a model id, a lane label, a stop reason. There is no prompt text and
// no response text in this table, by design — that is what lets Krypton stream
// them unattended rather than making a human approve each one.
//
// Ingest is idempotent on the CLIENT's row id. A client that times out waiting
// for the response cannot know whether the write landed, so it re-sends; the
// primary key turns that into a duplicate rather than a second charge. Every
// other property here follows from that one.
//
// Cost is NOT stored. It is computed on read from the rate table (`price.rs`)
// so that correcting a price corrects history — see ADR-0018.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::account::resolve_or_create_project;
use crate::api::readable_project;
use crate::auth::{self};
use crate::error::{AppError, AppResult};
use crate::price::{Money, Tokens};
use crate::state::AppState;
use crate::util::now;

/// Matches Krypton's outbox batch size. A backlog after an offline stretch
/// arrives in chunks of this size rather than as one unbounded request.
const MAX_TURNS_PER_REQUEST: usize = 500;
const MAX_FIELD_LEN: usize = 200;
/// The newest row schema this server understands. A row from a newer client is
/// rejected by name rather than parsed optimistically into wrong numbers.
const MAX_ROW_VERSION: u32 = 1;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/projects/{project}/usage/turns", post(ingest_turns))
        .route("/v1/projects/{project}/usage", get(read_usage))
}

// ------------------------------------------------------------------ payloads

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnTokens {
    #[serde(default)]
    pub input: i64,
    #[serde(default)]
    pub output: i64,
    #[serde(default)]
    pub cached_read: Option<i64>,
    #[serde(default)]
    pub cached_write: Option<i64>,
    #[serde(default)]
    pub thought: Option<i64>,
    #[serde(default)]
    pub total: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnContext {
    #[serde(default)]
    pub used: Option<i64>,
    #[serde(default)]
    pub size: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnCost {
    pub amount: f64,
    #[serde(default)]
    pub currency: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnRow {
    #[serde(default = "one")]
    pub v: u32,
    pub id: String,
    pub at: i64,
    #[serde(default)]
    pub duration_ms: Option<i64>,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub harness_id: String,
    #[serde(default)]
    pub lane: String,
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub model_confirmed: bool,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub turn: i64,
    #[serde(default)]
    pub stop_reason: String,
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub tokens: Option<TurnTokens>,
    #[serde(default)]
    pub context: Option<TurnContext>,
    #[serde(default)]
    pub cost: Option<TurnCost>,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
pub struct IngestRequest {
    pub turns: Vec<TurnRow>,
}

#[derive(Debug, Serialize)]
pub struct RejectedRow {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct IngestAck {
    pub accepted: usize,
    pub duplicates: usize,
    pub rejected: Vec<RejectedRow>,
}

// -------------------------------------------------------------------- ingest

/// `POST /v1/projects/{project}/usage/turns`
///
/// One transaction for the whole batch. A malformed row is named in `rejected`
/// and the rest still land: a fleet's ledger must not be held hostage by one
/// bad row, and the client acks rejects deliberately so they cannot wedge the
/// head of its queue forever.
async fn ingest_turns(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(req): Json<IngestRequest>,
) -> AppResult<(StatusCode, Json<IngestAck>)> {
    if req.turns.len() > MAX_TURNS_PER_REQUEST {
        return Err(AppError::too_large(format!(
            "at most {MAX_TURNS_PER_REQUEST} turns per request"
        )));
    }

    let conn = state.db();
    let actor = auth::require_actor(&conn, &headers)?;
    // The same scope resource pushes use. A separate `usage:write` would mean
    // every token already minted for a Krypton install stops working the day
    // this ships, for no security gained: both write project-scoped data.
    actor.require_scope(auth::SCOPE_RESOURCE_WRITE)?;
    let project_id = resolve_or_create_project(&conn, &actor, &project)?;

    let received_at = now();
    let mut ack = IngestAck {
        accepted: 0,
        duplicates: 0,
        rejected: Vec::new(),
    };

    let tx = conn.unchecked_transaction().map_err(AppError::from)?;
    for row in req.turns {
        if let Err(reason) = validate(&row) {
            ack.rejected.push(RejectedRow { id: row.id, reason });
            continue;
        }
        match insert_turn(&tx, &project_id, &actor.user_id, received_at, &row) {
            Ok(true) => ack.accepted += 1,
            // The row is already here. This is the normal outcome of a retry
            // after an ambiguous timeout, not an error worth surfacing.
            Ok(false) => ack.duplicates += 1,
            Err(e) => ack.rejected.push(RejectedRow {
                id: row.id,
                reason: format!("{e}"),
            }),
        }
    }
    tx.commit().map_err(AppError::from)?;

    Ok((StatusCode::ACCEPTED, Json(ack)))
}

fn validate(row: &TurnRow) -> Result<(), String> {
    if row.v > MAX_ROW_VERSION {
        return Err(format!("row version {} is newer than this server", row.v));
    }
    if row.id.is_empty() || row.id.len() > MAX_FIELD_LEN {
        return Err("id must be 1..=200 characters".to_string());
    }
    if row.at <= 0 {
        return Err("at must be a positive epoch-ms timestamp".to_string());
    }
    for (name, value) in [
        ("lane", &row.lane),
        ("backend", &row.backend),
        ("hostname", &row.hostname),
        ("harnessId", &row.harness_id),
        ("stopReason", &row.stop_reason),
        ("origin", &row.origin),
    ] {
        if value.len() > MAX_FIELD_LEN {
            return Err(format!("{name} exceeds {MAX_FIELD_LEN} characters"));
        }
    }
    if row.model.as_ref().is_some_and(|m| m.len() > MAX_FIELD_LEN) {
        return Err(format!("model exceeds {MAX_FIELD_LEN} characters"));
    }
    if let Some(tokens) = &row.tokens {
        if tokens.input < 0 || tokens.output < 0 {
            return Err("token counts cannot be negative".to_string());
        }
    }
    Ok(())
}

/// `Ok(false)` means the row was already present. Cost is written as REPORTED
/// only; an estimate is never persisted, so re-pricing is a read-time concern.
fn insert_turn(
    conn: &Connection,
    project_id: &str,
    user_id: &str,
    received_at: i64,
    row: &TurnRow,
) -> Result<bool, rusqlite::Error> {
    let tokens = row.tokens.as_ref();
    let changed = conn.execute(
        "INSERT INTO usage_turn (
             id, project_id, at, duration_ms, hostname, harness_id, lane, backend,
             model, model_confirmed, session_id, turn_seq, stop_reason, origin,
             has_tokens, input_tokens, output_tokens, cached_read, cached_write,
             thought_tokens, total_tokens, context_used, context_size,
             cost_amount, cost_currency, received_at, uploaded_by
         ) VALUES (
             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
             ?9, ?10, ?11, ?12, ?13, ?14,
             ?15, ?16, ?17, ?18, ?19,
             ?20, ?21, ?22, ?23,
             ?24, ?25, ?26, ?27
         )
         ON CONFLICT(project_id, id) DO NOTHING",
        params![
            row.id,
            project_id,
            row.at,
            row.duration_ms,
            row.hostname,
            row.harness_id,
            row.lane,
            row.backend,
            row.model,
            i64::from(row.model_confirmed),
            row.session_id,
            row.turn,
            row.stop_reason,
            row.origin,
            i64::from(tokens.is_some()),
            tokens.map(|t| t.input),
            tokens.map(|t| t.output),
            tokens.and_then(|t| t.cached_read),
            tokens.and_then(|t| t.cached_write),
            tokens.and_then(|t| t.thought),
            tokens.and_then(|t| t.total),
            row.context.as_ref().and_then(|c| c.used),
            row.context.as_ref().and_then(|c| c.size),
            row.cost.as_ref().map(|c| c.amount),
            row.cost.as_ref().map(|c| {
                if c.currency.is_empty() {
                    "USD".to_string()
                } else {
                    c.currency.clone()
                }
            }),
            received_at,
            user_id,
        ],
    )?;
    Ok(changed > 0)
}

// ---------------------------------------------------------------- aggregate

#[derive(Debug, Deserialize)]
pub struct UsageQuery {
    /// Inclusive epoch-ms lower bound on the turn's own timestamp.
    #[serde(default)]
    pub from: Option<i64>,
    /// Exclusive epoch-ms upper bound.
    #[serde(default)]
    pub to: Option<i64>,
    /// `day` (default) · `model` · `lane` · `backend`
    #[serde(default)]
    pub group: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageTotals {
    pub turns: i64,
    pub turns_without_tokens: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_read_tokens: i64,
    pub cached_write_tokens: i64,
    pub reported_cost: f64,
    pub reported_cost_turns: i64,
    /// Absent when no row in the bucket matched a rate — never zero, which
    /// would read as "this was free".
    pub estimated_cost: Option<f64>,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageBucket {
    pub key: String,
    #[serde(flatten)]
    pub totals: UsageTotals,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageResponse {
    pub project: String,
    pub group: String,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub totals: UsageTotals,
    pub buckets: Vec<UsageBucket>,
    /// Models present in the range that no rate matched. Named so a blank
    /// estimate is legible as a missing rate rather than as a zero bill.
    pub unpriced: Vec<String>,
}

/// One row's worth of aggregation input, kept so pricing can run per model
/// (which is the only granularity at which a rate means anything) before the
/// buckets are collapsed.
struct Accum {
    totals: UsageTotals,
    /// model → tokens, for pricing.
    by_model: BTreeMap<String, Tokens>,
}

impl Accum {
    fn new() -> Self {
        Self {
            totals: UsageTotals {
                currency: "USD".to_string(),
                ..Default::default()
            },
            by_model: BTreeMap::new(),
        }
    }

    fn add(&mut self, row: &AggRow) {
        self.totals.turns += 1;
        if !row.has_tokens {
            self.totals.turns_without_tokens += 1;
        } else {
            self.totals.input_tokens += row.input;
            self.totals.output_tokens += row.output;
            self.totals.cached_read_tokens += row.cached_read;
            self.totals.cached_write_tokens += row.cached_write;
            let entry = self
                .by_model
                .entry(row.model.clone().unwrap_or_default())
                .or_insert(Tokens {
                    input: 0,
                    output: 0,
                    cached_read: 0,
                    cached_write: 0,
                });
            entry.input += row.input;
            entry.output += row.output;
            entry.cached_read += row.cached_read;
            entry.cached_write += row.cached_write;
        }
        if let Some(amount) = row.cost_amount {
            self.totals.reported_cost += amount;
            self.totals.reported_cost_turns += 1;
            if let Some(currency) = &row.cost_currency {
                self.totals.currency = currency.clone();
            }
        }
    }

    /// Price what can be priced. `estimated_cost` stays `None` until at least
    /// one model in the bucket matched, so an all-unpriced bucket renders blank
    /// rather than as `0.00`.
    fn finish(
        mut self,
        prices: &crate::price::PriceTable,
        unpriced: &mut Vec<String>,
    ) -> UsageTotals {
        let mut estimate: Option<f64> = None;
        for (model, tokens) in &self.by_model {
            match prices.estimate(model, *tokens) {
                Some(Money { amount, currency }) => {
                    *estimate.get_or_insert(0.0) += amount;
                    if self.totals.reported_cost_turns == 0 {
                        self.totals.currency = currency;
                    }
                }
                None => {
                    if !model.is_empty() && !unpriced.contains(model) {
                        unpriced.push(model.clone());
                    }
                }
            }
        }
        self.totals.estimated_cost = estimate;
        self.totals
    }
}

struct AggRow {
    bucket: String,
    model: Option<String>,
    has_tokens: bool,
    input: i64,
    output: i64,
    cached_read: i64,
    cached_write: i64,
    cost_amount: Option<f64>,
    cost_currency: Option<String>,
}

/// `GET /v1/projects/{project}/usage`
async fn read_usage(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Query(query): Query<UsageQuery>,
) -> AppResult<Json<UsageResponse>> {
    let conn = state.db();
    let actor = auth::authenticate(&conn, &headers)?;
    let project_id = readable_project(&conn, actor.as_ref(), &project)?;
    let response = aggregate(&conn, &state.prices, &project, &project_id, &query)?;
    Ok(Json(response))
}

pub fn aggregate(
    conn: &Connection,
    prices: &crate::price::PriceTable,
    project_slug: &str,
    project_id: &str,
    query: &UsageQuery,
) -> AppResult<UsageResponse> {
    let group = query.group.as_deref().unwrap_or("day");
    // The bucket expression is chosen from a fixed set, never interpolated from
    // the request — a group-by is the one place a string from a query parameter
    // would otherwise reach SQL.
    let bucket_sql = match group {
        "day" => "strftime('%Y-%m-%d', at / 1000, 'unixepoch')",
        "model" => "coalesce(model, '')",
        "lane" => "lane",
        "backend" => "backend",
        other => {
            return Err(AppError::bad_request(
                "invalid_group",
                format!("unknown group '{other}' — expected day, model, lane, or backend"),
            ))
        }
    };

    let sql = format!(
        "SELECT {bucket_sql} AS bucket, model, has_tokens,
                coalesce(input_tokens, 0), coalesce(output_tokens, 0),
                coalesce(cached_read, 0), coalesce(cached_write, 0),
                cost_amount, cost_currency
         FROM usage_turn
         WHERE project_id = ?1
           AND (?2 IS NULL OR at >= ?2)
           AND (?3 IS NULL OR at < ?3)"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![project_id, query.from, query.to], |r| {
        Ok(AggRow {
            bucket: r.get(0)?,
            model: r.get(1)?,
            has_tokens: r.get::<_, i64>(2)? != 0,
            input: r.get(3)?,
            output: r.get(4)?,
            cached_read: r.get(5)?,
            cached_write: r.get(6)?,
            cost_amount: r.get(7)?,
            cost_currency: r.get(8)?,
        })
    })?;

    let mut overall = Accum::new();
    let mut buckets: BTreeMap<String, Accum> = BTreeMap::new();
    for row in rows {
        let row = row?;
        overall.add(&row);
        buckets
            .entry(row.bucket.clone())
            .or_insert_with(Accum::new)
            .add(&row);
    }

    let mut unpriced = Vec::new();
    let totals = overall.finish(prices, &mut unpriced);
    let mut out: Vec<UsageBucket> = buckets
        .into_iter()
        .map(|(key, accum)| UsageBucket {
            key,
            totals: accum.finish(prices, &mut Vec::new()),
        })
        .collect();
    // Days read best newest-first; every other grouping reads best by weight.
    if group == "day" {
        out.sort_by(|a, b| b.key.cmp(&a.key));
    } else {
        out.sort_by(|a, b| {
            b.totals
                .turns
                .cmp(&a.totals.turns)
                .then_with(|| a.key.cmp(&b.key))
        });
    }

    Ok(UsageResponse {
        project: project_slug.to_string(),
        group: group.to_string(),
        from: query.from,
        to: query.to,
        totals,
        buckets: out,
        unpriced,
    })
}

// ------------------------------------------------------------- recent turns

/// One turn, as stored. The aggregates above answer "what did this cost"; this
/// answers "which turn was that" — the row a person points at when a number
/// looks wrong, and the only place the fields that cannot be summed (stop
/// reason, origin, context level, whether the model id was confirmed) are
/// visible at all.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnDetail {
    pub at: i64,
    pub duration_ms: Option<i64>,
    pub lane: String,
    pub backend: String,
    pub model: Option<String>,
    pub model_confirmed: bool,
    pub stop_reason: String,
    pub origin: String,
    pub has_tokens: bool,
    pub input: i64,
    pub output: i64,
    pub cached_read: i64,
    pub cached_write: i64,
    pub context_used: Option<i64>,
    pub context_size: Option<i64>,
    pub cost_amount: Option<f64>,
    pub cost_currency: Option<String>,
}

/// Newest turns first, within the same range the totals cover.
///
/// `limit` is a page's worth, not a window onto the whole table: a project with
/// a year of turns must not render a year of rows. The ordering matches
/// `usage_turn_time_idx`, so this stays an index scan of `limit` rows however
/// many are stored. `rowid` breaks the tie, so two turns that ended in the same
/// millisecond keep a stable order between loads instead of swapping places.
pub fn recent_turns(
    conn: &Connection,
    project_id: &str,
    from: Option<i64>,
    limit: i64,
) -> AppResult<Vec<TurnDetail>> {
    let mut stmt = conn.prepare(
        "SELECT at, duration_ms, lane, backend, model, model_confirmed,
                stop_reason, origin, has_tokens,
                coalesce(input_tokens, 0), coalesce(output_tokens, 0),
                coalesce(cached_read, 0), coalesce(cached_write, 0),
                context_used, context_size, cost_amount, cost_currency
         FROM usage_turn
         WHERE project_id = ?1 AND (?2 IS NULL OR at >= ?2)
         ORDER BY at DESC, rowid DESC
         LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![project_id, from, limit], |r| {
        Ok(TurnDetail {
            at: r.get(0)?,
            duration_ms: r.get(1)?,
            lane: r.get(2)?,
            backend: r.get(3)?,
            model: r.get(4)?,
            model_confirmed: r.get::<_, i64>(5)? != 0,
            stop_reason: r.get(6)?,
            origin: r.get(7)?,
            has_tokens: r.get::<_, i64>(8)? != 0,
            input: r.get(9)?,
            output: r.get(10)?,
            cached_read: r.get(11)?,
            cached_write: r.get(12)?,
            context_used: r.get(13)?,
            context_size: r.get(14)?,
            cost_amount: r.get(15)?,
            cost_currency: r.get(16)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn row(id: &str, at: i64, model: &str, lane: &str, input: i64, output: i64) -> TurnRow {
        TurnRow {
            v: 1,
            id: id.to_string(),
            at,
            duration_ms: Some(1000),
            hostname: "mbp".to_string(),
            harness_id: "hm-1".to_string(),
            lane: lane.to_string(),
            backend: "claude".to_string(),
            model: Some(model.to_string()),
            model_confirmed: true,
            session_id: Some("s1".to_string()),
            turn: 1,
            stop_reason: "end_turn".to_string(),
            origin: "user".to_string(),
            tokens: Some(TurnTokens {
                input,
                output,
                cached_read: Some(1000),
                cached_write: None,
                thought: None,
                total: None,
            }),
            context: None,
            cost: None,
        }
    }

    fn seeded() -> Connection {
        let conn = db::open_in_memory().unwrap();
        conn.execute(
            "INSERT INTO user (id, email, display_name, password_hash, is_admin, created_at)
             VALUES ('u1', 'a@b.c', 'A', 'x', 1, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO project (id, slug, owner_id, is_public, created_at)
             VALUES ('p1', 'wk-j.krypton', 'u1', 0, 0)",
            [],
        )
        .unwrap();
        conn
    }

    fn prices() -> crate::price::PriceTable {
        crate::price::PriceTable::from_json(
            r#"[{ "match": "opus*", "input": 15.0, "output": 75.0, "cached_read": 1.5 }]"#,
        )
        .unwrap()
    }

    /// The whole point of a client-generated id: a client that could not tell
    /// whether its POST landed re-sends, and must not be billed twice for it.
    #[test]
    fn re_sending_a_row_is_a_duplicate_not_a_second_charge() {
        let conn = seeded();
        let r = row("usg-1", 1_786_233_600_000, "opus-5", "Claude-1", 100, 10);
        assert!(insert_turn(&conn, "p1", "u1", 1, &r).unwrap());
        assert!(!insert_turn(&conn, "p1", "u1", 2, &r).unwrap());

        let totals = aggregate(
            &conn,
            &prices(),
            "wk-j.krypton",
            "p1",
            &UsageQuery {
                from: None,
                to: None,
                group: None,
            },
        )
        .unwrap()
        .totals;
        assert_eq!(totals.turns, 1);
        assert_eq!(totals.input_tokens, 100);
    }

    /// A turn whose adapter reported nothing is a turn that happened. Counting
    /// it as zero tokens would make an unmeasured lane look like an idle one.
    #[test]
    fn a_turn_without_counters_is_counted_but_contributes_no_tokens() {
        let conn = seeded();
        let mut blind = row("usg-1", 1_786_233_600_000, "gemini-3", "Gemini-1", 0, 0);
        blind.tokens = None;
        insert_turn(&conn, "p1", "u1", 1, &blind).unwrap();
        insert_turn(
            &conn,
            "p1",
            "u1",
            1,
            &row("usg-2", 1_786_233_600_000, "opus-5", "Claude-1", 50, 5),
        )
        .unwrap();

        let totals = aggregate(
            &conn,
            &prices(),
            "wk-j.krypton",
            "p1",
            &UsageQuery {
                from: None,
                to: None,
                group: None,
            },
        )
        .unwrap()
        .totals;
        assert_eq!(totals.turns, 2);
        assert_eq!(totals.turns_without_tokens, 1);
        assert_eq!(totals.input_tokens, 50);
    }

    #[test]
    fn grouping_by_day_buckets_on_the_turns_own_timestamp() {
        let conn = seeded();
        let day1 = 1_786_233_600_000; // 2026-08-09T00:00:00Z
        insert_turn(&conn, "p1", "u1", 1, &row("a", day1, "opus-5", "L", 1, 1)).unwrap();
        insert_turn(
            &conn,
            "p1",
            "u1",
            1,
            &row("b", day1 + 86_400_000, "opus-5", "L", 1, 1),
        )
        .unwrap();

        let out = aggregate(
            &conn,
            &prices(),
            "wk-j.krypton",
            "p1",
            &UsageQuery {
                from: None,
                to: None,
                group: Some("day".into()),
            },
        )
        .unwrap();
        assert_eq!(out.buckets.len(), 2);
        // Newest first: a usage page is read from today backwards.
        assert_eq!(out.buckets[0].key, "2026-08-10");
        assert_eq!(out.buckets[1].key, "2026-08-09");
    }

    #[test]
    fn a_range_excludes_its_upper_bound_so_adjacent_days_do_not_double_count() {
        let conn = seeded();
        let day1 = 1_786_233_600_000;
        let day2 = day1 + 86_400_000;
        insert_turn(&conn, "p1", "u1", 1, &row("a", day1, "opus-5", "L", 1, 1)).unwrap();
        insert_turn(&conn, "p1", "u1", 1, &row("b", day2, "opus-5", "L", 1, 1)).unwrap();

        let out = aggregate(
            &conn,
            &prices(),
            "wk-j.krypton",
            "p1",
            &UsageQuery {
                from: Some(day1),
                to: Some(day2),
                group: None,
            },
        )
        .unwrap();
        assert_eq!(out.totals.turns, 1);
    }

    #[test]
    fn cost_is_estimated_from_the_rate_table_at_read_time() {
        let conn = seeded();
        insert_turn(
            &conn,
            "p1",
            "u1",
            1,
            &row("a", 1_786_233_600_000, "opus-5", "L", 1_000_000, 0),
        )
        .unwrap();

        let out = aggregate(
            &conn,
            &prices(),
            "wk-j.krypton",
            "p1",
            &UsageQuery {
                from: None,
                to: None,
                group: None,
            },
        )
        .unwrap();
        // 1M input at $15 + 1000 cached reads at $1.5/M.
        let estimated = out.totals.estimated_cost.expect("priced");
        assert!((estimated - (15.0 + 0.0015)).abs() < 1e-6, "{estimated}");
        assert_eq!(out.totals.reported_cost, 0.0);
        assert!(out.unpriced.is_empty());
    }

    /// A model no rate matches must leave the estimate BLANK and name itself,
    /// not silently price at zero.
    #[test]
    fn an_unpriced_model_is_named_and_leaves_the_estimate_absent() {
        let conn = seeded();
        insert_turn(
            &conn,
            "p1",
            "u1",
            1,
            &row("a", 1_786_233_600_000, "llama-9", "L", 1_000_000, 0),
        )
        .unwrap();

        let out = aggregate(
            &conn,
            &prices(),
            "wk-j.krypton",
            "p1",
            &UsageQuery {
                from: None,
                to: None,
                group: None,
            },
        )
        .unwrap();
        assert_eq!(out.totals.estimated_cost, None);
        assert_eq!(out.unpriced, vec!["llama-9".to_string()]);
    }

    #[test]
    fn reported_cost_is_kept_separate_from_the_estimate() {
        let conn = seeded();
        let mut r = row("a", 1_786_233_600_000, "opus-5", "L", 1_000_000, 0);
        r.cost = Some(TurnCost {
            amount: 0.42,
            currency: "USD".into(),
        });
        insert_turn(&conn, "p1", "u1", 1, &r).unwrap();

        let out = aggregate(
            &conn,
            &prices(),
            "wk-j.krypton",
            "p1",
            &UsageQuery {
                from: None,
                to: None,
                group: None,
            },
        )
        .unwrap();
        assert_eq!(out.totals.reported_cost, 0.42);
        assert_eq!(out.totals.reported_cost_turns, 1);
        assert!(
            out.totals.estimated_cost.unwrap() > 15.0,
            "both are reported, never merged"
        );
    }

    #[test]
    fn a_group_the_server_does_not_know_is_rejected_rather_than_interpolated() {
        let conn = seeded();
        let err = aggregate(
            &conn,
            &prices(),
            "wk-j.krypton",
            "p1",
            &UsageQuery {
                from: None,
                to: None,
                group: Some("lane; DROP TABLE usage_turn".into()),
            },
        );
        assert!(err.is_err());
    }

    /// The ledger is read newest-first and must honour the same range the
    /// totals above it cover — a row visible under "today" that the totals did
    /// not count would make the page contradict itself.
    #[test]
    fn recent_turns_are_newest_first_and_obey_the_range() {
        let conn = seeded();
        let day1 = 1_786_233_600_000;
        for (i, at) in [day1, day1 + 86_400_000, day1 + 172_800_000]
            .into_iter()
            .enumerate()
        {
            insert_turn(
                &conn,
                "p1",
                "u1",
                1,
                &row(&format!("usg-{i}"), at, "opus-5", "Claude-1", 10, 1),
            )
            .unwrap();
        }

        let all = recent_turns(&conn, "p1", None, 50).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].at, day1 + 172_800_000, "newest first");
        assert_eq!(all[2].at, day1);

        let windowed = recent_turns(&conn, "p1", Some(day1 + 86_400_000), 50).unwrap();
        assert_eq!(windowed.len(), 2);

        // A limit is a page, not a filter: the newest rows survive it.
        let page = recent_turns(&conn, "p1", None, 1).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].at, day1 + 172_800_000);
    }

    /// A turn the adapter never measured still has to appear in the ledger,
    /// carrying its non-numeric facts. Rendering it as zero tokens would be a
    /// claim the server cannot make.
    #[test]
    fn a_turn_without_counters_still_appears_in_the_ledger() {
        let conn = seeded();
        let mut blind = row("usg-1", 1_786_233_600_000, "gemini-3", "Gemini-1", 0, 0);
        blind.tokens = None;
        blind.stop_reason = "max_tokens".to_string();
        insert_turn(&conn, "p1", "u1", 1, &blind).unwrap();

        let turns = recent_turns(&conn, "p1", None, 50).unwrap();
        assert_eq!(turns.len(), 1);
        assert!(!turns[0].has_tokens);
        assert_eq!(turns[0].stop_reason, "max_tokens");
        assert_eq!(turns[0].lane, "Gemini-1");
    }

    #[test]
    fn validation_names_what_is_wrong_and_rejects_a_future_row_version() {
        let mut r = row("a", 1, "opus-5", "L", 1, 1);
        r.v = 99;
        assert!(validate(&r).unwrap_err().contains("newer than this server"));

        let mut r = row("", 1_786_233_600_000, "opus-5", "L", 1, 1);
        r.id = String::new();
        assert!(validate(&r).is_err());

        let mut r = row("a", 0, "opus-5", "L", 1, 1);
        r.at = 0;
        assert!(validate(&r).unwrap_err().contains("epoch-ms"));

        assert!(validate(&row("a", 1_786_233_600_000, "opus-5", "L", 1, 1)).is_ok());
    }
}
