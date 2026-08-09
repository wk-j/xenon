// Xenon — model rate table and cost estimation (spec 214, ADR-0018).
//
// Cost is computed HERE, at read time, and never stored on a turn row. Provider
// prices change on the provider's schedule, not on the client's release
// schedule: pricing in the desktop app would freeze every already-sent row at
// whatever the table said that week, and pricing at ingest would freeze it at
// whatever the table said that day. Computing on read means editing one file
// re-prices all of history, which is the only version of this that stays true.
//
// A rate the table cannot supply is reported as absent, never as zero. A zero
// looks like a free model; a blank looks like what it is.
//
// The table's shape follows LiteLLM's `model_prices_and_context_window.json`
// (per-million rates, cached reads priced separately) and its matching follows
// Langfuse: a pattern per entry, first match wins, so `claude-opus-*` covers a
// family without naming every dated build.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// One priced model family. Rates are USD per MILLION tokens, the unit every
/// provider publishes, so a table entry can be checked against a price page
/// without arithmetic.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rate {
    /// Glob-ish pattern matched against the model id, case-insensitively.
    /// `*` matches any run of characters; there is no other metacharacter.
    pub r#match: String,
    #[serde(default)]
    pub input: f64,
    #[serde(default)]
    pub output: f64,
    /// Cache READS are cheaper than fresh input on every provider that has
    /// them; omitting this prices them as input, which overstates the bill.
    #[serde(default)]
    pub cached_read: Option<f64>,
    /// Cache WRITES are dearer than fresh input on Anthropic. Same reasoning.
    #[serde(default)]
    pub cached_write: Option<f64>,
    #[serde(default = "default_currency")]
    pub currency: String,
    /// Free-text provenance — a link to the provider's price page. Never used
    /// in arithmetic; it exists so a wrong number is traceable to its source.
    #[serde(default)]
    pub source: String,
}

fn default_currency() -> String {
    "USD".to_string()
}

#[derive(Debug, Clone, Default)]
pub struct PriceTable {
    rates: Vec<Rate>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tokens {
    pub input: i64,
    pub output: i64,
    pub cached_read: i64,
    pub cached_write: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Money {
    pub amount: f64,
    pub currency: String,
}

impl PriceTable {
    /// Load the table, or an empty one if the file is missing.
    ///
    /// A missing file is not an error: an operator who has not written rates
    /// gets blank estimate columns, which is honest. A file that exists but is
    /// malformed IS an error — silently pricing at zero because of a stray
    /// comma is exactly the failure this module is built to avoid.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                log::info!(
                    "no price table at {} — usage pages will show tokens without estimates",
                    path.display()
                );
                return Ok(Self::default());
            }
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        let table = Self::from_json(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
        log::info!(
            "loaded {} model rate(s) from {}",
            table.rates.len(),
            path.display()
        );
        Ok(table)
    }

    /// Parse a table from JSON text. Separate from [`load`] so a caller that
    /// already has the bytes — a test, or a future config-embedded table —
    /// does not have to go through the filesystem to get one.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let rates: Vec<Rate> = serde_json::from_str(text).map_err(|e| format!("{e}"))?;
        Ok(Self { rates })
    }

    pub fn is_empty(&self) -> bool {
        self.rates.is_empty()
    }

    /// The first entry whose pattern matches. Order in the file is priority, so
    /// a specific override goes above the family it overrides.
    pub fn rate_for(&self, model: &str) -> Option<&Rate> {
        let lowered = model.to_ascii_lowercase();
        self.rates
            .iter()
            .find(|rate| glob_match(&rate.r#match.to_ascii_lowercase(), &lowered))
    }

    /// `None` when no rate matches — the caller renders a blank, and names the
    /// model as unpriced so the gap is visible rather than assumed to be zero.
    pub fn estimate(&self, model: &str, tokens: Tokens) -> Option<Money> {
        let rate = self.rate_for(model)?;
        // An entry whose every rate is zero is an UNFILLED entry, not a free
        // model. `prices.example.json` ships exactly that shape — patterns with
        // zeros and a link to each provider's price page — so a copied-verbatim
        // table reports "no rate for this" instead of confidently billing $0.00.
        if rate.input == 0.0
            && rate.output == 0.0
            && rate.cached_read.unwrap_or(0.0) == 0.0
            && rate.cached_write.unwrap_or(0.0) == 0.0
        {
            return None;
        }
        // An unpriced cache tier falls back to the fresh-input rate rather than
        // to zero: overstating a cache read is a smaller lie than pricing it free.
        let cached_read_rate = rate.cached_read.unwrap_or(rate.input);
        let cached_write_rate = rate.cached_write.unwrap_or(rate.input);
        let amount = (tokens.input as f64 * rate.input
            + tokens.output as f64 * rate.output
            + tokens.cached_read as f64 * cached_read_rate
            + tokens.cached_write as f64 * cached_write_rate)
            / 1_000_000.0;
        Some(Money {
            amount,
            currency: rate.currency.clone(),
        })
    }
}

/// `*` wildcards only. Deliberately not a regex: a rate table is edited by
/// hand, and a mistyped regex fails in ways that are hard to see in a price.
fn glob_match(pattern: &str, value: &str) -> bool {
    let mut segments = pattern.split('*');
    let Some(first) = segments.next() else {
        return false;
    };
    if !value.starts_with(first) {
        return false;
    }
    let mut cursor = first.len();
    let mut last: Option<&str> = None;
    for segment in segments {
        last = Some(segment);
        if segment.is_empty() {
            continue;
        }
        match value[cursor..].find(segment) {
            Some(at) => cursor += at + segment.len(),
            None => return false,
        }
    }
    match last {
        // No `*` at all: the whole string had to be the literal.
        None => value.len() == first.len(),
        // A trailing `*` accepts anything after the last segment; a trailing
        // literal must land at the end.
        Some("") => true,
        Some(tail) => value.ends_with(tail) && cursor <= value.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> PriceTable {
        PriceTable {
            rates: serde_json::from_str(
                r#"[
                  { "match": "claude-opus-5-cheap", "input": 1.0, "output": 2.0 },
                  { "match": "claude-opus-*", "input": 15.0, "output": 75.0,
                    "cached_read": 1.5, "cached_write": 18.75 },
                  { "match": "gpt-5*", "input": 1.25, "output": 10.0, "currency": "USD" }
                ]"#,
            )
            .unwrap(),
        }
    }

    #[test]
    fn a_family_pattern_covers_dated_builds() {
        assert_eq!(
            table().rate_for("claude-opus-5-20260501").unwrap().input,
            15.0
        );
        assert_eq!(table().rate_for("GPT-5-mini").unwrap().input, 1.25);
    }

    /// File order is priority, so an override placed above its family wins —
    /// otherwise a specific rate could never be expressed.
    #[test]
    fn the_first_matching_entry_wins() {
        assert_eq!(table().rate_for("claude-opus-5-cheap").unwrap().input, 1.0);
    }

    #[test]
    fn an_unknown_model_is_unpriced_rather_than_free() {
        assert!(table().rate_for("llama-9").is_none());
        assert!(table()
            .estimate(
                "llama-9",
                Tokens {
                    input: 1_000_000,
                    output: 0,
                    cached_read: 0,
                    cached_write: 0
                }
            )
            .is_none());
    }

    #[test]
    fn each_token_class_is_priced_at_its_own_rate() {
        let money = table()
            .estimate(
                "claude-opus-5",
                Tokens {
                    input: 1_000_000,
                    output: 1_000_000,
                    cached_read: 1_000_000,
                    cached_write: 1_000_000,
                },
            )
            .unwrap();
        assert!((money.amount - (15.0 + 75.0 + 1.5 + 18.75)).abs() < 1e-9);
        assert_eq!(money.currency, "USD");
    }

    /// Pricing a cache read at zero would make a heavily-cached lane look free.
    /// Falling back to the input rate overstates it instead, which is visible.
    #[test]
    fn an_unpriced_cache_tier_falls_back_to_input_not_to_zero() {
        let money = table()
            .estimate(
                "gpt-5",
                Tokens {
                    input: 0,
                    output: 0,
                    cached_read: 1_000_000,
                    cached_write: 0,
                },
            )
            .unwrap();
        assert!((money.amount - 1.25).abs() < 1e-9);
    }

    /// The shipped example table is all zeros on purpose. Treating that as a
    /// real price would put a confident `$0.0000` next to every model an
    /// operator has not filled in yet — the exact failure this module exists
    /// to prevent.
    #[test]
    fn an_all_zero_entry_reads_as_unfilled_not_as_free() {
        let table = PriceTable::from_json(
            r#"[{ "match": "claude-opus-*", "input": 0, "output": 0, "cached_read": 0 }]"#,
        )
        .unwrap();
        assert!(
            table.rate_for("claude-opus-5").is_some(),
            "the pattern still matches"
        );
        assert_eq!(
            table.estimate(
                "claude-opus-5",
                Tokens {
                    input: 1_000_000,
                    output: 1_000_000,
                    cached_read: 0,
                    cached_write: 0
                }
            ),
            None
        );
    }

    /// The example file must stay loadable — it is what an operator copies.
    #[test]
    fn the_shipped_example_table_parses() {
        let table = PriceTable::load(Path::new("assets/prices.example.json")).unwrap();
        assert!(
            !table.is_empty(),
            "the example must contain patterns to copy"
        );
        assert!(
            table
                .estimate(
                    "claude-opus-5",
                    Tokens {
                        input: 1_000_000,
                        output: 0,
                        cached_read: 0,
                        cached_write: 0
                    }
                )
                .is_none(),
            "the example ships zeros, which must not price as free"
        );
    }

    #[test]
    fn a_missing_table_loads_empty_instead_of_failing() {
        let table = PriceTable::load(Path::new("/nonexistent/prices.json")).unwrap();
        assert!(table.is_empty());
    }

    #[test]
    fn glob_matching_is_anchored_at_both_ends() {
        assert!(glob_match("gpt-5*", "gpt-5-mini"));
        assert!(glob_match("gpt-5", "gpt-5"));
        assert!(!glob_match("gpt-5", "gpt-5-mini"));
        assert!(!glob_match("gpt-5*", "azure-gpt-5"));
        assert!(glob_match("*opus*", "claude-opus-5"));
        assert!(glob_match("*-5", "claude-opus-5"));
        assert!(!glob_match("*-5", "claude-opus-5-mini"));
    }
}
