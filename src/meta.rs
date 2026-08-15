// Rendering for a revision's `meta` — the payload of a resource that has no files.
//
// The browse UI was built around files: `resource_page` picks one file from the
// revision and renders its bytes. That covers every kind but one, whose meta is
// a breadcrumb (`{"source": ".krypton/reviews"}`, `{"date": "2026-08-15"}`) and
// whose substance is on disk. `attention` is the exception — a judgement item has NO on-disk form, so
// its question, the option the lane chose, the rationale, the trade-offs and the
// stated uncertainty all travel in `meta` and nowhere else. Without this module
// such a resource renders as its title over "this revision has no files", which
// is the whole payload silently withheld from the reader.
//
// Nothing here may drop a field. Known keys are laid out in reading order and
// every remaining key falls through to a generic table, so a producer that adds
// a field gets it displayed rather than swallowed.

use serde_json::Value;

use crate::web::escape;

/// Keys `render_attention` lays out by hand; everything else falls through to
/// the generic table so a new field is never silently dropped.
const ATTENTION_KNOWN: [&str; 9] = [
    "question",
    "reversibility",
    "chosen",
    "rationale",
    "tradedOff",
    "uncertainty",
    "laneName",
    "laneId",
    "createdAt",
];

/// Render `meta` for a resource whose revision carries no files.
///
/// `title` is the page heading (the resource title), passed in so a field that
/// merely repeats it is not printed twice. Returns `None` when there is nothing
/// to show, leaving the caller's own empty state in place.
pub fn render_meta(kind: &str, meta: &Value, title: &str) -> Option<String> {
    let object = meta.as_object()?;
    if object.is_empty() {
        return None;
    }
    let html = match kind {
        "attention" => render_attention(object, title),
        _ => render_generic(object, &[]),
    };
    if html.is_empty() {
        None
    } else {
        Some(html)
    }
}

/// An attention flag (Krypton's `attention_flag`, spec 128 / ADR-0001): one
/// decision a lane made on its own and wants a human to weigh in on.
///
/// Laid out in the order the reader needs it — what was decided and how hard it
/// is to undo first, then why, then what it cost and what is still unsettled.
fn render_attention(object: &serde_json::Map<String, Value>, title: &str) -> String {
    let mut out = String::from("<section class=\"jdg\">");

    // Reversibility drives triage, so it leads. A text chip carries it as well
    // as the colour — the house rule is never colour alone (see render.rs).
    if let Some(rev) = string_of(object.get("reversibility")) {
        let tone = match rev.to_ascii_lowercase().as_str() {
            "irreversible" => "irreversible",
            "costly" => "costly",
            _ => "reversible",
        };
        out.push_str(&format!(
            "<p class=\"jdg__tier jdg__tier--{tone}\">{}</p>",
            escape(&rev)
        ));
    }

    // The resource title is the question, truncated to 300 chars on the way in.
    // Print the field only when it actually says more than the heading already.
    if let Some(question) = string_of(object.get("question")) {
        if question.trim() != title.trim() {
            out.push_str(&field("question", &escape(&question)));
        }
    }

    for key in ["chosen", "rationale"] {
        if let Some(value) = string_of(object.get(key)) {
            out.push_str(&field(key, &escape(&value)));
        }
    }

    if let Some(items) = list_of(object.get("tradedOff")) {
        let mut list = String::from("<ul class=\"jdg__list\">");
        for item in items {
            list.push_str(&format!("<li>{}</li>", escape(&item)));
        }
        list.push_str("</ul>");
        out.push_str(&field("traded off", &list));
    }

    if let Some(value) = string_of(object.get("uncertainty")) {
        out.push_str(&field("uncertainty", &escape(&value)));
    }

    // Provenance last: useful for attribution, never the reason you opened this.
    let lane = string_of(object.get("laneName")).or_else(|| string_of(object.get("laneId")));
    let created = object.get("createdAt").and_then(|v| v.as_i64());
    if lane.is_some() || created.is_some() {
        let mut bits: Vec<String> = Vec::new();
        if let Some(lane) = lane {
            bits.push(format!("lane {}", escape(&lane)));
        }
        if let Some(created) = created {
            bits.push(escape(&utc_stamp(created)));
        }
        out.push_str(&format!("<p class=\"meta\">{}</p>", bits.join(" · ")));
    }

    out.push_str("</section>");
    out.push_str(&render_generic(object, &ATTENTION_KNOWN));
    out
}

/// Every key not already laid out, as a plain two-column table. This is the
/// no-field-left-behind path: an unknown kind renders here in full, and a known
/// kind renders whatever its producer added since this code was written.
fn render_generic(object: &serde_json::Map<String, Value>, skip: &[&str]) -> String {
    let rows: Vec<(&String, &Value)> = object
        .iter()
        .filter(|(k, _)| !skip.contains(&k.as_str()))
        .filter(|(_, v)| !v.is_null())
        .collect();
    if rows.is_empty() {
        return String::new();
    }
    let mut out = String::from("<table class=\"kv\"><tbody>");
    for (key, value) in rows {
        out.push_str(&format!(
            "<tr><th>{}</th><td>{}</td></tr>",
            escape(key),
            render_value(value)
        ));
    }
    out.push_str("</tbody></table>");
    out
}

/// One JSON value as HTML. Scalars inline; anything structured as pretty JSON,
/// which is honest about the shape rather than flattening it into prose.
fn render_value(value: &Value) -> String {
    match value {
        Value::String(s) => escape(s),
        Value::Bool(b) => escape(&b.to_string()),
        Value::Number(n) => escape(&n.to_string()),
        Value::Array(items) if items.iter().all(|i| i.is_string()) => {
            let mut out = String::from("<ul class=\"jdg__list\">");
            for item in items {
                out.push_str(&format!(
                    "<li>{}</li>",
                    escape(item.as_str().unwrap_or_default())
                ));
            }
            out.push_str("</ul>");
            out
        }
        other => format!(
            "<pre class=\"kv__json\">{}</pre>",
            escape(&serde_json::to_string_pretty(other).unwrap_or_else(|_| other.to_string()))
        ),
    }
}

/// A labelled block. `body` is already-escaped HTML.
fn field(label: &str, body: &str) -> String {
    format!(
        "<div class=\"jdg__field\"><h3>{}</h3><div class=\"jdg__body\">{body}</div></div>",
        escape(label)
    )
}

/// `1786195508583` → `2026-08-08 13:25 UTC`.
///
/// Krypton stamps an attention flag with `Date.now()`, i.e. milliseconds, while
/// the server's own columns are seconds; the magnitude tells them apart, so a
/// producer that switches units does not start rendering dates in 1970. Done by
/// hand rather than by adding a date crate for one line of output — the civil
/// calendar from a day count is a closed-form calculation (Howard Hinnant's
/// `civil_from_days`), and Xenon stays a no-new-dependency binary.
fn utc_stamp(raw: i64) -> String {
    // Anything past ~2001 in seconds is beyond 1e9; a millisecond stamp of the
    // same era is beyond 1e12. Nothing this server stores predates that.
    let secs = if raw.abs() >= 100_000_000_000 {
        raw / 1000
    } else {
        raw
    };
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let (hour, minute) = (time_of_day / 3600, (time_of_day % 3600) / 60);

    // civil_from_days: shift the epoch to 0000-03-01 so leap day lands last.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = era * 400 + yoe + i64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

fn string_of(value: Option<&Value>) -> Option<String> {
    let s = value?.as_str()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn list_of(value: Option<&Value>) -> Option<Vec<String>> {
    let items: Vec<String> = value?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if items.is_empty() {
        None
    } else {
        Some(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn attention_meta() -> Value {
        json!({
            "id": "jdg-1",
            "laneId": "claude-1",
            "laneName": "Claude-1",
            "createdAt": 1786195508583i64,
            "question": "Which one?",
            "chosen": "The first",
            "rationale": "Because it is simpler",
            "tradedOff": ["The second, too slow", "The third, unproven"],
            "uncertainty": "Whether load matters",
            "reversibility": "costly"
        })
    }

    /// The bug this module exists to fix: an attention flag's payload lives only
    /// in `meta`, so every field must reach the page.
    #[test]
    fn an_attention_flag_renders_every_field_it_carries() {
        let html = render_meta("attention", &attention_meta(), "Which one?").expect("some html");
        for expected in [
            "The first",
            "Because it is simpler",
            "The second, too slow",
            "The third, unproven",
            "Whether load matters",
            "costly",
            "Claude-1",
        ] {
            assert!(html.contains(expected), "missing {expected} in {html}");
        }
    }

    /// The heading already prints the question; printing it again as a field
    /// reads like a rendering bug.
    #[test]
    fn the_question_is_not_repeated_under_its_own_heading() {
        let html = render_meta("attention", &attention_meta(), "Which one?").expect("some html");
        assert_eq!(html.matches("Which one?").count(), 0, "{html}");

        // …but a title truncated on the way in must not lose the full text.
        let html = render_meta("attention", &attention_meta(), "Which").expect("some html");
        assert!(html.contains("Which one?"), "{html}");
    }

    /// A field added by a future producer must show up rather than vanish.
    #[test]
    fn an_unknown_key_falls_through_to_the_generic_table() {
        let mut meta = attention_meta();
        meta["blastRadius"] = json!("3 files");
        let html = render_meta("attention", &meta, "Which one?").expect("some html");
        assert!(html.contains("blastRadius"), "{html}");
        assert!(html.contains("3 files"), "{html}");
    }

    /// Agent-authored text reaches this page from an origin holding session
    /// cookies, so an escaping omission here is XSS, not a cosmetic bug.
    #[test]
    fn agent_text_is_escaped_everywhere_it_lands() {
        let meta = json!({
            "question": "<img src=x onerror=alert(1)>",
            "chosen": "<script>alert(2)</script>",
            "tradedOff": ["<b>bold</b>"],
            "reversibility": "<svg onload=alert(3)>",
            "laneName": "<i>lane</i>",
            "extra": "<u>u</u>"
        });
        let html = render_meta("attention", &meta, "title").expect("some html");
        // No tag an agent wrote may survive as a tag. The words inside one
        // (`onerror=…`) are fine once the brackets are gone — they are then
        // just text in a text node, which is what escaping is for.
        for tag in ["<script", "<img", "<svg", "<b>", "<i>", "<u>"] {
            assert!(!html.contains(tag), "{tag} survived as markup in {html}");
        }
        assert!(html.contains("&lt;script&gt;"), "{html}");
        assert!(
            html.contains("&lt;img src=x onerror=alert(1)&gt;"),
            "{html}"
        );
    }

    /// An unknown kind still renders — the generic table is the floor, so no
    /// resource is ever a title over an empty page.
    #[test]
    fn an_unknown_kind_renders_its_meta_generically() {
        let html = render_meta("something-new", &json!({"a": 1, "b": "two"}), "t").expect("html");
        assert!(html.contains("two"), "{html}");
        assert!(html.contains('1'), "{html}");
    }

    #[test]
    fn timestamps_render_as_dates_in_either_unit() {
        // Krypton's `Date.now()` milliseconds…
        assert_eq!(utc_stamp(1_786_195_508_583), "2026-08-08 13:25 UTC");
        // …and the server's own seconds, which must not land in 1970.
        assert_eq!(utc_stamp(1_786_195_508), "2026-08-08 13:25 UTC");
        assert_eq!(utc_stamp(0), "1970-01-01 00:00 UTC");
        // A leap day, where an off-by-one in the civil calendar would show.
        assert_eq!(utc_stamp(1_709_164_800), "2024-02-29 00:00 UTC");
    }

    #[test]
    fn nothing_to_show_yields_none_so_the_caller_keeps_its_empty_state() {
        assert!(render_meta("attention", &json!({}), "t").is_none());
        assert!(render_meta("attention", &Value::Null, "t").is_none());
        assert!(render_meta("review", &json!("a string"), "t").is_none());
        // All-null values are as empty as no values.
        assert!(render_meta("review", &json!({ "a": null }), "t").is_none());
    }
}
