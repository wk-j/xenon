// Typed-block post-pass over comrak output (spec docs/02-frontend-architecture.md, stage 1).
//
// A Krypton Review Board is ordinary Markdown plus typed fences —
// ```review:walkthrough, ```review:finding, ```review:decision, ```review:metrics,
// ```review:chart, ```review:svg, and a plain ```diff. comrak renders each of
// those as an anonymous grey code block, so without this pass a Board published
// to Xenon shows strictly less than the same Board open in Krypton.
//
// Ported from Krypton's `render_review_blocks` (src-tauri/src/hook_server.rs).
// The rendering logic is a port; the SECURITY POSTURE IS NOT. Krypton runs this
// on a loopback surface for the one local user who already owns the machine.
// Xenon serves the same agent-authored markup from an origin holding session
// cookies for several accounts, so an escaping omission that is cosmetic there
// is session-stealing XSS here. Every renderer below re-escapes what it emits;
// `render_rv_svg` is the single deliberate exception and is documented as such.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::web::escape;

/// Publish-time source snapshot from Krypton (`excerpts.json`, spec 230).
#[derive(Debug, Deserialize)]
pub struct ExcerptSidecar {
    pub version: u32,
    #[serde(default)]
    pub anchors: BTreeMap<String, ExcerptRecord>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ExcerptRecord {
    pub skip: Option<String>,
    pub file_lines: Option<usize>,
    pub label: Option<String>,
    pub first_line: Option<usize>,
    pub anchor_line: Option<usize>,
    pub lines: Option<Vec<String>>,
    pub omitted: Option<usize>,
    pub stale: Option<bool>,
}

pub struct ExcerptIndex {
    anchors: BTreeMap<String, ExcerptRecord>,
}

impl ExcerptIndex {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let sidecar: ExcerptSidecar = serde_json::from_slice(bytes).ok()?;
        if sidecar.version != 1 {
            return None;
        }
        Some(Self {
            anchors: sidecar.anchors,
        })
    }

    fn get(&self, key: &str) -> Option<&ExcerptRecord> {
        self.anchors.get(key.trim())
    }
}

/// Inverse of [`escape`] for the five entities it emits. comrak hands us a code
/// block body already HTML-escaped, so it is un-escaped once here and re-escaped
/// by each per-kind renderer. `&amp;` is undone LAST so `&amp;lt;` recovers as
/// the literal text `&lt;` rather than collapsing into `<`.
pub(crate) fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// Rewrite every recognized `<pre><code class="language-review:…">` block (and
/// plain `language-diff`) in comrak output into semantic HTML. String-level
/// because comrak's output for a code block is a fixed, predictable shape —
/// pinned by `comrak_fence_shape_is_what_this_pass_expects` below, so an upgrade
/// that changes it fails loudly instead of silently reverting every Board.
pub fn render_review_blocks(html: &str) -> String {
    render_review_blocks_with(html, None)
}

pub fn render_review_blocks_with(html: &str, excerpts: Option<&ExcerptIndex>) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    // comrak always emits the info string as a `language-` class on <code>.
    const OPEN: &str = "<pre><code class=\"language-";
    const CLOSE: &str = "</code></pre>";
    while let Some(start) = rest.find(OPEN) {
        let (before, from_open) = rest.split_at(start);
        out.push_str(before);
        let after_open = &from_open[OPEN.len()..];
        let Some(quote) = after_open.find('"') else {
            out.push_str(from_open);
            return out;
        };
        let lang = after_open[..quote].to_ascii_lowercase();
        let Some(body_start) = after_open[quote..].find('>').map(|i| quote + i + 1) else {
            out.push_str(from_open);
            return out;
        };
        let Some(body_end) = after_open[body_start..].find(CLOSE).map(|i| body_start + i) else {
            out.push_str(from_open);
            return out;
        };
        let body = unescape(&after_open[body_start..body_end]);
        let kind = lang.split_whitespace().next().unwrap_or("");
        match render_review_block(kind, &body, excerpts) {
            Some(rendered) => out.push_str(&rendered),
            // Unknown fence: keep comrak's plain code block verbatim.
            None => out.push_str(&from_open[..OPEN.len() + body_end + CLOSE.len()]),
        }
        rest = &after_open[body_end + CLOSE.len()..];
    }
    out.push_str(rest);
    out
}

/// Dispatch one fence body to its renderer. `None` ⇒ not a review block.
fn render_review_block(kind: &str, body: &str, excerpts: Option<&ExcerptIndex>) -> Option<String> {
    match kind {
        "review:walkthrough" => Some(render_rv_walkthrough(body, excerpts)),
        "review:finding" => Some(render_rv_finding(body, excerpts)),
        "review:decision" => Some(render_rv_decision(body)),
        "review:metrics" => Some(render_rv_metrics(body)),
        "review:chart" => Some(render_rv_chart(body)),
        "review:svg" => Some(render_rv_svg(body)),
        "diff" => Some(render_rv_diff(body)),
        // Forward-compatible: a newer lane's block renders as a labelled code
        // block rather than disappearing.
        other if other.starts_with("review:") => Some(format!(
            "<p class=\"rv-unknown\">{}</p><pre><code>{}</code></pre>",
            escape(other),
            escape(body)
        )),
        _ => None,
    }
}

/// Read a typed block body as flat `key: value` plus `key:`-headed indented
/// groups. Deliberately lenient in the same way Krypton's archive is: this is a
/// viewer, so it reads what the lane most reliably writes and shows the rest
/// as-is rather than failing.
fn rv_scalar(body: &str, key: &str) -> Option<String> {
    for line in body.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        let (k, v) = line.split_once(':')?;
        if !k.trim().eq_ignore_ascii_case(key) {
            continue;
        }
        let value = v.trim().trim_matches('"').trim_matches('\'').to_string();
        return if value.is_empty() { None } else { Some(value) };
    }
    None
}

/// The lines under a bare `key:`, trimmed. Empty when the key is absent or
/// carries an inline value.
///
/// A member line is either indented or a `- ` list item at column zero — both
/// are valid YAML and Krypton lanes write both, commonly mixing them (`- at:`
/// flush left with an indented `say:` under it). Anything else at column zero
/// starts the next key and ends the group. The Krypton `#reviews` archive
/// accepted this in spec 217; stopping at the first flush-left `-` left
/// `<ol class="rv-steps">` empty while the title still rendered.
fn rv_group(body: &str, key: &str) -> Vec<String> {
    let mut collecting = false;
    let mut out: Vec<String> = Vec::new();
    for line in body.lines() {
        let indented = line.starts_with(' ') || line.starts_with('\t');
        let trimmed = line.trim();
        if collecting {
            if trimmed.is_empty() {
                continue;
            }
            if !indented && !trimmed.starts_with('-') {
                break;
            }
            out.push(trimmed.to_string());
            continue;
        }
        if indented {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(key) && v.trim().is_empty() {
                collecting = true;
            }
        }
    }
    out
}

/// Strip one layer of surrounding quotes from a scalar an agent wrote.
fn rv_unquote(value: &str) -> String {
    let v = value.trim();
    if v.len() >= 2
        && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')))
    {
        return v[1..v.len() - 1].to_string();
    }
    v.to_string()
}

/// Walkthrough → an ordered list with a monospace anchor per step. When the
/// published revision carries `excerpts.json` (spec 230), the snapshot of
/// that `at:` is rendered underneath. Without a sidecar, anchors stay text.
fn render_rv_walkthrough(body: &str, excerpts: Option<&ExcerptIndex>) -> String {
    let mut out = String::new();
    if let Some(title) = rv_scalar(body, "title") {
        out.push_str("<div class=\"rv-steps__title\">");
        out.push_str(&escape(&rv_unquote(&title)));
        out.push_str("</div>");
    }
    struct Step {
        at: Option<String>,
        says: Vec<String>,
    }
    let mut steps: Vec<Step> = Vec::new();
    for line in rv_group(body, "steps") {
        if let Some(at) = line
            .strip_prefix("- at:")
            .or_else(|| line.strip_prefix("-at:"))
        {
            steps.push(Step {
                at: Some(rv_unquote(at)),
                says: Vec::new(),
            });
        } else if let Some(say) = line.strip_prefix("say:") {
            match steps.last_mut() {
                Some(step) => step.says.push(rv_unquote(say)),
                None => steps.push(Step {
                    at: None,
                    says: vec![rv_unquote(say)],
                }),
            }
        } else if let Some(bare) = line.strip_prefix("- ") {
            steps.push(Step {
                at: None,
                says: vec![rv_unquote(bare)],
            });
        }
    }
    out.push_str("<ol class=\"rv-steps\">");
    for step in &steps {
        out.push_str("<li>");
        if let Some(at) = &step.at {
            out.push_str("<span class=\"rv-step__at\">");
            out.push_str(&escape(at));
            out.push_str("</span>");
        }
        for say in &step.says {
            out.push_str("<span class=\"rv-step__say\">");
            out.push_str(&escape(say));
            out.push_str("</span>");
        }
        if let Some(at) = &step.at {
            out.push_str(&render_rv_source(at, excerpts));
        }
        out.push_str("</li>");
    }
    out.push_str("</ol>");
    out
}

/// Finding → a bordered card with the severity carried by a text chip AND the
/// heading colour. Never a left accent rail, and never colour alone: the chip is
/// what a colour-blind reader (or a printed page) has to go on.
fn render_rv_finding(body: &str, excerpts: Option<&ExcerptIndex>) -> String {
    let severity = rv_scalar(body, "severity")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "non-blocking".to_string());
    let (tone, chip) = match severity.as_str() {
        "blocking" => ("blocking", "BLOCK"),
        "suggestion" => ("sugg", "SUGG"),
        _ => ("warn", "WARN"),
    };
    let title = rv_scalar(body, "title").unwrap_or_else(|| "(untitled finding)".to_string());
    let anchor = match (rv_scalar(body, "file"), rv_scalar(body, "line")) {
        (Some(file), Some(line)) => Some(format!("{file}:{line}")),
        (Some(file), None) => Some(file),
        _ => None,
    };
    let mut out = format!(
        "<div class=\"rv-finding rv-finding--{tone}\"><div class=\"rv-finding__head\"><span class=\"rv-finding__sev\">{chip}</span><span class=\"rv-finding__title\">{}</span>",
        escape(&rv_unquote(&title))
    );
    let mut source = String::new();
    if let Some(anchor) = anchor {
        let anchor = rv_unquote(&anchor);
        out.push_str("<span class=\"rv-finding__at\">");
        out.push_str(&escape(&anchor));
        out.push_str("</span>");
        source = render_rv_source(&anchor, excerpts);
    }
    out.push_str("</div>");
    out.push_str(&source);
    out.push_str("</div>");
    out
}

fn render_rv_source(key: &str, excerpts: Option<&ExcerptIndex>) -> String {
    let Some(index) = excerpts else {
        return String::new();
    };
    let Some(record) = index.get(key) else {
        return String::new();
    };
    match record.skip.as_deref() {
        Some("missing") => rv_src_notice(key, "ไฟล์นี้ไม่มีแล้ว"),
        Some("drifted") => {
            let n = record.file_lines.unwrap_or(0);
            rv_src_notice(key, &format!("บรรทัดนี้เลยท้ายไฟล์ — ตอนนี้ไฟล์มี {n} บรรทัด"))
        }
        Some(_) => String::new(),
        None => render_rv_excerpt(record),
    }
}

fn rv_src_notice(label: &str, reason: &str) -> String {
    format!(
        "<div class=\"rv-src rv-src--drifted\"><div class=\"rv-src__head\"><span>{}</span><span class=\"rv-src__chip\">{}</span></div></div>",
        escape(label),
        escape(reason)
    )
}

fn render_rv_excerpt(record: &ExcerptRecord) -> String {
    let Some(lines) = record.lines.as_ref() else {
        return String::new();
    };
    let first = record.first_line.unwrap_or(1);
    let stale = record.stale.unwrap_or(false);
    let mut out = String::from("<div class=\"rv-src");
    if stale {
        out.push_str(" rv-src--stale");
    }
    out.push_str("\"><div class=\"rv-src__head\"><span>");
    out.push_str(&escape(record.label.as_deref().unwrap_or("")));
    out.push_str("</span>");
    if stale {
        out.push_str("<span class=\"rv-src__chip\">ไฟล์เปลี่ยนหลังรีวิวนี้</span>");
    }
    out.push_str("</div><div class=\"rv-src__body\">");
    for (i, line) in lines.iter().enumerate() {
        let number = first + i;
        out.push_str(if record.anchor_line == Some(number) {
            "<div class=\"rv-src__line rv-src__line--anchor\"><span class=\"rv-src__ln\">"
        } else {
            "<div class=\"rv-src__line\"><span class=\"rv-src__ln\">"
        });
        out.push_str(&number.to_string());
        out.push_str("</span><span>");
        out.push_str(&escape(line));
        out.push_str("</span></div>");
    }
    out.push_str("</div>");
    if record.omitted.unwrap_or(0) > 0 {
        out.push_str("<div class=\"rv-src__more\">อีก ");
        out.push_str(&record.omitted.unwrap_or(0).to_string());
        out.push_str(" บรรทัด</div>");
    }
    out.push_str("</div>");
    out
}

/// Decision → the question plus an ordered options list, the recommendation
/// marked. This shows the LANE's recommendation; the human's answer lives in the
/// bundle's `response.md`, which renders as ordinary markdown.
fn render_rv_decision(body: &str) -> String {
    let question = rv_scalar(body, "question").unwrap_or_else(|| "(no question)".to_string());
    let recommended: usize = rv_scalar(body, "recommended")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let mut out = format!(
        "<p class=\"rv-decision__question\">{}</p><ol class=\"rv-options\">",
        escape(&rv_unquote(&question))
    );
    let mut n = 0usize;
    for line in rv_group(body, "options") {
        let Some(text) = line.strip_prefix("- ") else {
            continue;
        };
        n += 1;
        out.push_str(if n == recommended {
            "<li class=\"is-chosen\">"
        } else {
            "<li>"
        });
        out.push_str(&escape(&rv_unquote(text)));
        if n == recommended {
            out.push_str("<span class=\"rv-option__rec\">rec</span>");
        }
        out.push_str("</li>");
    }
    out.push_str("</ol>");
    out
}

/// Metrics → a definition row strip.
fn render_rv_metrics(body: &str) -> String {
    let mut out = String::from("<dl class=\"rv-metrics\">");
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let (label, value) = match line.split_once(':') {
            Some((k, v)) => (k.trim(), rv_unquote(v)),
            None => (line.trim(), String::new()),
        };
        out.push_str("<dt>");
        out.push_str(&escape(label));
        out.push_str("</dt><dd>");
        out.push_str(&escape(&value));
        out.push_str("</dd>");
    }
    out.push_str("</dl>");
    out
}

/// Chart → label/value rows with proportional CSS bar widths. `line` and
/// `sparkline` render the same way: a browse surface shows the values, not the
/// shape.
fn render_rv_chart(body: &str) -> String {
    let mut rows: Vec<(String, f64)> = Vec::new();
    let mut pending_label: Option<String> = None;
    for line in rv_group(body, "data") {
        // Either `label: 152` (map form) or `- label: acp/` + `value: 152`.
        if let Some(rest) = line.strip_prefix("- ") {
            if let Some((k, v)) = rest.split_once(':') {
                if k.trim().eq_ignore_ascii_case("label") {
                    pending_label = Some(rv_unquote(v));
                    continue;
                }
                if let Ok(n) = rv_unquote(v).parse::<f64>() {
                    rows.push((rv_unquote(k), n));
                }
            }
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case("value") {
            if let (Some(label), Ok(n)) = (pending_label.take(), rv_unquote(v).parse::<f64>()) {
                rows.push((label, n));
            }
            continue;
        }
        if let Ok(n) = rv_unquote(v).parse::<f64>() {
            rows.push((rv_unquote(k), n));
        }
    }

    let mut out = String::from("<div class=\"rv-chart\">");
    if let Some(title) = rv_scalar(body, "title") {
        out.push_str("<div class=\"rv-chart__title\">");
        out.push_str(&escape(&rv_unquote(&title)));
        out.push_str("</div>");
    }
    // Scale against a zero-anchored max, so a bar's width is proportional to its
    // value rather than to its distance from the smallest (the truncated-axis
    // anti-pattern). Magnitudes only — a negative value reads by its label.
    let max = rows.iter().fold(0f64, |m, (_, v)| m.max(v.abs()));
    for (label, value) in &rows {
        let pct = if max > 0.0 {
            (value.abs() / max * 100.0).clamp(1.0, 100.0)
        } else {
            1.0
        };
        out.push_str("<div class=\"rv-chart__row\"><span class=\"rv-chart__label\">");
        out.push_str(&escape(label));
        out.push_str(
            "</span><span class=\"rv-chart__track\"><span class=\"rv-chart__bar\" style=\"width:",
        );
        out.push_str(&format!("{pct:.1}"));
        out.push_str("%\"></span></span><span class=\"rv-chart__value\">");
        out.push_str(&escape(&format_rv_number(*value)));
        out.push_str("</span></div>");
    }
    if rows.is_empty() {
        out.push_str("<pre><code>");
        out.push_str(&escape(body));
        out.push_str("</code></pre>");
    }
    out.push_str("</div>");
    out
}

/// Integers stay integral; fractions keep one decimal.
fn format_rv_number(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{}", value as i64)
    } else {
        format!("{value:.1}")
    }
}

/// SVG → the ONE path by which agent-authored markup reaches this origin
/// unescaped, so read the model carefully before changing it.
///
/// This is **refuse-whole-on-denylist**, NOT an allowlist: if nothing on the
/// list matches, the original body is emitted verbatim. A refused diagram
/// degrades to its escaped source, which still informs the reader.
///
/// Two checks deliberately run on different forms of the text. The substring
/// checks run on WHITESPACE-COMPACTED text so a split like `java\tscript:`
/// cannot slip through. The handler check runs on UN-compacted text, because
/// compaction would glue `onload` onto the preceding tag name and defeat the
/// attribute-boundary test.
///
/// Residual risk: a denylist is only as complete as its list. Accepted because
/// the input comes from our own agents rather than anonymous publishers, and
/// because refusal degrades safely. Revisit before Xenon accepts resources from
/// untrusted publishers.
fn render_rv_svg(body: &str) -> String {
    let lower = body.to_ascii_lowercase();
    let compact: String = lower.chars().filter(|c| !c.is_whitespace()).collect();
    let unsafe_svg = !lower.trim_start().starts_with("<svg")
        || compact.contains("<script")
        || compact.contains("<foreignobject")
        || compact.contains("<iframe")
        || compact.contains("javascript:")
        || compact.contains("data:text/html")
        || compact.contains("xlink:href")
        || has_event_handler_attribute(&lower)
        || compact.contains("url(http")
        || compact.contains("url(//");
    if unsafe_svg {
        return format!(
            "<p class=\"rv-unknown\">svg not rendered (failed the safety check)</p><pre><code>{}</code></pre>",
            escape(body)
        );
    }
    format!("<div class=\"rv-svg\">{body}</div>")
}

/// Does this LOWERCASED (not compacted) markup contain an `on…=` event-handler
/// attribute? An attribute name always begins at a whitespace or `<`/`/`/quote
/// boundary, and HTML forbids whitespace inside the name, so a run like
/// `on load=` is two attributes rather than a handler. Errs toward refusing — a
/// false positive only degrades the diagram to its source.
fn has_event_handler_attribute(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut i = 0;
    while let Some(found) = lower[i..].find("on") {
        let at = i + found;
        let boundary_ok = at == 0
            || matches!(
                bytes[at - 1],
                b' ' | b'\t' | b'\n' | b'\r' | b'\x0c' | b'<' | b'/' | b'"' | b'\'' | b'-'
            );
        if boundary_ok {
            // `on` + one or more name chars, optional whitespace, then `=`.
            let mut j = at + 2;
            while j < bytes.len() && (bytes[j].is_ascii_alphabetic() || bytes[j] == b'-') {
                j += 1;
            }
            if j > at + 2 {
                let mut k = j;
                while k < bytes.len() && (bytes[k] as char).is_whitespace() {
                    k += 1;
                }
                if k < bytes.len() && bytes[k] == b'=' {
                    return true;
                }
            }
        }
        i = at + 2;
    }
    false
}

/// Diff → prefix-coloured lines in a plain `<pre>`.
fn render_rv_diff(body: &str) -> String {
    let mut out = String::from("<pre class=\"rv-diff\">");
    for line in body.lines() {
        let class = if line.starts_with("@@") {
            "rv-diff__hunk"
        } else if line.starts_with('+') {
            "rv-diff__add"
        } else if line.starts_with('-') {
            "rv-diff__del"
        } else {
            ""
        };
        if class.is_empty() {
            out.push_str("<span>");
        } else {
            out.push_str(&format!("<span class=\"{class}\">"));
        }
        // A blank line still needs to occupy a row.
        if line.is_empty() {
            out.push_str("&nbsp;");
        } else {
            out.push_str(&escape(line));
        }
        out.push_str("</span>");
    }
    out.push_str("</pre>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::markdown_to_html;

    /// The whole post-pass is a string walk keyed on comrak's code-block output.
    /// That shape is not a documented contract, so pin it: a comrak upgrade that
    /// changes it must fail HERE, loudly, rather than silently reverting every
    /// Board to grey code blocks.
    #[test]
    fn comrak_fence_shape_is_what_this_pass_expects() {
        let html = markdown_to_html("```review:finding\ntitle: x\n```\n");
        assert!(
            html.contains("<pre><code class=\"language-review:finding\">"),
            "comrak fence output changed — render_review_blocks needs updating; got: {html}"
        );
        assert!(html.contains("</code></pre>"));
    }

    // ── the security corpus: agent markup must never execute on this origin ──

    #[test]
    fn svg_with_a_script_element_is_refused_whole() {
        let out = render_rv_svg("<svg><script>alert(1)</script></svg>");
        assert!(out.contains("svg not rendered"));
        assert!(!out.contains("<script>"));
        assert!(
            out.contains("&lt;script&gt;"),
            "refused body must be escaped"
        );
    }

    #[test]
    fn svg_with_an_event_handler_is_refused() {
        assert!(render_rv_svg("<svg onload=\"alert(1)\"></svg>").contains("svg not rendered"));
        assert!(render_rv_svg("<svg><rect onclick='x()'/></svg>").contains("svg not rendered"));
    }

    #[test]
    fn whitespace_split_javascript_url_does_not_slip_through() {
        // The substring checks run on compacted text precisely for this.
        let out = render_rv_svg("<svg><a href=\"java\tscript:alert(1)\">x</a></svg>");
        assert!(out.contains("svg not rendered"));
    }

    #[test]
    fn on_word_in_prose_is_not_mistaken_for_a_handler() {
        // `on` followed by whitespace then `=` is two attributes, not a handler,
        // and a plain word starting with "on" must not trip the scan.
        let out = render_rv_svg("<svg><text>one on two</text></svg>");
        assert!(!out.contains("svg not rendered"), "false positive: {out}");
        assert!(out.contains("<div class=\"rv-svg\">"));
    }

    #[test]
    fn foreign_object_iframe_and_external_urls_are_refused() {
        for hostile in [
            "<svg><foreignObject><body>x</body></foreignObject></svg>",
            "<svg><iframe src=\"/x\"></iframe></svg>",
            "<svg><image xlink:href=\"x\"/></svg>",
            "<svg style=\"background:url(http://evil/x)\"></svg>",
            "<svg style=\"background:url(//evil/x)\"></svg>",
            "<svg><a href=\"data:text/html,<script>1</script>\">x</a></svg>",
        ] {
            assert!(
                render_rv_svg(hostile).contains("svg not rendered"),
                "should have been refused: {hostile}"
            );
        }
    }

    #[test]
    fn a_body_that_is_not_an_svg_at_all_is_refused() {
        assert!(render_rv_svg("<div>not an svg</div>").contains("svg not rendered"));
        assert!(render_rv_svg("").contains("svg not rendered"));
    }

    #[test]
    fn a_clean_svg_passes_through_verbatim() {
        let svg = "<svg viewBox=\"0 0 10 10\"><circle cx=\"5\" cy=\"5\" r=\"4\"/></svg>";
        assert_eq!(
            render_rv_svg(svg),
            format!("<div class=\"rv-svg\">{svg}</div>")
        );
    }

    #[test]
    fn every_other_renderer_escapes_agent_text() {
        // One hostile string, every renderer that interpolates agent input.
        const XSS: &str = "<img src=x onerror=alert(1)>";
        let rendered = [
            render_rv_finding(
                &format!("severity: blocking\ntitle: {XSS}\nfile: {XSS}"),
                None,
            ),
            render_rv_walkthrough(
                &format!("title: {XSS}\nsteps:\n  - at: {XSS}\n    say: {XSS}"),
                None,
            ),
            render_rv_decision(&format!("question: {XSS}\noptions:\n  - {XSS}")),
            render_rv_metrics(&format!("{XSS}: {XSS}")),
            render_rv_chart(&format!("title: {XSS}\ndata:\n  {XSS}: 1")),
            render_rv_diff(&format!("+{XSS}")),
        ];
        for html in rendered {
            assert!(!html.contains("<img"), "unescaped agent markup in: {html}");
            assert!(html.contains("&lt;img"), "expected escaped form in: {html}");
        }
    }

    #[test]
    fn unescape_does_not_collapse_double_encoded_entities() {
        // `&amp;lt;` is the literal text `&lt;`, not `<`. Undoing `&amp;` last
        // is what keeps a Board that quotes HTML from becoming live markup.
        assert_eq!(unescape("&amp;lt;script&amp;gt;"), "&lt;script&gt;");
    }

    // ── rendering behaviour ──

    #[test]
    fn an_unknown_review_fence_is_labelled_rather_than_dropped() {
        let html = render_review_blocks(&markdown_to_html(
            "```review:from-the-future\npayload\n```\n",
        ));
        assert!(html.contains("rv-unknown"));
        assert!(html.contains("review:from-the-future"));
        assert!(html.contains("payload"), "body must survive: {html}");
    }

    #[test]
    fn a_non_review_fence_is_left_exactly_as_comrak_wrote_it() {
        let comrak = markdown_to_html("```rust\nfn main() {}\n```\n");
        assert_eq!(render_review_blocks(&comrak), comrak);
    }

    #[test]
    fn prose_around_a_block_survives_and_the_fence_becomes_semantic() {
        let html = render_review_blocks(&markdown_to_html(
            "# Heading\n\ntext before\n\n```review:finding\nseverity: blocking\ntitle: it breaks\nfile: src/a.rs\nline: 12\n```\n\ntext after\n",
        ));
        assert!(html.contains("<h1>"));
        assert!(html.contains("text before"));
        assert!(html.contains("text after"));
        assert!(html.contains("rv-finding--blocking"));
        assert!(
            html.contains("BLOCK"),
            "severity needs a text chip, not colour alone"
        );
        assert!(html.contains("it breaks"));
        assert!(html.contains("src/a.rs:12"));
        assert!(
            !html.contains("language-review:finding"),
            "fence should be gone"
        );
    }

    #[test]
    fn an_unknown_severity_degrades_to_warn_rather_than_vanishing() {
        let html = render_rv_finding("severity: ร้ายแรง\ntitle: t", None);
        assert!(html.contains("rv-finding--warn"));
        assert!(html.contains("WARN"));
        assert!(html.contains("t"));
    }

    #[test]
    fn walkthrough_steps_render_in_order_with_anchors() {
        let html = render_rv_walkthrough(
            "title: tour\nsteps:\n  - at: src/a.rs:1\n    say: first\n  - at: src/b.rs:2\n    say: second\n",
            None,
        );
        assert_eq!(html.matches("<li>").count(), 2);
        let first = html.find("src/a.rs:1").unwrap();
        let second = html.find("src/b.rs:2").unwrap();
        assert!(first < second, "steps must keep document order");
        assert!(html.contains("first") && html.contains("second"));
    }

    #[test]
    fn walkthrough_reads_flush_left_list_items() {
        // The shape Krypton lanes actually write: `- at:` at column zero with
        // an indented `say:` under it. Requiring indent used to emit the title
        // plus an empty <ol class="rv-steps">.
        let html = render_rv_walkthrough(
            "title: tour\nsteps:\n- at: src/a.rs:1\n  say: first\n- at: src/b.rs:2\n  say: second\n",
            None,
        );
        assert_eq!(html.matches("<li>").count(), 2, "{html}");
        assert!(
            html.contains("src/a.rs:1") && html.contains("first"),
            "{html}"
        );
        assert!(
            html.contains("src/b.rs:2") && html.contains("second"),
            "{html}"
        );
        assert!(html.contains("rv-steps__title"));
    }

    #[test]
    fn sidecar_excerpts_render_under_walkthrough_and_finding() {
        let json = r#"{
            "version": 1,
            "anchors": {
                "src/a.rs:1": {
                    "label": "src/a.rs:1-3",
                    "first_line": 1,
                    "anchor_line": 1,
                    "lines": ["fn a() {}", "fn b() {}", "fn c() {}"],
                    "omitted": 0,
                    "stale": false
                },
                "src/gone.rs:9": { "skip": "missing" }
            }
        }"#;
        let index = ExcerptIndex::parse(json.as_bytes()).unwrap();
        let html = render_review_blocks_with(
            &markdown_to_html(
                "```review:walkthrough\nsteps:\n  - at: src/a.rs:1\n    say: here\n```\n\n```review:finding\nfile: src/gone.rs\nline: 9\ntitle: gone\n```\n",
            ),
            Some(&index),
        );
        assert!(html.contains("rv-src__line--anchor"), "{html}");
        assert!(html.contains("fn a() {}"), "{html}");
        assert!(html.contains("ไฟล์นี้ไม่มีแล้ว"), "{html}");
        assert!(!html.contains("border-left"));
    }

    #[test]
    fn sidecar_unknown_version_is_ignored() {
        assert!(ExcerptIndex::parse(br#"{"version": 2, "anchors": {}}"#).is_none());
    }

    #[test]
    fn decision_marks_the_recommended_option() {
        let html = render_rv_decision(
            "question: which?\noptions:\n  - keep it\n  - change it\nrecommended: 2\n",
        );
        assert!(html.contains("which?"));
        assert!(html.contains("<li class=\"is-chosen\">change it"));
        assert!(html.contains("rv-option__rec"));
    }

    #[test]
    fn chart_bars_are_proportional_to_a_zero_anchored_max() {
        let html = render_rv_chart("kind: bar\ndata:\n  a: 10\n  b: 5\n");
        assert!(
            html.contains("width:100.0%"),
            "largest is full width: {html}"
        );
        assert!(
            html.contains("width:50.0%"),
            "half the max is half wide: {html}"
        );
    }

    #[test]
    fn chart_without_parseable_data_falls_back_to_the_source() {
        let html = render_rv_chart("kind: bar\nnothing here\n");
        assert!(html.contains("<pre><code>"));
        assert!(html.contains("nothing here"));
    }

    #[test]
    fn metrics_render_every_row() {
        let html = render_rv_metrics("Reviewers: 1\nBlockers: 4\n");
        assert_eq!(html.matches("<dt>").count(), 2);
        assert!(html.contains("Reviewers") && html.contains("Blockers"));
    }

    #[test]
    fn diff_lines_are_classified_by_prefix() {
        let html = render_rv_diff("@@ -1 +1 @@\n-old\n+new\n unchanged");
        assert!(html.contains("rv-diff__hunk"));
        assert!(html.contains("rv-diff__del"));
        assert!(html.contains("rv-diff__add"));
    }

    #[test]
    fn thai_prose_survives_the_post_pass_intact() {
        // Boards are authored in Thai; the pass is byte-oriented, so guard the
        // multi-byte path explicitly rather than assuming it.
        let html = render_review_blocks(&markdown_to_html(
            "```review:finding\nseverity: blocking\ntitle: คิวลองใหม่ไม่เคยถูกอ่าน\n```\n",
        ));
        assert!(html.contains("คิวลองใหม่ไม่เคยถูกอ่าน"));
    }
}
