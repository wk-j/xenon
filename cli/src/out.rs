// Human-readable printing. `--json` skips this and dumps the server body.

use serde_json::Value;

pub fn json(value: &Value) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => println!("{text}"),
        Err(_) => println!("{value}"),
    }
}

pub fn table(headers: &[&str], rows: &[Vec<String>]) {
    if rows.is_empty() {
        println!("(none)");
        return;
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }
    let line = |cols: &[String]| {
        cols.iter()
            .enumerate()
            .map(|(i, cell)| {
                if i + 1 == cols.len() {
                    cell.clone()
                } else {
                    format!("{cell:<width$}", width = widths[i])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    println!(
        "{}",
        line(&headers.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
    );
    for row in rows {
        println!("{}", line(row));
    }
}

pub fn kv(pairs: &[(&str, String)]) {
    let width = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (key, value) in pairs {
        println!("{key:<width$}  {value}");
    }
}

pub fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("-")
        .to_string()
}

pub fn i64_field(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Null) | None => "-".to_string(),
        Some(other) => other.to_string(),
    }
}

pub fn bool_field(value: &Value, key: &str) -> String {
    match value.get(key).and_then(Value::as_bool) {
        Some(true) => "yes".to_string(),
        Some(false) => "no".to_string(),
        None => "-".to_string(),
    }
}

pub fn opt_text(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::Null) | None => "-".to_string(),
        Some(Value::String(s)) if s.is_empty() => "-".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// Unix seconds → `YYYY-MM-DD HH:MM:SS` UTC. Copied in spirit from the server
/// so the CLI does not have to link it.
pub fn ts(secs: i64) -> String {
    let day = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(day);
    let (h, min, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02}")
}

pub fn ts_field(value: &Value, key: &str) -> String {
    match value.get(key).and_then(Value::as_i64) {
        Some(secs) if secs > 0 => ts(secs),
        _ => "-".to_string(),
    }
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
