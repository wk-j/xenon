// Static frontend assets (spec docs/02-frontend-architecture.md, stage 2).
//
// CSS and JS live in `assets/` as real files you can open, lint, and diff —
// NOT as string constants inside a handler module. That separation is the whole
// point: `src/web.rs` grew a 139-line `STYLE` const and eight inline `<script>`
// blocks, and every UI change meant editing a Rust file.
//
// They are still baked into the binary at compile time with `include_str!`, so
// Xenon remains one static binary with no external services and nothing to
// deploy alongside it. `include_str!` rather than `rust-embed` because there are
// five files and no directory walk to do; the crate earns its place when the
// count grows, and swapping it in later does not change any URL.
//
// Extracting the scripts is also what makes a real Content-Security-Policy
// possible on the browse UI: inline scripts are why one cannot be set today.

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use std::sync::OnceLock;

use crate::state::AppState;
use crate::util::sha256_hex;

/// One served file: URL name, bytes, and MIME type.
struct Asset {
    name: &'static str,
    body: &'static str,
    content_type: &'static str,
}

const ASSETS: &[Asset] = &[
    Asset {
        name: "app.css",
        body: include_str!("../assets/app.css"),
        content_type: "text/css; charset=utf-8",
    },
    Asset {
        name: "app.js",
        body: include_str!("../assets/app.js"),
        content_type: "text/javascript; charset=utf-8",
    },
    Asset {
        name: "login.js",
        body: include_str!("../assets/login.js"),
        content_type: "text/javascript; charset=utf-8",
    },
    Asset {
        name: "register.js",
        body: include_str!("../assets/register.js"),
        content_type: "text/javascript; charset=utf-8",
    },
    Asset {
        name: "tokens.js",
        body: include_str!("../assets/tokens.js"),
        content_type: "text/javascript; charset=utf-8",
    },
];

/// Short content hash per asset, computed once. It rides in the query string so
/// a changed file gets a new URL — which is what makes `immutable` caching safe
/// here and nowhere else on this server.
///
/// `OnceLock` rather than `LazyLock`: the crate's MSRV is 1.77 and `LazyLock`
/// only stabilised in 1.80.
static FINGERPRINTS: OnceLock<Vec<String>> = OnceLock::new();

fn fingerprints() -> &'static [String] {
    FINGERPRINTS.get_or_init(|| ASSETS.iter().map(|a| tag(a.body)).collect())
}

fn tag(body: &str) -> String {
    sha256_hex(body.as_bytes())[..12].to_string()
}

fn index_of(name: &str) -> Option<usize> {
    ASSETS.iter().position(|a| a.name == name)
}

/// `/assets/app.css?v=<hash>` — the URL to put in a template.
pub fn url(name: &str) -> String {
    match index_of(name) {
        Some(i) => format!("/assets/{name}?v={}", fingerprints()[i]),
        // A typo must be loud in tests rather than silently 404 in a browser.
        None => {
            debug_assert!(false, "unknown asset: {name}");
            format!("/assets/{name}")
        }
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/assets/{name}", get(serve))
}

async fn serve(Path(name): Path<String>) -> Response {
    let Some(i) = index_of(&name) else {
        return (StatusCode::NOT_FOUND, "no such asset").into_response();
    };
    let asset = &ASSETS[i];
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, asset.content_type.to_string()),
            // Safe only because the URL carries a content hash: a changed file
            // is a different URL. Never apply this to a data-bearing route.
            (
                header::CACHE_CONTROL,
                "public, max-age=31536000, immutable".to_string(),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        ],
        asset.body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_asset_is_non_empty_and_uniquely_named() {
        let mut seen = std::collections::HashSet::new();
        for asset in ASSETS {
            assert!(!asset.body.is_empty(), "{} is empty", asset.name);
            assert!(seen.insert(asset.name), "duplicate asset: {}", asset.name);
        }
    }

    #[test]
    fn urls_carry_a_content_hash_that_tracks_the_body() {
        let css = url("app.css");
        assert!(css.starts_with("/assets/app.css?v="), "{css}");
        assert_ne!(
            tag("a"),
            tag("b"),
            "the fingerprint must change with the body"
        );
    }

    /// The CSS moved out of `src/web.rs`; guard the move so a future edit does
    /// not quietly reintroduce a rule there instead of in the stylesheet.
    #[test]
    fn the_stylesheet_still_carries_the_rules_the_pages_rely_on() {
        let css = ASSETS[index_of("app.css").unwrap()].body;
        for needed in [
            ":root{--bg:",
            ".artifact-open",
            ".rv-finding",
            ".rv-steps",
            ".rv-chart",
            "pre.rv-diff",
        ] {
            assert!(css.contains(needed), "app.css lost `{needed}`");
        }
    }

    #[test]
    fn the_shared_helpers_are_present_for_every_page_script() {
        let app = ASSETS[index_of("app.js").unwrap()].body;
        assert!(app.contains("function xreq") || app.contains("xreq("));
        assert!(app.contains("function xfail"));
        for page in ["login.js", "register.js", "tokens.js"] {
            let body = ASSETS[index_of(page).unwrap()].body;
            assert!(
                body.contains("xreq(") || body.contains("xfail("),
                "{page} should use the shared helpers"
            );
        }
    }
}
