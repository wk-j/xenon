// Xenon — central resource server for Krypton-generated resources.
//
// See docs/01-protocol.md for the wire contract, and the Krypton repo's
// docs/212-xenon-resource-server.md for the full design and its rationale.

pub mod account;
pub mod api;
pub mod assets;
pub mod auth;
pub mod blob;
pub mod config;
pub mod db;
pub mod error;
pub mod meta;
pub mod render;
pub mod state;
pub mod util;
pub mod web;

use axum::routing::get;
use axum::Router;
use std::sync::Arc;

use crate::state::AppState;

pub fn build_app(state: Arc<AppState>) -> Router {
    let max_blob_bytes = state.config.max_blob_bytes as usize;
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(api::routes(max_blob_bytes))
        .merge(account::routes())
        .merge(assets::routes())
        .merge(web::routes())
        .with_state(state)
}
