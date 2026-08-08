// Xenon — one error type for every handler.
//
// Every failure carries a machine-readable `code` alongside the HTTP status, so
// clients (the Krypton publisher especially) can branch on the reason without
// parsing prose. The `message` is for humans and is never trusted by a client.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    /// Extra machine-readable detail, e.g. the list of digests still missing.
    pub detail: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<serde_json::Value>,
}

impl AppError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn unauthorized(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code, message)
    }

    pub fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    pub fn too_large(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // 5xx detail is logged, not returned — internal messages can name paths
        // and SQL, which a client has no business seeing.
        if self.status.is_server_error() {
            log::error!("{}: {}", self.code, self.message);
            return (
                self.status,
                Json(ErrorBody {
                    error: self.code,
                    message: "internal server error".to_string(),
                    detail: None,
                }),
            )
                .into_response();
        }
        (
            self.status,
            Json(ErrorBody {
                error: self.code,
                message: self.message,
                detail: self.detail,
            }),
        )
            .into_response()
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::internal(format!("database: {e}"))
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::internal(format!("io: {e}"))
    }
}

pub type AppResult<T> = Result<T, AppError>;
