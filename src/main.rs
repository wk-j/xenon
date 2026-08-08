// Xenon — entry point.

use xenon::config::Config;
use xenon::state::AppState;
use xenon::{build_app, db};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // `--healthcheck` lets the container probe itself without shipping curl in
    // the runtime image.
    if std::env::args().any(|a| a == "--healthcheck") {
        std::process::exit(i32::from(!healthcheck()));
    }

    if let Err(message) = run().await {
        log::error!("{message}");
        std::process::exit(1);
    }
}

fn healthcheck() -> bool {
    use std::io::{Read, Write};

    let port = std::env::var("XENON_PORT").unwrap_or_else(|_| "8787".to_string());
    let timeout = std::time::Duration::from_secs(2);
    let Ok(addr) = format!("127.0.0.1:{port}").parse() else {
        return false;
    };
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(&addr, timeout) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    if stream
        .write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return false;
    }
    response.starts_with("HTTP/1.0 200") || response.starts_with("HTTP/1.1 200")
}

async fn run() -> Result<(), String> {
    let config = Config::from_env()?;
    log::info!(
        "starting xenon: data_dir={} max_blob={}MiB signup={}",
        config.data_dir.display(),
        config.max_blob_bytes / (1024 * 1024),
        if config.allow_signup {
            "open"
        } else {
            "invite-only"
        }
    );
    if config.insecure_cookies {
        log::warn!(
            "XENON_INSECURE_COOKIES is set — session cookies will omit `Secure`. \
             Use this for local development only."
        );
    }

    let conn = db::open(&config.db_path())?;
    let user_count: i64 = conn
        .query_row("SELECT count(*) FROM user", [], |r| r.get(0))
        .map_err(|e| format!("read user table: {e}"))?;
    if user_count == 0 {
        log::warn!(
            "no accounts exist yet — the FIRST registration at /register becomes the admin. \
             Register now, before exposing this instance."
        );
    }

    let port = config.port;
    let state = AppState::new(config, conn).map_err(|e| e.message)?;
    let app = build_app(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .map_err(|e| format!("bind 0.0.0.0:{port}: {e}"))?;
    log::info!("listening on http://0.0.0.0:{port}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("server error: {e}"))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    log::info!("shutting down");
}
