// End-to-end: a real Xenon listener and the `xen` binary talking to it.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;
use xenon::config::Config;
use xenon::state::AppState;
use xenon::{build_app, db};

struct Live {
    url: String,
    _dir: tempfile::TempDir,
}

impl Live {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::for_test(dir.path().to_path_buf());
        let conn = db::open(&config.db_path()).unwrap();
        let state = AppState::new(config, conn).unwrap();
        let app = build_app(state);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let listener = rt.block_on(async {
            tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind")
        });
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            rt.block_on(async {
                axum::serve(listener, app).await.expect("serve");
            });
        });
        let url = format!("http://{addr}");
        wait_for(&url);
        Self { url, _dir: dir }
    }
}

fn wait_for(url: &str) {
    for _ in 0..100 {
        if std::net::TcpStream::connect_timeout(
            &url.trim_start_matches("http://").parse().unwrap(),
            Duration::from_millis(50),
        )
        .is_ok()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("xenon did not start at {url}");
}

fn xen(config: &Path, url: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xen"))
        .arg("--config")
        .arg(config)
        .arg("--url")
        .arg(url)
        .args(args)
        .env_remove("XENON_TOKEN")
        .env_remove("XENON_SESSION")
        .env_remove("XENON_URL")
        .env_remove("XENON_PASSWORD")
        .env_remove("XENON_CLI_CONFIG")
        .output()
        .expect("run xen")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn json_out(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or(Value::Null)
}

fn assert_ok(out: &Output) {
    assert!(
        out.status.success(),
        "xen failed\nstdout:\n{}\nstderr:\n{}",
        stdout(out),
        stderr(out)
    );
}

fn tmp_config() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cli.toml");
    (dir, path)
}

fn register_admin(config: &Path, url: &str) {
    let out = xen(
        config,
        url,
        &[
            "register",
            "--email",
            "wk@example.com",
            "--password",
            "correct horse battery",
            "--name",
            "wk",
        ],
    );
    assert_ok(&out);
}

#[test]
fn health_prints_ok() {
    let live = Live::start();
    let (_dir, config) = tmp_config();
    let out = xen(&config, &live.url, &["health"]);
    assert_ok(&out);
    assert_eq!(stdout(&out).trim(), "ok");
}

#[test]
fn register_login_me_and_logout() {
    let live = Live::start();
    let (_dir, config) = tmp_config();
    register_admin(&config, &live.url);

    let me = xen(&config, &live.url, &["--json", "me"]);
    assert_ok(&me);
    let body = json_out(&me);
    assert_eq!(body["user"]["email"], "wk@example.com");
    assert_eq!(body["user"]["is_admin"], true);

    let out = xen(&config, &live.url, &["logout"]);
    assert_ok(&out);

    let me = xen(&config, &live.url, &["me"]);
    assert!(!me.status.success(), "logged-out me must fail");

    let login = xen(
        &config,
        &live.url,
        &[
            "login",
            "--email",
            "wk@example.com",
            "--password",
            "correct horse battery",
        ],
    );
    assert_ok(&login);
    let me = xen(&config, &live.url, &["me"]);
    assert_ok(&me);
}

#[test]
fn invite_admits_a_second_account() {
    let live = Live::start();
    let (_admin_dir, admin) = tmp_config();
    register_admin(&admin, &live.url);

    let invite = xen(&admin, &live.url, &["--json", "invite"]);
    assert_ok(&invite);
    let code = json_out(&invite)["code"].as_str().unwrap().to_string();

    let (_friend_dir, friend) = tmp_config();
    let joined = xen(
        &friend,
        &live.url,
        &[
            "--json",
            "register",
            "--email",
            "friend@example.com",
            "--password",
            "a sufficiently long one",
            "--invite",
            &code,
        ],
    );
    assert_ok(&joined);
    assert_eq!(json_out(&joined)["is_admin"], false);
}

#[test]
fn token_push_list_show_and_file_roundtrip() {
    let live = Live::start();
    let (_dir, config) = tmp_config();
    register_admin(&config, &live.url);

    let minted = xen(
        &config,
        &live.url,
        &[
            "--json",
            "token",
            "create",
            "--label",
            "this laptop",
            "--save",
        ],
    );
    assert_ok(&minted);
    let token = json_out(&minted)["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("xen_"), "{token}");

    let bundle = tempfile::tempdir().unwrap();
    let review = bundle.path().join("review.md");
    std::fs::write(&review, "# hello\n\nfrom xen\n").unwrap();

    let pushed = xen(
        &config,
        &live.url,
        &[
            "--json",
            "push",
            "wk-j.xenon",
            "--kind",
            "review",
            "--slug",
            "2026-08-12-hello",
            "--title",
            "Hello",
            "--file",
            review.to_str().unwrap(),
            "--meta",
            r#"{"lane":"Grok-1"}"#,
        ],
    );
    assert_ok(&pushed);
    let body = json_out(&pushed);
    assert_eq!(body["unchanged"], false);
    let resource_id = body["resource_id"].as_str().unwrap().to_string();
    let revision_id = body["revision_id"].as_str().unwrap().to_string();

    let again = xen(
        &config,
        &live.url,
        &[
            "--json",
            "push",
            "wk-j.xenon",
            "--kind",
            "review",
            "--slug",
            "2026-08-12-hello",
            "--title",
            "Hello",
            "--file",
            review.to_str().unwrap(),
            "--meta",
            r#"{"lane":"Grok-1"}"#,
        ],
    );
    assert_ok(&again);
    assert_eq!(json_out(&again)["unchanged"], true);

    let listed = xen(
        &config,
        &live.url,
        &[
            "--json",
            "resource",
            "list",
            "wk-j.xenon",
            "--kind",
            "review",
        ],
    );
    assert_ok(&listed);
    let rows = json_out(&listed);
    assert_eq!(rows[0]["slug"], "2026-08-12-hello");

    let shown = xen(
        &config,
        &live.url,
        &[
            "--json",
            "resource",
            "show",
            "wk-j.xenon",
            "review",
            "2026-08-12-hello",
        ],
    );
    assert_ok(&shown);
    assert_eq!(json_out(&shown)["id"], resource_id);

    let dest = bundle.path().join("out.md");
    let got = xen(
        &config,
        &live.url,
        &[
            "file",
            &revision_id,
            "review.md",
            "-o",
            dest.to_str().unwrap(),
        ],
    );
    assert_ok(&got);
    assert_eq!(
        std::fs::read_to_string(&dest).unwrap(),
        "# hello\n\nfrom xen\n"
    );

    let activity = xen(
        &config,
        &live.url,
        &["--json", "activity", "--project", "wk-j.xenon"],
    );
    assert_ok(&activity);
    let activity_body = json_out(&activity);
    let kinds: Vec<_> = activity_body["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e.get("kind").and_then(Value::as_str))
        .collect();
    assert!(kinds.contains(&"resource.publish"), "activity: {kinds:?}");

    let projects = xen(&config, &live.url, &["--json", "project", "list"]);
    assert_ok(&projects);
    assert_eq!(json_out(&projects)[0]["slug"], "wk-j.xenon");

    // A token cannot mint another token — even this one we just saved.
    let (_bare_dir, bare) = tmp_config();
    let escalated = xen(
        &bare,
        &live.url,
        &[
            "--token",
            &token,
            "token",
            "create",
            "--label",
            "escalation",
        ],
    );
    assert!(!escalated.status.success());
    assert!(
        stderr(&escalated).contains("login session") || stderr(&escalated).contains("session"),
        "{}",
        stderr(&escalated)
    );
}

#[test]
fn attention_inline_and_usage() {
    let live = Live::start();
    let (_dir, config) = tmp_config();
    register_admin(&config, &live.url);

    let pushed = xen(
        &config,
        &live.url,
        &[
            "--json",
            "push",
            "wk-j.xenon",
            "--kind",
            "attention",
            "--slug",
            "jdg-test-1",
            "--title",
            "A question",
            "--meta",
            r#"{"reversibility":"reversible"}"#,
        ],
    );
    assert_ok(&pushed);
    assert_eq!(json_out(&pushed)["unchanged"], false);

    let turns = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        turns.path(),
        r#"{
          "turns": [{
            "v": 1,
            "id": "usg-test-1",
            "at": 1786233600000,
            "durationMs": 1000,
            "hostname": "mbp",
            "harnessId": "hm-1",
            "lane": "Grok-1",
            "backend": "grok",
            "model": "grok-4",
            "modelConfirmed": true,
            "sessionId": "s1",
            "turn": 1,
            "stopReason": "end_turn",
            "origin": "user",
            "tokens": { "input": 10, "output": 5 }
          }]
        }"#,
    )
    .unwrap();
    let posted = xen(
        &config,
        &live.url,
        &[
            "--json",
            "usage",
            "post",
            "wk-j.xenon",
            "--file",
            turns.path().to_str().unwrap(),
        ],
    );
    assert_ok(&posted);
    assert_eq!(json_out(&posted)["accepted"], 1);

    let usage = xen(
        &config,
        &live.url,
        &["--json", "usage", "show", "wk-j.xenon", "--group", "model"],
    );
    assert_ok(&usage);
    assert_eq!(json_out(&usage)["totals"]["turns"], 1);
}

#[test]
fn secret_scan_blocks_a_token_in_a_file() {
    let live = Live::start();
    let (_dir, config) = tmp_config();
    register_admin(&config, &live.url);

    let bundle = tempfile::tempdir().unwrap();
    let leak = bundle.path().join("note.md");
    std::fs::write(&leak, "token = xen_abcdefghij_0123456789abcdef\n").unwrap();

    let blocked = xen(
        &config,
        &live.url,
        &[
            "push",
            "wk-j.xenon",
            "--kind",
            "doc",
            "--slug",
            "leak",
            "--title",
            "Leak",
            "--file",
            leak.to_str().unwrap(),
        ],
    );
    assert!(!blocked.status.success());
    assert!(
        stderr(&blocked).contains("Xenon API token"),
        "{}",
        stderr(&blocked)
    );

    let forced = xen(
        &config,
        &live.url,
        &[
            "--json",
            "push",
            "wk-j.xenon",
            "--kind",
            "doc",
            "--slug",
            "leak",
            "--title",
            "Leak",
            "--file",
            leak.to_str().unwrap(),
            "--force",
        ],
    );
    assert_ok(&forced);
}

#[test]
fn project_github_repo_roundtrip() {
    let live = Live::start();
    let (_dir, config) = tmp_config();
    register_admin(&config, &live.url);

    // Project exists after the first write.
    let pushed = xen(
        &config,
        &live.url,
        &[
            "--json",
            "push",
            "wk-j.xenon",
            "--kind",
            "attention",
            "--slug",
            "seed",
            "--title",
            "Seed",
        ],
    );
    assert_ok(&pushed);

    let set = xen(
        &config,
        &live.url,
        &[
            "--json",
            "project",
            "set",
            "wk-j.xenon",
            "--github-repo",
            "wk-j/xenon",
        ],
    );
    assert_ok(&set);
    assert_eq!(json_out(&set)["github_repo"], "wk-j/xenon");
}
