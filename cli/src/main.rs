// xen — command-line client for a Xenon resource server.
//
// Covers the `/v1` wire protocol in docs/01-protocol.md. The server binary
// stays `xenon`; this one never opens the database.

mod client;
mod cmd;
mod config;
mod error;
mod out;
mod push;

use clap::{Parser, Subcommand};
use config::Settings;
use error::Result;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "xen",
    version,
    about = "Command-line client for a Xenon resource server",
    after_help = "\
Examples:
  xen login --email you@example.com
  xen token create --label 'this laptop' --save
  xen push my.project --kind doc --slug notes --title Notes --file README.md
  xen resource list my.project
  xen resource show my.project doc notes
"
)]
struct Cli {
    /// Xenon base URL
    #[arg(long, global = true, env = "XENON_URL")]
    url: Option<String>,

    /// API token (`xen_…`)
    #[arg(long, global = true, env = "XENON_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Session cookie value
    #[arg(long, global = true, env = "XENON_SESSION", hide_env_values = true)]
    session: Option<String>,

    /// Path to the CLI config file
    #[arg(long, global = true, env = "XENON_CLI_CONFIG")]
    config: Option<PathBuf>,

    /// Print JSON instead of a table
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check that the server answers
    #[command(alias = "ping")]
    Health,

    /// Create an account and store the session
    Register {
        #[arg(long)]
        email: String,
        /// Ends up in the shell history — omit it to be prompted
        #[arg(long, env = "XENON_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        invite: Option<String>,
    },

    /// Sign in and store the session
    Login {
        #[arg(long)]
        email: String,
        #[arg(long, env = "XENON_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },

    /// End the stored session
    Logout,

    /// Show the signed-in account
    #[command(alias = "whoami")]
    Me,

    /// Mint a single-use invite code (admin, session)
    Invite,

    /// API tokens. Minting and revoke need a session, never another token.
    #[command(subcommand)]
    Token(TokenCmd),

    /// Projects visible to the caller
    #[command(subcommand)]
    Project(ProjectCmd),

    /// Published resources
    #[command(subcommand)]
    Resource(ResourceCmd),

    /// Fetch a file from a sealed revision
    File {
        revision: String,
        path: String,
        /// Write to this path instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Publish a resource (manifest → missing blobs → commit)
    Push {
        project: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        slug: String,
        #[arg(long)]
        title: String,
        /// Local file to include (repeatable). An absolute path publishes under its file name.
        #[arg(long)]
        file: Vec<PathBuf>,
        /// Directory to include recursively (hidden names and symlinks skipped)
        #[arg(long)]
        dir: Vec<PathBuf>,
        /// Read one file from stdin (needs --as)
        #[arg(long)]
        stdin: bool,
        /// Bundle path for --stdin
        #[arg(long = "as")]
        as_path: Option<String>,
        /// JSON object stored as the revision's meta
        #[arg(long)]
        meta: Option<String>,
        /// JSON object stored as the client-asserted origin
        #[arg(long)]
        origin: Option<String>,
        /// Force the single-shot inline route (≤ 1 MB)
        #[arg(long)]
        inline: bool,
        /// Skip the local secret scan
        #[arg(long)]
        force: bool,
    },

    /// Activity feed the caller may see
    Activity {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        cursor: Option<i64>,
        #[arg(long, default_value_t = 30)]
        limit: i64,
    },

    /// Per-turn LLM usage
    #[command(subcommand)]
    Usage(UsageCmd),

    /// Client settings stored in the config file
    #[command(subcommand)]
    Config(ConfigCmd),
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Mint a token. The secret is printed once.
    Create {
        #[arg(long)]
        label: String,
        /// Repeatable. Defaults to resource:read and resource:write.
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// Restrict the token to one project the caller already owns
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        expires_in_days: Option<i64>,
        /// Write the new token into the config file
        #[arg(long)]
        save: bool,
    },
    /// List token metadata (never secrets)
    List,
    /// Revoke a token immediately
    Revoke { id: String },
    /// Store an already-minted token in the config file
    Set { token: String },
    /// Forget the stored token
    Unset,
}

#[derive(Subcommand)]
enum ProjectCmd {
    /// List projects visible to the caller
    List,
    /// Update project settings (today: the linked GitHub repo)
    Set {
        slug: String,
        #[arg(long)]
        github_repo: Option<String>,
        #[arg(long)]
        clear_github_repo: bool,
    },
}

#[derive(Subcommand)]
enum ResourceCmd {
    /// List committed resources in a project
    List {
        project: String,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        since: Option<i64>,
        #[arg(long)]
        limit: Option<i64>,
    },
    /// Show a resource by id, or by project kind slug
    Show {
        /// `<id>` or `<project> <kind> <slug>`
        locator: Vec<String>,
        #[arg(long)]
        seq: Option<i64>,
    },
    /// Sealed revisions of a resource, newest first
    Revisions {
        /// `<id>` or `<project> <kind> <slug>`
        locator: Vec<String>,
    },
}

#[derive(Subcommand)]
enum UsageCmd {
    /// Summarise LLM usage for a project
    Show {
        project: String,
        /// Epoch milliseconds, inclusive
        #[arg(long)]
        from: Option<i64>,
        /// Epoch milliseconds, exclusive
        #[arg(long)]
        to: Option<i64>,
        #[arg(long, default_value = "day")]
        group: String,
    },
    /// Post turn rows from a JSON file
    Post {
        project: String,
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Show the resolved URL and whether a token/session is stored
    Show,
    /// Persist the server URL
    SetUrl { url: String },
}

fn main() {
    let cli = Cli::parse();
    let json = cli.json;
    if let Err(err) = run(cli) {
        if json {
            eprintln!("{}", err.to_json());
        } else {
            eprintln!("{err}");
        }
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let mut settings = Settings::load(cli.config, cli.url, cli.token, cli.session, cli.json)?;
    match cli.command {
        Command::Health => cmd::health(&settings),
        Command::Register {
            email,
            password,
            name,
            invite,
        } => cmd::register(&mut settings, email, password, name, invite),
        Command::Login { email, password } => cmd::login(&mut settings, email, password),
        Command::Logout => cmd::logout(&mut settings),
        Command::Me => cmd::me(&settings),
        Command::Invite => cmd::invite(&settings),
        Command::Token(TokenCmd::Create {
            label,
            scopes,
            project,
            expires_in_days,
            save,
        }) => cmd::token_create(&mut settings, label, scopes, project, expires_in_days, save),
        Command::Token(TokenCmd::List) => cmd::token_list(&settings),
        Command::Token(TokenCmd::Revoke { id }) => cmd::token_revoke(&settings, id),
        Command::Token(TokenCmd::Set { token }) => cmd::token_set(&mut settings, token),
        Command::Token(TokenCmd::Unset) => cmd::token_unset(&mut settings),
        Command::Project(ProjectCmd::List) => cmd::project_list(&settings),
        Command::Project(ProjectCmd::Set {
            slug,
            github_repo,
            clear_github_repo,
        }) => cmd::project_set(&settings, slug, github_repo, clear_github_repo),
        Command::Resource(ResourceCmd::List {
            project,
            kind,
            since,
            limit,
        }) => cmd::resource_list(&settings, project, kind, since, limit),
        Command::Resource(ResourceCmd::Show { locator, seq }) => {
            cmd::resource_show(&settings, locator, seq)
        }
        Command::Resource(ResourceCmd::Revisions { locator }) => {
            cmd::resource_revisions(&settings, locator)
        }
        Command::File {
            revision,
            path,
            output,
        } => cmd::file_get(&settings, revision, path, output),
        Command::Push {
            project,
            kind,
            slug,
            title,
            file,
            dir,
            stdin,
            as_path,
            meta,
            origin,
            inline,
            force,
        } => cmd::push(
            &settings,
            cmd::PushOpts {
                project,
                kind,
                slug,
                title,
                files: file,
                dirs: dir,
                stdin,
                as_path,
                meta,
                origin,
                inline,
                force,
            },
        ),
        Command::Activity {
            project,
            kind,
            cursor,
            limit,
        } => cmd::activity(&settings, project, kind, cursor, limit),
        Command::Usage(UsageCmd::Show {
            project,
            from,
            to,
            group,
        }) => cmd::usage_show(&settings, project, from, to, group),
        Command::Usage(UsageCmd::Post { project, file }) => {
            cmd::usage_post(&settings, project, file)
        }
        Command::Config(ConfigCmd::Show) => cmd::config_show(&settings),
        Command::Config(ConfigCmd::SetUrl { url }) => cmd::config_set_url(&mut settings, url),
    }
}
