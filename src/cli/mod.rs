pub mod grant;
pub mod revoke;
pub mod prune;
pub mod list;
pub mod status;
pub mod view;
pub mod run;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "secrets4", version, about = "AI-safe secret-grant cache for LLM-driven workflows")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Grant a secret to LLM use for a TTL window. Reads value from stdin or --from-file.
    Grant {
        name: String,
        #[arg(long, default_value = "2h")]
        ttl: String,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        from_file: Option<std::path::PathBuf>,
    },
    /// Revoke a granted secret immediately.
    Revoke { name: String },
    /// Drop expired entries from the cache.
    Prune,
    /// List currently-active grants (names + expiry; never values).
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show cache state summary.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Print value to a tty (refuses non-tty). Human-only.
    View { name: String },
    /// Run a command with $env[NAME] tokens replaced by granted values.
    /// By default, subprocess stdout/stderr are scanned and granted values
    /// are replaced with [REDACTED:NAME]. Use --no-redact to disable.
    Run {
        cmd: String,
        #[arg(long)]
        no_redact: bool,
    },
}

pub const EXIT_OK: i32 = 0;
pub const EXIT_GENERIC_ERR: i32 = 1;
pub const EXIT_PARSE_ERR: i32 = 66;
pub const EXIT_UNKNOWN_NAME: i32 = 64;
pub const EXIT_EXPIRED_OR_NOT_GRANTED: i32 = 65;

pub fn dispatch(cli: Cli) -> Result<i32> {
    match cli.cmd {
        Cmd::Grant { name, ttl, stdin, from_file } => {
            grant::run(&name, &ttl, stdin, from_file.as_deref())
        }
        Cmd::Revoke { name } => revoke::run(&name),
        Cmd::Prune => prune::run(),
        Cmd::List { json } => list::run(json),
        Cmd::Status { json } => status::run(json),
        Cmd::View { name } => view::run(&name),
        Cmd::Run { cmd, no_redact } => run::run(&cmd, !no_redact),
    }
}
