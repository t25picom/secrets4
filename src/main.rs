use anyhow::Result;
use clap::Parser;
use secrets4::cli;
use std::process::ExitCode;

fn main() -> Result<ExitCode> {
    let cli = cli::Cli::parse();
    let code = cli::dispatch(cli)?;
    Ok(ExitCode::from(code as u8))
}
