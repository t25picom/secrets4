use crate::audit;
use crate::cache::{self, CacheRef};
use crate::cli;
use crate::paths;
use anyhow::{anyhow, Result};
use std::io::{IsTerminal, Write};

pub fn run(name: &str) -> Result<i32> {
    if !std::io::stdout().is_terminal() {
        return Err(anyhow!(
            "view refuses to write secret to a non-tty stdout (LLM tool pipes are non-tty). Run from an interactive shell."
        ));
    }
    paths::ensure_config_dir_secure()?;
    let cache_path = paths::cache_file()?;
    let key_path = paths::cache_key_file()?;
    let lock_path = paths::lock_file()?;
    let c = CacheRef {
        cache_path: &cache_path,
        key_path: &key_path,
        lock_path: &lock_path,
    };
    let grants = cache::list(&c)?;
    let g = grants
        .get(name)
        .ok_or_else(|| anyhow!("no active grant for {}", name))?;

    let mut tty = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_err(|e| anyhow!("cannot open /dev/tty: {e}"))?;
    tty.write_all(&g.value)?;
    tty.write_all(b"\n")?;
    tty.flush()?;
    audit::warn_if_failed(audit::record("view", &[("name", serde_json::json!(name))]));
    Ok(cli::EXIT_OK)
}
