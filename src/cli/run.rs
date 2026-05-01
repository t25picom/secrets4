use crate::audit;
use crate::cache::{self, CacheRef};
use crate::cli;
use crate::injection::{find_tokens, rewrite, spawn};
use crate::paths;
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use zeroize::Zeroizing;

pub fn run(cmd: &str, redact: bool) -> Result<i32> {
    let tokens = match find_tokens(cmd) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("secrets4: parse error in command: {e}");
            return Ok(cli::EXIT_PARSE_ERR);
        }
    };

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
    let now = Utc::now();

    let mut env: HashMap<String, Zeroizing<Vec<u8>>> = HashMap::new();
    for tok in &tokens {
        match grants.get(&tok.name) {
            Some(g) if g.expires_at > now => {
                env.insert(tok.name.clone(), g.value.clone());
            }
            Some(_) => {
                eprintln!(
                    "secrets4: {} is expired. Ask the user to re-grant: secrets4 grant {} --ttl <duration>",
                    tok.name, tok.name
                );
                return Ok(cli::EXIT_EXPIRED_OR_NOT_GRANTED);
            }
            None => {
                eprintln!(
                    "secrets4: {} is not granted. Ask the user to run: secrets4 grant {} --ttl <duration>",
                    tok.name, tok.name
                );
                return Ok(cli::EXIT_EXPIRED_OR_NOT_GRANTED);
            }
        }
    }

    let rewritten = rewrite(cmd, &tokens);
    let status = if redact {
        spawn::spawn_with_env(&rewritten, env)?
    } else {
        spawn::spawn_with_env_no_redact(&rewritten, env)?
    };
    let code = status.code().unwrap_or(1);
    let names: Vec<_> = tokens.iter().map(|t| t.name.as_str()).collect();
    audit::warn_if_failed(audit::record(
        "run",
        &[
            ("names", serde_json::json!(names)),
            ("exit_code", serde_json::json!(code)),
        ],
    ));
    Ok(code)
}
