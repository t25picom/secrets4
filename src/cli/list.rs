use crate::cache::{self, CacheRef};
use crate::cli;
use crate::paths;
use crate::ttl;
use anyhow::Result;
use chrono::Utc;

pub fn run(json: bool) -> Result<i32> {
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

    if json {
        print!("{{\"grants\":[");
        let mut first = true;
        for (name, g) in &grants {
            if !first {
                print!(",");
            }
            first = false;
            let remaining = (g.expires_at - now).num_seconds().max(0);
            print!(
                "{{\"name\":\"{}\",\"expires_at\":\"{}\",\"ttl_remaining_secs\":{}}}",
                name,
                g.expires_at.to_rfc3339(),
                remaining
            );
        }
        println!("]}}");
    } else {
        if grants.is_empty() {
            eprintln!("(no active grants)");
            return Ok(cli::EXIT_OK);
        }
        let max_name = grants.keys().map(|k| k.len()).max().unwrap_or(0);
        for (name, g) in &grants {
            let remaining = (g.expires_at - now).num_seconds().max(0) as u64;
            println!(
                "{:<width$}  {}  (expires {})",
                name,
                ttl::humanize_remaining(remaining),
                g.expires_at.format("%Y-%m-%d %H:%M:%SZ"),
                width = max_name
            );
        }
    }
    Ok(cli::EXIT_OK)
}
