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
    let count = grants.len();
    let soonest = grants
        .values()
        .map(|g| (g.expires_at - now).num_seconds().max(0) as u64)
        .min();

    if json {
        let soonest_s = match soonest {
            Some(s) => s.to_string(),
            None => "null".into(),
        };
        println!(
            "{{\"grants\":{},\"soonest_expiry_secs\":{}}}",
            count, soonest_s
        );
    } else {
        eprintln!("active grants: {}", count);
        if let Some(s) = soonest {
            eprintln!("soonest expiry: {} from now", ttl::humanize_remaining(s));
        }
    }
    Ok(cli::EXIT_OK)
}
