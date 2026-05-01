use crate::audit;
use crate::cache::{self, CacheRef};
use crate::cli;
use crate::paths;
use crate::ttl;
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

#[derive(Serialize)]
struct StatusOutput {
    grants: usize,
    soonest_expiry_secs: Option<u64>,
}

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
    audit::warn_if_failed(audit::record(
        "status",
        &[
            ("count", serde_json::json!(count)),
            ("soonest_expiry_secs", serde_json::json!(soonest)),
        ],
    ));

    if json {
        println!(
            "{}",
            serde_json::to_string(&StatusOutput {
                grants: count,
                soonest_expiry_secs: soonest,
            })?
        );
    } else {
        eprintln!("active grants: {}", count);
        if let Some(s) = soonest {
            eprintln!("soonest expiry: {} from now", ttl::humanize_remaining(s));
        }
    }
    Ok(cli::EXIT_OK)
}
