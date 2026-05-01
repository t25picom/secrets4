use crate::audit;
use crate::cache::{self, CacheRef};
use crate::cli;
use crate::paths;
use crate::ttl;
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

#[derive(Serialize)]
struct ListGrant {
    name: String,
    expires_at: String,
    ttl_remaining_secs: i64,
}

#[derive(Serialize)]
struct ListOutput {
    grants: Vec<ListGrant>,
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
    audit::warn_if_failed(audit::record(
        "list",
        &[("count", serde_json::json!(grants.len()))],
    ));

    if json {
        let out = ListOutput {
            grants: grants
                .iter()
                .map(|(name, g)| ListGrant {
                    name: name.clone(),
                    expires_at: g.expires_at.to_rfc3339(),
                    ttl_remaining_secs: (g.expires_at - now).num_seconds().max(0),
                })
                .collect(),
        };
        println!("{}", serde_json::to_string(&out)?);
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
