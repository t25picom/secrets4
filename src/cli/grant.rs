use crate::audit;
use crate::cache::{self, CacheRef};
use crate::cli;
use crate::paths;
use crate::ttl;
use anyhow::{anyhow, Result};
use std::io::{self, Read};
use std::path::Path;
use zeroize::Zeroizing;

pub fn run(name: &str, ttl_str: &str, from_stdin: bool, from_file: Option<&Path>) -> Result<i32> {
    validate_name(name)?;
    paths::ensure_config_dir_secure()?;

    let ttl_secs = ttl::parse_duration(ttl_str)?;
    if ttl_secs == 0 {
        return Err(anyhow!("ttl must be > 0"));
    }

    let value: Zeroizing<Vec<u8>> = if let Some(p) = from_file {
        Zeroizing::new(std::fs::read(p)?)
    } else if from_stdin {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Zeroizing::new(buf)
    } else {
        eprint!("Value for {name} (input hidden): ");
        let s = rpassword::read_password()?;
        Zeroizing::new(s.into_bytes())
    };

    let cache_path = paths::cache_file()?;
    let key_path = paths::cache_key_file()?;
    let lock_path = paths::lock_file()?;
    let c = CacheRef {
        cache_path: &cache_path,
        key_path: &key_path,
        lock_path: &lock_path,
    };

    cache::grant(&c, name, value, ttl_secs)?;
    audit::warn_if_failed(audit::record(
        "grant",
        &[
            ("name", serde_json::json!(name)),
            ("ttl_secs", serde_json::json!(ttl_secs)),
        ],
    ));
    eprintln!(
        "Granted {} for {} ({} secs).",
        name,
        ttl::humanize_remaining(ttl_secs),
        ttl_secs
    );
    Ok(cli::EXIT_OK)
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("empty name"));
    }
    let bytes = name.as_bytes();
    if !(bytes[0].is_ascii_uppercase() || bytes[0] == b'_') {
        return Err(anyhow!("name must start with [A-Z_]"));
    }
    for b in &bytes[1..] {
        if !(b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_') {
            return Err(anyhow!("name has invalid char {:?}", *b as char));
        }
    }
    Ok(())
}
