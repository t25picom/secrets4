use crate::cache::{self, CacheRef};
use crate::cli;
use crate::paths;
use anyhow::Result;

pub fn run() -> Result<i32> {
    paths::ensure_config_dir_secure()?;
    let cache_path = paths::cache_file()?;
    let key_path = paths::cache_key_file()?;
    let lock_path = paths::lock_file()?;
    let c = CacheRef {
        cache_path: &cache_path,
        key_path: &key_path,
        lock_path: &lock_path,
    };
    let n = cache::prune(&c)?;
    eprintln!("Pruned {} expired grant(s).", n);
    Ok(cli::EXIT_OK)
}
