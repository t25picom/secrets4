use anyhow::{anyhow, Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

pub fn config_dir() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "secrets4")
        .ok_or_else(|| anyhow!("cannot resolve config dir"))?;
    Ok(dirs.config_dir().to_path_buf())
}

pub fn cache_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("cache.enc"))
}

pub fn cache_key_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("cache.key"))
}

pub fn lock_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("cache.lock"))
}

pub fn audit_log() -> Result<PathBuf> {
    Ok(config_dir()?.join("audit.log"))
}

pub fn ensure_config_dir_secure() -> Result<()> {
    let dir = config_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let perm = std::fs::metadata(&dir)?.permissions();
    if perm.mode() & 0o777 != 0o700 {
        let mut p = perm;
        p.set_mode(0o700);
        std::fs::set_permissions(&dir, p)?;
    }
    Ok(())
}
