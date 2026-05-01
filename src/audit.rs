use crate::cache::atomic;
use crate::paths;
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde_json::{Map, Value};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const MAX_AUDIT_LOG_BYTES: u64 = 10 * 1024 * 1024;

pub fn record(event: &str, fields: &[(&str, Value)]) -> Result<()> {
    let path = paths::audit_log()?;
    record_at(&path, event, fields, MAX_AUDIT_LOG_BYTES)
}

fn record_at(path: &Path, event: &str, fields: &[(&str, Value)], max_bytes: u64) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let lock_path = path.with_extension("lock");
    let _lock = atomic::lock_exclusive(&lock_path)?;
    validate_audit_log(path)?;
    rotate_if_needed(path, max_bytes)?;

    let mut entry = Map::new();
    entry.insert("ts".into(), Value::String(Utc::now().to_rfc3339()));
    entry.insert("event".into(), Value::String(event.into()));
    for (key, value) in fields {
        entry.insert((*key).into(), value.clone());
    }

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening audit log {}", path.display()))?;
    serde_json::to_writer(&mut f, &entry)?;
    f.write_all(b"\n")?;
    f.flush()?;
    Ok(())
}

fn validate_audit_log(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(anyhow!(
            "audit log {} is not a regular file",
            path.display()
        ));
    }
    let current_uid = nix::unistd::Uid::current().as_raw();
    if meta.uid() != current_uid {
        return Err(anyhow!(
            "audit log {} is owned by uid {}, expected {}",
            path.display(),
            meta.uid(),
            current_uid
        ));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
        eprintln!(
            "warning: audit log {} had group/world permissions; repaired to 0600, but previous exposure may already have happened",
            path.display()
        );
    }
    Ok(())
}

fn rotate_if_needed(path: &Path, max_bytes: u64) -> Result<()> {
    if !path.exists() || std::fs::metadata(path)?.len() < max_bytes {
        return Ok(());
    }
    let rotated = path.with_extension("log.1");
    match std::fs::remove_file(&rotated) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("remove {}", rotated.display())),
    }
    std::fs::rename(path, &rotated)
        .with_context(|| format!("rename {} -> {}", path.display(), rotated.display()))?;
    if let Some(parent) = path.parent() {
        let dir =
            std::fs::File::open(parent).with_context(|| format!("open {}", parent.display()))?;
        nix::unistd::fsync(std::os::fd::AsRawFd::as_raw_fd(&dir))
            .map_err(|e| anyhow!("dir fsync: {e}"))?;
    }
    Ok(())
}

pub fn warn_if_failed(result: Result<()>) {
    if let Err(e) = result {
        eprintln!("warning: failed to write audit log: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn records_ndjson_and_repairs_permissions() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, b"").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();

        record_at(&path, "grant", &[("name", serde_json::json!("FOO"))], 1024).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let log = std::fs::read_to_string(&path).unwrap();
        assert!(log.contains("\"event\":\"grant\""));
        assert!(log.contains("\"name\":\"FOO\""));
    }

    #[test]
    fn rotates_when_log_reaches_limit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, b"0123456789").unwrap();

        record_at(&path, "status", &[], 10).unwrap();
        assert!(path.with_extension("log.1").exists());
        let log = std::fs::read_to_string(&path).unwrap();
        assert!(log.contains("\"event\":\"status\""));
    }
}
