use crate::paths;
use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{Map, Value};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

pub fn record(event: &str, fields: &[(&str, Value)]) -> Result<()> {
    let path = paths::audit_log()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

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
        .open(&path)
        .with_context(|| format!("opening audit log {}", path.display()))?;
    serde_json::to_writer(&mut f, &entry)?;
    f.write_all(b"\n")?;
    f.flush()?;
    Ok(())
}

pub fn warn_if_failed(result: Result<()>) {
    if let Err(e) = result {
        eprintln!("warning: failed to write audit log: {e}");
    }
}
