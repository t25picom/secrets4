pub mod atomic;
pub mod format;

use crate::crypto::{aead, rand};
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use std::collections::BTreeMap;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::Zeroizing;

pub use format::{Grant, GrantFile};

pub struct CacheRef<'a> {
    pub cache_path: &'a Path,
    pub key_path: &'a Path,
    pub lock_path: &'a Path,
}

pub fn ensure_keyfile(key_path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    if key_path.exists() {
        let bytes = std::fs::read(key_path)?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "cache key file {} has wrong length {}",
                key_path.display(),
                bytes.len()
            ));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        return Ok(Zeroizing::new(k));
    }
    let parent = key_path
        .parent()
        .ok_or_else(|| anyhow!("key path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let key: [u8; 32] = rand::random_bytes();
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(key_path)
            .with_context(|| format!("creating {}", key_path.display()))?;
        f.write_all(&key)?;
        f.sync_all()?;
    }
    Ok(Zeroizing::new(key))
}

pub fn load(c: &CacheRef) -> Result<GrantFile> {
    let key = ensure_keyfile(c.key_path)?;
    if !c.cache_path.exists() {
        return Ok(GrantFile::default());
    }
    let bytes = std::fs::read(c.cache_path)?;
    if bytes.len() < format::MAGIC.len() + 12 {
        return Err(anyhow!("cache file truncated"));
    }
    if &bytes[..format::MAGIC.len()] != format::MAGIC {
        return Err(anyhow!("cache file magic mismatch"));
    }
    let nonce_off = format::MAGIC.len();
    let nonce: [u8; 12] = bytes[nonce_off..nonce_off + 12].try_into().unwrap();
    let ct = &bytes[nonce_off + 12..];
    let pt = aead::open(&key, &nonce, format::MAGIC, ct)?;
    let mut file: GrantFile =
        ciborium::de::from_reader(&pt[..]).map_err(|e| anyhow!("decode cache: {e}"))?;
    file.prune_expired();
    Ok(file)
}

pub fn save(c: &CacheRef, file: &GrantFile) -> Result<()> {
    let key = ensure_keyfile(c.key_path)?;
    let mut buf = Vec::new();
    ciborium::ser::into_writer(file, &mut buf).map_err(|e| anyhow!("encode cache: {e}"))?;
    let nonce: [u8; 12] = rand::random_bytes();
    let ct = aead::seal(&key, &nonce, format::MAGIC, &buf)?;

    let mut out = Vec::with_capacity(format::MAGIC.len() + 12 + ct.len());
    out.extend_from_slice(format::MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    atomic::write_locked(c.cache_path, c.lock_path, &out)
}

pub fn grant(
    c: &CacheRef,
    name: &str,
    value: Zeroizing<Vec<u8>>,
    ttl_secs: u64,
) -> Result<()> {
    if value.contains(&0u8) {
        return Err(anyhow!("value contains NUL byte; refusing"));
    }
    if value.is_empty() {
        return Err(anyhow!("value is empty; refusing"));
    }
    let mut file = load(c)?;
    let now = Utc::now();
    let expires = now
        + chrono::Duration::seconds(ttl_secs as i64);
    file.grants.insert(
        name.to_string(),
        Grant {
            value: value.to_vec(),
            granted_at: now,
            expires_at: expires,
        },
    );
    save(c, &file)
}

pub fn revoke(c: &CacheRef, name: &str) -> Result<bool> {
    let mut file = load(c)?;
    let removed = file.grants.remove(name).is_some();
    save(c, &file)?;
    Ok(removed)
}

pub fn prune(c: &CacheRef) -> Result<usize> {
    let mut file = load(c)?;
    let before = file.grants.len();
    file.prune_expired();
    let pruned = before - file.grants.len();
    save(c, &file)?;
    Ok(pruned)
}

pub fn list(c: &CacheRef) -> Result<BTreeMap<String, Grant>> {
    Ok(load(c)?.grants)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn cref<'a>(d: &'a Path) -> (CacheRef<'a>, std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let cp = d.join("cache.enc");
        let kp = d.join("cache.key");
        let lp = d.join("cache.lock");
        let r = CacheRef {
            cache_path: Box::leak(cp.clone().into_boxed_path()),
            key_path: Box::leak(kp.clone().into_boxed_path()),
            lock_path: Box::leak(lp.clone().into_boxed_path()),
        };
        (r, cp, kp, lp)
    }

    #[test]
    fn round_trip_grant() {
        let dir = tempdir().unwrap();
        let cp = dir.path().join("cache.enc");
        let kp = dir.path().join("cache.key");
        let lp = dir.path().join("cache.lock");
        let r = CacheRef {
            cache_path: &cp,
            key_path: &kp,
            lock_path: &lp,
        };
        grant(&r, "FOO", Zeroizing::new(b"bar".to_vec()), 60).unwrap();
        let m = list(&r).unwrap();
        assert_eq!(m.get("FOO").unwrap().value, b"bar");
    }

    #[test]
    fn nasty_values_round_trip() {
        let dir = tempdir().unwrap();
        let cp = dir.path().join("cache.enc");
        let kp = dir.path().join("cache.key");
        let lp = dir.path().join("cache.lock");
        let r = CacheRef {
            cache_path: &cp,
            key_path: &kp,
            lock_path: &lp,
        };
        let nasty: &[&[u8]] = &[
            b"p@ssw\"rd$with$specials",
            b"line1\nline2",
            b"`backtick`",
            b"'single' \"double\"",
            b"\xff\xfe binary",
        ];
        for (i, v) in nasty.iter().enumerate() {
            grant(&r, &format!("S{i}"), Zeroizing::new(v.to_vec()), 60).unwrap();
        }
        let m = list(&r).unwrap();
        for (i, v) in nasty.iter().enumerate() {
            assert_eq!(m.get(&format!("S{i}")).unwrap().value, *v);
        }
    }

    #[test]
    fn expired_grants_pruned_on_load() {
        let dir = tempdir().unwrap();
        let cp = dir.path().join("cache.enc");
        let kp = dir.path().join("cache.key");
        let lp = dir.path().join("cache.lock");
        let r = CacheRef {
            cache_path: &cp,
            key_path: &kp,
            lock_path: &lp,
        };
        let mut file = GrantFile::default();
        file.grants.insert(
            "OLD".into(),
            Grant {
                value: b"x".to_vec(),
                granted_at: Utc::now() - chrono::Duration::seconds(120),
                expires_at: Utc::now() - chrono::Duration::seconds(60),
            },
        );
        file.grants.insert(
            "FRESH".into(),
            Grant {
                value: b"y".to_vec(),
                granted_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::seconds(60),
            },
        );
        save(&r, &file).unwrap();
        let loaded = list(&r).unwrap();
        assert!(loaded.contains_key("FRESH"));
        assert!(!loaded.contains_key("OLD"));
    }

    #[test]
    fn revoke_removes() {
        let dir = tempdir().unwrap();
        let cp = dir.path().join("cache.enc");
        let kp = dir.path().join("cache.key");
        let lp = dir.path().join("cache.lock");
        let r = CacheRef {
            cache_path: &cp,
            key_path: &kp,
            lock_path: &lp,
        };
        grant(&r, "X", Zeroizing::new(b"v".to_vec()), 60).unwrap();
        assert!(revoke(&r, "X").unwrap());
        assert!(!list(&r).unwrap().contains_key("X"));
    }

    #[test]
    fn rejects_nul_in_value() {
        let dir = tempdir().unwrap();
        let cp = dir.path().join("cache.enc");
        let kp = dir.path().join("cache.key");
        let lp = dir.path().join("cache.lock");
        let r = CacheRef {
            cache_path: &cp,
            key_path: &kp,
            lock_path: &lp,
        };
        assert!(grant(&r, "X", Zeroizing::new(b"a\0b".to_vec()), 60).is_err());
    }
}
