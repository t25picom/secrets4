pub mod atomic;
pub mod format;

use crate::crypto::{aead, rand};
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
#[cfg(not(test))]
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub use format::{Grant, GrantFile};

const KEY_FILE_MAGIC: &[u8; 4] = b"S4K\x03";
const LEGACY_PASSWORD_KEY_FILE_MAGIC: &[u8; 4] = b"S4K\x02";
const PASSWORD_SALT_LEN: usize = 16;
const INSTALL_ID_FILE: &str = "install.id";

pub struct CacheRef<'a> {
    pub cache_path: &'a Path,
    pub key_path: &'a Path,
    pub lock_path: &'a Path,
}

pub fn ensure_keyfile(key_path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    if key_path.exists() {
        validate_keyfile_permissions(key_path)?;
        let bytes = std::fs::read(key_path)?;
        if bytes.starts_with(KEY_FILE_MAGIC) {
            let install_id = load_install_id(key_path)?;
            let ad = keyfile_ad(KEY_FILE_MAGIC, &install_id);
            return open_wrapped_keyfile(&bytes, KEY_FILE_MAGIC, &ad);
        }
        if bytes.starts_with(LEGACY_PASSWORD_KEY_FILE_MAGIC) {
            let key = open_wrapped_keyfile(
                &bytes,
                LEGACY_PASSWORD_KEY_FILE_MAGIC,
                LEGACY_PASSWORD_KEY_FILE_MAGIC,
            )?;
            write_wrapped_keyfile(key_path, &key)?;
            return Ok(key);
        }
        if bytes.len() != 32 {
            return Err(anyhow!(
                "cache key file {} has wrong length {}",
                key_path.display(),
                bytes.len()
            ));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        write_wrapped_keyfile(key_path, &k)?;
        return Ok(Zeroizing::new(k));
    }
    let key: [u8; 32] = rand::random_bytes();
    write_wrapped_keyfile(key_path, &key)?;
    Ok(Zeroizing::new(key))
}

pub fn load(c: &CacheRef) -> Result<GrantFile> {
    if !c.cache_path.exists() {
        return Ok(GrantFile::default());
    }
    let key = ensure_keyfile(c.key_path)?;
    load_with_key(c, &key)
}

fn load_with_key(c: &CacheRef, key: &[u8; aead::KEY_LEN]) -> Result<GrantFile> {
    if !c.cache_path.exists() {
        return Ok(GrantFile::default());
    }
    validate_cachefile_permissions(c.cache_path)?;
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
    let pt = aead::open(key, &nonce, format::MAGIC, ct)?;
    let mut file: GrantFile =
        ciborium::de::from_reader(&pt[..]).map_err(|e| anyhow!("decode cache: {e}"))?;
    file.prune_expired();
    Ok(file)
}

fn validate_keyfile_permissions(key_path: &Path) -> Result<()> {
    validate_secure_file(key_path, "cache key file")
}

fn validate_cachefile_permissions(cache_path: &Path) -> Result<()> {
    validate_secure_file(cache_path, "cache file")
}

fn validate_secure_file(path: &Path, label: &str) -> Result<()> {
    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(anyhow!(
            "{} {} is not a regular file",
            label,
            path.display()
        ));
    }

    let current_uid = nix::unistd::Uid::current().as_raw();
    if meta.uid() != current_uid {
        return Err(anyhow!(
            "{} {} is owned by uid {}, expected {}",
            label,
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
            "warning: {} {} had group/world permissions; repaired to 0600, but previous exposure may already have happened",
            label,
            path.display()
        );
    }

    Ok(())
}

fn open_wrapped_keyfile(bytes: &[u8], magic: &[u8; 4], ad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if bytes.len() < magic.len() + PASSWORD_SALT_LEN + aead::NONCE_LEN {
        return Err(anyhow!("cache key file truncated"));
    }
    let salt_off = magic.len();
    let salt: [u8; PASSWORD_SALT_LEN] = bytes[salt_off..salt_off + PASSWORD_SALT_LEN]
        .try_into()
        .unwrap();
    let nonce_off = salt_off + PASSWORD_SALT_LEN;
    let nonce: [u8; aead::NONCE_LEN] = bytes[nonce_off..nonce_off + aead::NONCE_LEN]
        .try_into()
        .unwrap();
    let ct = &bytes[nonce_off + aead::NONCE_LEN..];
    let password = wrapping_password(false)?;
    let wrapping_key = derive_wrapping_key(&password, &salt)?;
    let pt = aead::open(&wrapping_key, &nonce, ad, ct)?;
    if pt.len() != aead::KEY_LEN {
        return Err(anyhow!("cache key plaintext has wrong length {}", pt.len()));
    }
    let mut key = [0u8; aead::KEY_LEN];
    key.copy_from_slice(&pt[..]);
    Ok(Zeroizing::new(key))
}

fn write_wrapped_keyfile(key_path: &Path, key: &[u8; aead::KEY_LEN]) -> Result<()> {
    let parent = key_path
        .parent()
        .ok_or_else(|| anyhow!("key path has no parent"))?;
    std::fs::create_dir_all(parent)?;

    let install_id = load_or_create_install_id(key_path)?;
    let ad = keyfile_ad(KEY_FILE_MAGIC, &install_id);
    let salt: [u8; PASSWORD_SALT_LEN] = rand::random_bytes();
    let password = wrapping_password(true)?;
    let wrapping_key = derive_wrapping_key(&password, &salt)?;
    let nonce: [u8; aead::NONCE_LEN] = rand::random_bytes();
    let ct = aead::seal(&wrapping_key, &nonce, &ad, key)?;

    let mut out =
        Vec::with_capacity(KEY_FILE_MAGIC.len() + PASSWORD_SALT_LEN + aead::NONCE_LEN + ct.len());
    out.extend_from_slice(KEY_FILE_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);

    let tmp = parent.join(format!(
        "{}.tmp.{}.{:x}",
        key_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("cache.key"),
        std::process::id(),
        rand::random_bytes::<8>()
            .iter()
            .fold(0u64, |a, b| a.wrapping_mul(256).wrapping_add(*b as u64)),
    ));

    {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating tmp {}", tmp.display()))?;
        f.write_all(&out)?;
        f.flush()?;
        f.sync_all()?;
    }

    std::fs::rename(&tmp, key_path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), key_path.display()))?;

    let dir_file = File::open(parent).with_context(|| format!("open dir {}", parent.display()))?;
    nix::unistd::fsync(dir_file.as_raw_fd()).map_err(|e| anyhow!("dir fsync: {e}"))?;
    Ok(())
}

fn keyfile_ad(magic: &[u8; 4], install_id: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(magic.len() + install_id.len());
    ad.extend_from_slice(magic);
    ad.extend_from_slice(install_id);
    ad
}

fn install_id_path(key_path: &Path) -> Result<PathBuf> {
    let parent = key_path
        .parent()
        .ok_or_else(|| anyhow!("key path has no parent"))?;
    Ok(parent.join(INSTALL_ID_FILE))
}

fn load_install_id(key_path: &Path) -> Result<Vec<u8>> {
    let path = install_id_path(key_path)?;
    validate_secure_file(&path, "install id file")?;
    let id = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    if id.is_empty() {
        return Err(anyhow!("install id file {} is empty", path.display()));
    }
    Ok(id)
}

fn load_or_create_install_id(key_path: &Path) -> Result<Vec<u8>> {
    let path = install_id_path(key_path)?;
    if path.exists() {
        return load_install_id(key_path);
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("install id path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let id = uuid::Uuid::new_v4()
        .as_hyphenated()
        .to_string()
        .into_bytes();
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(&id)?;
    f.flush()?;
    f.sync_all()?;
    let dir_file = File::open(parent).with_context(|| format!("open dir {}", parent.display()))?;
    nix::unistd::fsync(dir_file.as_raw_fd()).map_err(|e| anyhow!("dir fsync: {e}"))?;
    Ok(id)
}

#[cfg(test)]
fn derive_wrapping_key(
    _password: &[u8],
    _salt: &[u8; PASSWORD_SALT_LEN],
) -> Result<Zeroizing<[u8; aead::KEY_LEN]>> {
    Ok(Zeroizing::new([0x42; aead::KEY_LEN]))
}

#[cfg(not(test))]
fn derive_wrapping_key(
    password: &[u8],
    salt: &[u8; PASSWORD_SALT_LEN],
) -> Result<Zeroizing<[u8; aead::KEY_LEN]>> {
    let params = argon2::Params::new(256 * 1024, 4, 1, Some(aead::KEY_LEN))
        .map_err(|e| anyhow!("invalid Argon2id params: {e}"))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; aead::KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| anyhow!("derive wrapping key: {e}"))?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
fn wrapping_password(_create: bool) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(b"test-password".to_vec()))
}

#[cfg(not(test))]
fn wrapping_password(create: bool) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(password) = std::env::var_os("SECRETS4_PASSWORD") {
        let bytes = password.into_vec();
        if !bytes.is_empty() {
            return Ok(Zeroizing::new(bytes));
        }
    }

    prompt_wrapping_password(create)
}

#[cfg(not(test))]
fn prompt_wrapping_password(create: bool) -> Result<Zeroizing<Vec<u8>>> {
    if create {
        let p1 = rpassword::prompt_password("New secrets4 master password: ")?;
        let p2 = rpassword::prompt_password("Confirm new secrets4 master password: ")?;
        if p1 != p2 {
            return Err(anyhow!("master passwords did not match"));
        }
        if p1.len() < 16 {
            return Err(anyhow!("master password must be at least 16 characters"));
        }
        Ok(Zeroizing::new(p1.into_bytes()))
    } else {
        let p = rpassword::prompt_password("secrets4 master password: ")?;
        if p.is_empty() {
            return Err(anyhow!("empty master password"));
        }
        Ok(Zeroizing::new(p.into_bytes()))
    }
}

pub fn save(c: &CacheRef, file: &GrantFile) -> Result<()> {
    let lock = atomic::lock_exclusive(c.lock_path)?;
    save_with_lock(c, &lock, file)
}

fn save_with_lock(c: &CacheRef, lock: &atomic::LockGuard, file: &GrantFile) -> Result<()> {
    let key = ensure_keyfile(c.key_path)?;
    save_with_key_lock(c, lock, file, &key)
}

fn save_with_key_lock(
    c: &CacheRef,
    lock: &atomic::LockGuard,
    file: &GrantFile,
    key: &[u8; aead::KEY_LEN],
) -> Result<()> {
    let mut buf = Zeroizing::new(Vec::new());
    ciborium::ser::into_writer(file, &mut *buf).map_err(|e| anyhow!("encode cache: {e}"))?;
    let nonce: [u8; 12] = rand::random_bytes();
    let ct = aead::seal(key, &nonce, format::MAGIC, &buf)?;

    let mut out = Vec::with_capacity(format::MAGIC.len() + 12 + ct.len());
    out.extend_from_slice(format::MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    atomic::write_with_lock(c.cache_path, lock, &out)
}

pub fn grant(c: &CacheRef, name: &str, value: Zeroizing<Vec<u8>>, ttl_secs: u64) -> Result<()> {
    if value.contains(&0u8) {
        return Err(anyhow!("value contains NUL byte; refusing"));
    }
    if value.is_empty() {
        return Err(anyhow!("value is empty; refusing"));
    }
    let now = Utc::now();
    let ttl_i64 = i64::try_from(ttl_secs).map_err(|_| anyhow!("ttl is too large"))?;
    let expires = now
        .checked_add_signed(chrono::Duration::seconds(ttl_i64))
        .ok_or_else(|| anyhow!("ttl is too large"))?;

    let lock = atomic::lock_exclusive(c.lock_path)?;
    let key = ensure_keyfile(c.key_path)?;
    let mut file = load_with_key(c, &key)?;
    file.grants.insert(
        name.to_string(),
        Grant {
            value,
            granted_at: now,
            expires_at: expires,
        },
    );
    save_with_key_lock(c, &lock, &file, &key)
}

pub fn revoke(c: &CacheRef, name: &str) -> Result<bool> {
    let lock = atomic::lock_exclusive(c.lock_path)?;
    let key = ensure_keyfile(c.key_path)?;
    let mut file = load_with_key(c, &key)?;
    let removed = file.grants.remove(name).is_some();
    save_with_key_lock(c, &lock, &file, &key)?;
    Ok(removed)
}

pub fn prune(c: &CacheRef) -> Result<usize> {
    let lock = atomic::lock_exclusive(c.lock_path)?;
    let key = ensure_keyfile(c.key_path)?;
    let mut file = load_with_key(c, &key)?;
    let before = file.grants.len();
    file.prune_expired();
    let pruned = before - file.grants.len();
    save_with_key_lock(c, &lock, &file, &key)?;
    Ok(pruned)
}

pub fn rotate_key(c: &CacheRef) -> Result<()> {
    let lock = atomic::lock_exclusive(c.lock_path)?;
    if !c.key_path.exists() {
        return Err(anyhow!(
            "no cache key exists; grant a secret before rotating"
        ));
    }
    let old_key = ensure_keyfile(c.key_path)?;
    let file = load_with_key(c, &old_key)?;
    let new_key: [u8; aead::KEY_LEN] = rand::random_bytes();
    write_wrapped_keyfile(c.key_path, &new_key)?;
    save_with_key_lock(c, &lock, &file, &new_key)
}

pub fn list(c: &CacheRef) -> Result<BTreeMap<String, Grant>> {
    Ok(load(c)?.grants)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
        assert_eq!(m.get("FOO").unwrap().value.as_slice(), b"bar");
    }

    #[test]
    fn keyfile_is_wrapped_not_raw() {
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
        let keyfile = std::fs::read(&kp).unwrap();
        assert!(keyfile.starts_with(KEY_FILE_MAGIC));
        assert_ne!(keyfile.len(), aead::KEY_LEN);
        assert!(dir.path().join(INSTALL_ID_FILE).exists());
    }

    #[test]
    fn unsafe_existing_keyfile_permissions_are_repaired() {
        let dir = tempdir().unwrap();
        let kp = dir.path().join("cache.key");
        std::fs::write(&kp, [7u8; aead::KEY_LEN]).unwrap();
        let mut perms = std::fs::metadata(&kp).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&kp, perms).unwrap();

        let key = ensure_keyfile(&kp).unwrap();
        assert_eq!(&key[..], &[7u8; aead::KEY_LEN]);
        let mode = std::fs::metadata(&kp).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn unsafe_existing_cachefile_permissions_are_repaired() {
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
        let mut perms = std::fs::metadata(&cp).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&cp, perms).unwrap();

        let m = list(&r).unwrap();
        assert_eq!(m.get("FOO").unwrap().value.as_slice(), b"bar");
        let mode = std::fs::metadata(&cp).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn rotate_key_preserves_grants_and_rewrites_keyfile() {
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
        let before = std::fs::read(&kp).unwrap();
        rotate_key(&r).unwrap();
        let after = std::fs::read(&kp).unwrap();
        assert_ne!(before, after);
        let m = list(&r).unwrap();
        assert_eq!(m.get("FOO").unwrap().value.as_slice(), b"bar");
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
            assert_eq!(m.get(&format!("S{i}")).unwrap().value.as_slice(), *v);
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
                value: Zeroizing::new(b"x".to_vec()),
                granted_at: Utc::now() - chrono::Duration::seconds(120),
                expires_at: Utc::now() - chrono::Duration::seconds(60),
            },
        );
        file.grants.insert(
            "FRESH".into(),
            Grant {
                value: Zeroizing::new(b"y".to_vec()),
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

    #[test]
    fn rejects_ttl_that_cannot_fit_chrono_duration() {
        let dir = tempdir().unwrap();
        let cp = dir.path().join("cache.enc");
        let kp = dir.path().join("cache.key");
        let lp = dir.path().join("cache.lock");
        let r = CacheRef {
            cache_path: &cp,
            key_path: &kp,
            lock_path: &lp,
        };
        assert!(grant(&r, "X", Zeroizing::new(b"v".to_vec()), u64::MAX).is_err());
    }

    #[test]
    fn concurrent_grants_preserve_all_names() {
        use std::sync::Arc;
        use std::thread;

        let dir = Arc::new(tempdir().unwrap());
        let cp = dir.path().join("cache.enc");
        let kp = dir.path().join("cache.key");
        let lp = dir.path().join("cache.lock");
        let mut handles = vec![];

        for i in 0..16 {
            let cp = cp.clone();
            let kp = kp.clone();
            let lp = lp.clone();
            let _dir = Arc::clone(&dir);
            handles.push(thread::spawn(move || {
                let r = CacheRef {
                    cache_path: &cp,
                    key_path: &kp,
                    lock_path: &lp,
                };
                grant(
                    &r,
                    &format!("S{i}"),
                    Zeroizing::new(format!("v{i}").into_bytes()),
                    60,
                )
                .unwrap();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let r = CacheRef {
            cache_path: &cp,
            key_path: &kp,
            lock_path: &lp,
        };
        let grants = list(&r).unwrap();
        assert_eq!(grants.len(), 16);
        for i in 0..16 {
            assert_eq!(
                grants.get(&format!("S{i}")).unwrap().value.as_slice(),
                format!("v{i}").as_bytes()
            );
        }
    }
}
