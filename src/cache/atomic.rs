use anyhow::{anyhow, Context, Result};
use nix::fcntl::{flock, FlockArg};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub fn write_locked(target: &Path, lock_path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let lock_file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .mode(0o600)
        .open(lock_path)
        .with_context(|| format!("opening lock {}", lock_path.display()))?;
    flock(lock_file.as_raw_fd(), FlockArg::LockExclusive)
        .map_err(|e| anyhow!("flock failed: {e}"))?;

    let parent = target
        .parent()
        .ok_or_else(|| anyhow!("target has no parent"))?;
    let tmp = parent.join(format!(
        "{}.tmp.{}.{:x}",
        target.file_name().and_then(|s| s.to_str()).unwrap_or("vault"),
        std::process::id(),
        crate::crypto::rand::random_bytes::<8>()
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
        f.write_all(data)?;
        f.flush()?;
        f.sync_all()?;
    }

    std::fs::rename(&tmp, target)
        .with_context(|| format!("rename {} -> {}", tmp.display(), target.display()))?;

    let dir_file = File::open(parent).with_context(|| format!("open dir {}", parent.display()))?;
    nix::unistd::fsync(dir_file.as_raw_fd()).map_err(|e| anyhow!("dir fsync: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn writes_data_atomically() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("v.enc");
        let lock = dir.path().join("v.lock");
        write_locked(&target, &lock, b"first").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
        write_locked(&target, &lock, b"second").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"second");
    }

    #[test]
    fn concurrent_writes_serialize() {
        use std::sync::Arc;
        use std::thread;
        let dir = Arc::new(tempdir().unwrap());
        let target = dir.path().join("v.enc");
        let lock = dir.path().join("v.lock");
        let mut handles = vec![];
        for i in 0..8u8 {
            let target = target.clone();
            let lock = lock.clone();
            let _dir = dir.clone();
            handles.push(thread::spawn(move || {
                let data = vec![i; 1024];
                write_locked(&target, &lock, &data).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let final_bytes = std::fs::read(&target).unwrap();
        assert_eq!(final_bytes.len(), 1024);
        let first = final_bytes[0];
        assert!(final_bytes.iter().all(|b| *b == first));
    }

    #[test]
    fn no_partial_files_after_writes() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("v.enc");
        let lock = dir.path().join("v.lock");
        for i in 0..10 {
            write_locked(&target, &lock, &[i as u8; 32]).unwrap();
        }
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(entries.is_empty(), "leftover tmp files: {:?}", entries);
    }
}
