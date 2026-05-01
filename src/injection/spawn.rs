use crate::injection::redact;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::io;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use zeroize::Zeroizing;

const PARENT_ENV_ALLOWLIST: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "TERM", "LANG", "LC_ALL", "TMPDIR", "SHELL", "PWD",
];

pub fn spawn_with_env(
    rewritten_cmd: &str,
    secrets: HashMap<String, Zeroizing<Vec<u8>>>,
) -> Result<ExitStatus> {
    spawn_inner(rewritten_cmd, secrets, true)
}

pub fn spawn_with_env_no_redact(
    rewritten_cmd: &str,
    secrets: HashMap<String, Zeroizing<Vec<u8>>>,
) -> Result<ExitStatus> {
    spawn_inner(rewritten_cmd, secrets, false)
}

fn spawn_inner(
    rewritten_cmd: &str,
    secrets: HashMap<String, Zeroizing<Vec<u8>>>,
    redact_output: bool,
) -> Result<ExitStatus> {
    for (k, v) in &secrets {
        if v.contains(&0u8) {
            return Err(anyhow!("secret {} contains NUL byte; refusing", k));
        }
        if std::str::from_utf8(v).is_err() {
            return Err(anyhow!(
                "secret {} is non-UTF-8; envp on Unix accepts arbitrary bytes but std::process::Command requires OsStr — refusing for v1",
                k
            ));
        }
    }

    let mut cmd = Command::new("/bin/bash");
    cmd.arg("-c").arg(rewritten_cmd).env_clear();

    for k in PARENT_ENV_ALLOWLIST {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }

    for (k, v) in &secrets {
        let s = std::str::from_utf8(v).expect("checked above");
        cmd.env(k, s);
    }

    if redact_output {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }

    let mut child = cmd.spawn().map_err(|e| anyhow!("spawn bash: {e}"))?;

    if redact_output {
        let secrets_vec: Vec<(String, Zeroizing<Vec<u8>>)> =
            secrets.into_iter().collect();
        let stdout = child.stdout.take().expect("piped");
        let stderr = child.stderr.take().expect("piped");
        let secrets_clone = secrets_vec.clone();

        let h_out = thread::spawn(move || -> io::Result<()> {
            redact::copy_redacting(stdout, io::stdout(), &secrets_vec).map(|_| ())
        });
        let h_err = thread::spawn(move || -> io::Result<()> {
            redact::copy_redacting(stderr, io::stderr(), &secrets_clone).map(|_| ())
        });

        let status = child.wait().map_err(|e| anyhow!("wait: {e}"))?;
        let _ = h_out.join();
        let _ = h_err.join();
        Ok(status)
    } else {
        let status = child.wait().map_err(|e| anyhow!("wait: {e}"))?;
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::injection::{find_tokens, rewrite};

    fn run_capture(
        cmd: &str,
        secrets: HashMap<String, Zeroizing<Vec<u8>>>,
    ) -> (i32, Vec<u8>, Vec<u8>) {
        let toks = find_tokens(cmd).unwrap();
        let rewritten = rewrite(cmd, &toks);

        let mut command = Command::new("/bin/bash");
        command
            .arg("-c")
            .arg(&rewritten)
            .env_clear()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for k in PARENT_ENV_ALLOWLIST {
            if let Ok(v) = std::env::var(k) {
                command.env(k, v);
            }
        }
        for (k, v) in &secrets {
            let s = std::str::from_utf8(v).unwrap();
            command.env(k, s);
        }
        let out = command.output().unwrap();
        (out.status.code().unwrap_or(-1), out.stdout, out.stderr)
    }

    #[test]
    fn injects_simple() {
        let mut secrets = HashMap::new();
        secrets.insert("X".to_string(), Zeroizing::new(b"hello world".to_vec()));
        let (code, stdout, stderr) =
            run_capture(r#"printf '%s' "$env[X]""#, secrets);
        assert_eq!(code, 0);
        assert_eq!(stdout, b"hello world");
        assert!(stderr.is_empty(), "stderr: {:?}", String::from_utf8_lossy(&stderr));
    }

    #[test]
    fn special_chars_pass_through() {
        let nasty: &[&[u8]] = &[
            b"p@ssw\"rd$with$specials",
            b"`backtick`",
            b"'single' \"double\"",
            b"with spaces & semis;",
            b"line1\nline2",
        ];
        for v in nasty {
            let mut secrets = HashMap::new();
            secrets.insert("X".to_string(), Zeroizing::new(v.to_vec()));
            let (code, stdout, stderr) =
                run_capture(r#"printf '%s' "$env[X]""#, secrets);
            assert_eq!(code, 0, "nonzero exit for {:?}", v);
            assert_eq!(stdout, *v, "stdout mismatch for {:?}", v);
            assert!(stderr.is_empty(), "stderr leak for {:?}: {:?}", v, stderr);
        }
    }
}
