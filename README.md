# secrets4

AI-safe local secret-grant cache for LLM-driven workflows.

What you will mostly see here is the real life of ai agents writing iffy code and arguing with each other. 

**Platform:** Unix-like systems. `secrets4` prompts for a strong master
password to wrap the local cache key.

## Requirements

- Unix-like OS
- Rust 1.78+ to build from source
- A strong master password

## What it does

The human grants a secret to LLM use for a time-bounded window
(`30s` / `15m` / `2h` / `20d`). Within that window, an LLM-driven
agent can use the value via `secrets4 run 'cmd $env[NAME]'` after
the cache key is unlocked. Interactive use prompts for the master
password; fully unattended automation must opt in by providing
`SECRETS4_PASSWORD`. At expiry, the entry is auto-pruned and `run`
returns a deterministic exit code the LLM can react to.

The value is injected into the subprocess via the kernel's `envp`
vector — never substituted into the shell command string, never
written to argv. Subprocess stdout/stderr is scanned and any
occurrence of a granted value is replaced with `[REDACTED:NAME]`
before reaching the calling LLM harness.

## Quick start

```sh
cargo build --release
ln -s "$(pwd)/target/release/secrets4" /usr/local/bin/secrets4

# Human:
printf 'sk-...' | secrets4 grant API_KEY --ttl 8h --stdin

# LLM agent for the next 8 hours:
secrets4 run 'curl -H "Authorization: Bearer $env[API_KEY]" https://api.example.com'
```

On first use, `secrets4` asks you to create and confirm a master
password. Later commands prompt for that password when they need to
unwrap the cache key. For non-interactive automation, `SECRETS4_PASSWORD`
can provide the password explicitly; use that only in environments where
process environments are protected.

Tests that need an isolated cache should use
`SECRETS4_CONFIG_DIR=/tmp/some-dir` rather than overriding `HOME`.

## Commands

```
secrets4 grant NAME [--ttl 2h] [--stdin | --from-file PATH]
secrets4 revoke NAME
secrets4 prune
secrets4 list   [--json]
secrets4 status [--json]
secrets4 view NAME            # tty-only; refuses pipes
secrets4 run 'CMD ... $env[NAME] ...'  [--no-redact]
```

## Exit codes (stable contract for LLM consumers)

| code | meaning |
|---|---|
| 0  | ok |
| 64 | unknown grant name (on `revoke`) |
| 65 | not granted / expired (on `run`) |
| 66 | parse error in command |

## Storage

`~/.config/secrets4/` (mode `0700`):

- `cache.enc` — ChaCha20-Poly1305-encrypted grant store
- `cache.key` — Argon2id/password-wrapped 32-byte AEAD key (mode `0600`)
- `cache.lock` — flock target
- `audit.log` — NDJSON activity log (no values)

Atomic writes: tmpfile + `fsync` + `rename` + `fsync(parent)` under
`flock`. Concurrent grants/revokes serialize correctly.

For tests and one-off smoke runs, `SECRETS4_CONFIG_DIR` may be set to
override the cache directory.

## Threat model

Defended:

- Offline copy of `~/.config/secrets4/` without the master password →
  ciphertext at rest
- LLM seeing a value it injects → never echoed by `secrets4` itself
  (`view` refuses non-tty; `run` redacts subprocess output by default)
- Concurrent writes / crash mid-write → atomic + locked
- TTL elapsed → entry auto-pruned

Not defended:

- Code running as the user on the user's machine → out of scope
  (single-user trust)
- Full-machine compromise while the master password is available to the
  running user session → out of scope
- Subprocess that base64-encodes / transforms the value before
  printing → byte-exact redaction misses transformed forms

Note: this build does not use macOS Keychain as an authentication
boundary. A future macOS convenience unlock must use the native
Security/LocalAuthentication APIs with user-presence or biometric access
control; a plain generic Keychain item can be read silently by an
unlocked user session and is not sufficient.

## Design

The code and this README are authoritative for current behavior.
[`docs/design.md`](docs/design.md) is historical context and still
references earlier drafts.

## Inspiration

The `$env[NAME]` injection syntax convention is borrowed from
[scrt4](https://github.com/VestedJosh/scrt4). The rest of secrets4
is independent design and code.

## License

MIT
