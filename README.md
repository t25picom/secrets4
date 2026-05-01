# secrets4

AI-safe secret-grant cache for LLM-driven workflows.

## What it does

The human grants a secret to LLM use for a time-bounded window
(`30s` / `15m` / `2h` / `20d`). Within that window, an LLM-driven
agent can use the value via `secrets4 run 'cmd $env[NAME]'`
without re-prompting the human. At expiry, the entry is auto-pruned
and `run` returns a deterministic exit code the LLM can react to.

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
- `cache.key` — random 32-byte AEAD key (mode `0600`)
- `cache.lock` — flock target
- `audit.log` — NDJSON activity log (no values)

Atomic writes: tmpfile + `fsync` + `rename` + `fsync(parent)` under
`flock`. Concurrent grants/revokes serialize correctly.

## Threat model

Defended:

- Disk theft / leaked backup → ciphertext at rest
- LLM seeing a value it injects → never echoed by `secrets4` itself
  (`view` refuses non-tty; `run` redacts subprocess output by default)
- Concurrent writes / crash mid-write → atomic + locked
- TTL elapsed → entry auto-pruned

Not defended:

- Code running as the user on the user's machine → out of scope
  (single-user trust)
- Subprocess that base64-encodes / transforms the value before
  printing → byte-exact redaction misses transformed forms

## Design

See [`docs/design.md`](docs/design.md). Note: design doc references
some features (master password, vault format, backup) from earlier
drafts. The current build is the LLM-grant cache described above.
The design will be updated to match.

## License

MIT
