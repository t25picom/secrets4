# secrets4 — design

**Status:** draft for review
**Date:** 2026-04-30
**Owner:** the user
**Replaces:** scrt4 (community v0.2.x), as the user's local AI-safe secret vault

## 1. Why we're doing this

scrt4 is the current vault. It has two recurring bugs that justify a rewrite, not a patch:

1. **Output-safety bug.** Secret values that contain shell metacharacters (`$`, backticks, quotes, newlines) leak into stdout/stderr — and therefore into the AI agent's tool-output context. Root cause: scrt4 substitutes `$env[NAME]` placeholders into a shell command string before exec; a `"` or `$` in the value breaks shell parsing and the value ends up in the parser's error path.
2. **Durability bug.** `scrt4 add` silently drops writes. Newly-added secrets vanish. Recovered only because the user had backups. Root cause: vault writes are not atomic and the long-running daemon races with the CLI.

Both are textbook "bash is the wrong tool for this" failures. The rewrite addresses them at the architectural level, not patch-by-patch.

## 2. Goals and non-goals

### Goals (in priority order)

1. **AI-safe injection.** A secret value never appears in the AI agent's tool output, regardless of byte content. Special characters, multibyte, control chars, newlines — all safe.
2. **Durable writes.** Every successful `add` survives crash, power loss, concurrent invocation. No silent drops.
3. **Strong unlock.** Master password protected by Argon2id with parameters sized to the host. No weak-password footguns at setup.
4. **Auditable.** Single Rust binary, ≤ ~2.5k LoC of our code, vetted crypto crates, no plugin/module system.
5. **Drop-in for daily use.** Same mental model as `op run` / `scrt4 run`: write `$env[NAME]` in your command, get the value injected at exec time.
6. **Long-lived backups stay safe** even against a future cryptographically-relevant quantum computer (CRQC).

### Non-goals (explicitly out of scope for v1)

- Multi-user / team / cloud sync.
- Built-in cloud backup (use `secrets4 export-backup` and put the file wherever you want).
- GUI, notepad, system tray, menu module.
- Magic Wormhole sharing.
- Approval workflows / phone-push / Pushover / iMessage. (Future v2 candidate; not in v1.)
- WebAuthn / FIDO2 / Touch ID / Secure Enclave binding. (See §4 for rationale.)
- YubiKey hardware second factor. (Future v1.1 candidate; not v1.)

## 3. Threat model

### Defended

| Threat | Defense |
|---|---|
| Disk theft / leaked backup | Vault encrypted at rest with ChaCha20-Poly1305 using a DEK that is only recoverable by deriving it from the master password via Argon2id |
| AI sees secret in conversation | Secret is never substituted into the command string; it's passed via the subprocess `envp` and referenced by the shell as `$NAME`. Shell-quoting bugs are impossible because the secret never touches the shell parser |
| AI tries `cat ~/.config/secrets4/vault.enc` | File contents are ciphertext |
| AI tries `secrets4 view <name>` | `view` requires a fresh password unlock and writes only to a tty (refuses if stdout is a pipe). When invoked by Claude Code's Bash tool, stdout *is* a pipe, so `view` fails closed |
| Crash mid-`add` | Atomic write: write-tempfile + `fsync` + `rename` over old file + `fsync` parent dir. Either old or new vault on disk, never partial |
| Concurrent `add` from two shells | Advisory lock (`flock`) on `~/.config/secrets4/vault.lock` for the duration of any mutating operation |
| Long-lived backup attacked by future CRQC | Backup format wraps DEK with hybrid X25519 + ML-KEM-768 KEM. Attacker must break BOTH (currently no known way to break either at scale) |
| Cold-boot attack on running daemon | DEK held in `Zeroizing<[u8; 32]>`; `mlock`'d page; explicit zero on lock / TTL / signal |

### Not defended (out of scope by design)

- **Malicious code running as the user on the user's Mac.** That code can ptrace the daemon, read the socket, scan memory. Single-user-trust is the boundary. Anyone targeting the user this way already won.
- **Compromised Rust supply chain.** Mitigated by `cargo audit` in CI and pinned dependencies, but not vendored-everything. Acceptable.
- **Subprocess that itself prints the secret.** If the user runs `secrets4 run 'echo $env[X]'`, the secret appears in stdout — by the subprocess's own choice. We offer optional output redaction (§7) as belt-and-suspenders, but it is *not* the security boundary.

## 4. Authentication: password-only

### Decision

Master password is the only unlock factor in v1. No Touch ID, no Secure Enclave, no WebAuthn.

### Why password-only (not Touch ID + password)

The previous draft of this design had two independent wraps on disk: one Touch ID-bound, one password-derived. Reasons we dropped the Touch ID wrap:

1. **Caveats made it second-class anyway.** Touch ID via Secure Enclave only works when the Mac is logged in at the console — not at the lockscreen, not over SSH, not lid-closed without an external sensor, not on a fresh Mac after disaster recovery. The headless and agent paths are exactly the user's main use case for abpm. Touch ID was already a "sometimes" path.
2. **Two wraps = two bug surfaces, two synchronization points.** Adding Touch ID adds the LocalAuthentication framework binding, Keychain ACL setup, biometric prompt rendering, "what happens when the user re-enrolls a finger" recovery code, and a second on-disk envelope. Estimated ~500 LoC and a whole platform-specific dependency.
3. **One mental model.** Same unlock everywhere: console, SSH, agent, lid-closed, new Mac. No "this works here but not there" footgun.
4. **Forces strong entropy at setup.** A password-only design treats the password as load-bearing, so setup will steer the user to a strong passphrase rather than tolerating a weak one because Touch ID hides it most of the time.
5. **Apple-portable becomes Unix-portable.** No SE chip lock-in.

### Master password requirements

- Minimum 16 characters or 5+ word passphrase.
- `secrets4 setup` runs a **diceware generator** (EFF long wordlist, 6 words ≈ 77.5 bits) and offers the generated passphrase as the default. User can accept or supply their own.
- If user supplies their own, it must pass a minimum-entropy check: ≥ 14 chars AND not in the top-10k common-passwords list (bundled at compile time, ~80 KB).
- Password is **never stored on disk in any form**. Only the Argon2id-derived wrap-key encrypts the DEK.

### Argon2id parameters

- **memory:** 256 MiB
- **iterations:** 4
- **parallelism:** 1
- **target unlock cost:** ~500 ms on M-series Macs
- Parameters are stored in the vault header so they can be increased on `rotate` without breaking older vaults.

### Session lifecycle (daemon)

- A small daemon (`secrets4-agent`) holds the unwrapped DEK in memory after a successful unlock.
- TTL configurable; default 4 hours from last use.
- `secrets4 lock` zeroizes immediately.
- Daemon listens on `~/.config/secrets4/sock` (mode 0600, owner-only).
- Daemon binary is the same as the CLI; spawned via `secrets4 unlock` or `launchd` user-agent.
- See §6 for protocol.

### Optional v1.1 — YubiKey

Out of scope for v1. Sketched here only so v1's vault format doesn't preclude it later: the wrap-key can be a HKDF over multiple inputs (Argon2id-of-password, optionally HMAC-SHA1 challenge-response from a YubiKey). v1 vault header reserves a `factors[]` array; v1 has one entry; v1.1 adds a second.

## 5. Vault storage

### Layout

```
~/.config/secrets4/        # mode 0700, owned by user
├── vault.enc              # 0600. Encrypted vault. ChaCha20-Poly1305. Atomically written.
├── vault.lock             # 0600. flock target; zero-byte
├── sock                   # 0600. Unix socket for daemon
├── agent.pid              # 0600. Daemon pid (for inspection only; not load-bearing)
└── audit.log              # 0600. Append-only NDJSON; one line per access (lock/unlock/run/view/add/rm)
```

`secrets4 setup` enforces `0700` on the parent dir at every invocation; `setup` and the daemon refuse to start if the dir is group- or world-readable. This closes the "socket is `0600` but dir is `0755` so a sibling user could `connect()` to the socket path" loophole that would otherwise exist on a multi-user box.

### Vault file format (versioned envelope)

Binary frame:

```
"S4\x01"               # 4-byte magic + version
header_len: u32        # little-endian length of header bytes
header: bytes          # CBOR-encoded HeaderV1 (see below); authenticated by AEAD AD
nonce: 12 bytes        # ChaCha20-Poly1305 nonce, fresh per write
ciphertext: bytes      # AEAD ciphertext of vault body
tag: 16 bytes          # Poly1305 tag
```

`HeaderV1` (CBOR):
```
{
  "v": 1,
  "kdf": {
    "alg": "argon2id",
    "m": 262144,    # KiB; 256 MiB
    "t": 4,
    "p": 1,
    "salt": <16 bytes>
  },
  "aead": "chacha20-poly1305",
  "wrap": <32 bytes>,   # the DEK, AEAD-encrypted by Argon2id-derived wrap-key
  "wrap_nonce": <12 bytes>,
  "wrap_tag": <16 bytes>,
  "factors": ["password"],   # extension point for v1.1 YubiKey/etc.
  "created": <iso-8601>,
  "rotated": <iso-8601>
}
```

The `header` bytes are passed as **associated data** to the body AEAD, so any tampering with header parameters (e.g., downgrading Argon2 cost) invalidates the body.

Vault body plaintext is CBOR:
```
{
  "secrets": {
    "<NAME>": {
      "value": "<utf-8 string OR bytes>",
      "kind": "string" | "bytes",
      "tags": ["personal", ...],
      "created": <iso-8601>,
      "updated": <iso-8601>,
      "notes": "<optional>"
    },
    ...
  },
  "version": <monotonic int, incremented on each write>
}
```

### Atomic write

Every mutating operation:
1. Acquire exclusive `flock` on `vault.lock`.
2. Read current `vault.enc`, decrypt, mutate in memory.
3. Bump `version`.
4. Encrypt with **fresh nonce**.
5. Write to `vault.enc.tmp.<pid>.<rand>` in the same dir.
6. `fsync(tmpfile)`.
7. `rename(tmp, vault.enc)`.
8. `fsync(parent_dir)`.
9. Release lock.

No daemon-mediated write path; the daemon is read-only against the vault file. Writes go through the CLI under flock. This eliminates the daemon-CLI race that drops `add` writes in scrt4.

### Audit log

`audit.log` is append-only NDJSON. Each line:
```
{"t": "<iso8601>", "op": "unlock|lock|run|view|add|rm|rotate", "name": "<secret-name|null>", "session": "<uuid>", "result": "ok|err:<reason>"}
```

Never contains secret values. Used for forensic review only. Log rotates at 10 MiB; old log is gzipped to `audit.log.1.gz`.

## 6. Daemon protocol

### Process lifecycle

- Spawned by `secrets4 unlock` if no live socket present.
- Detaches via double-fork; logs to `~/.config/secrets4/agent.log`.
- Listens on `~/.config/secrets4/sock` (`SOCK_STREAM`, 0600).
- On idle TTL expiry: zeroizes DEK, exits.
- On SIGTERM/SIGINT: zeroizes DEK, removes socket, exits.
- Memory: DEK and unwrapped secret values are in `Zeroizing<...>` and `mlock`'d (best-effort).

### Wire protocol

Length-prefixed CBOR. Each request:
```
{ "op": "...", "args": {...}, "req_id": <uuid> }
```

Each response:
```
{ "ok": true, "result": {...} } | { "ok": false, "err": "<msg>" }
```

### Where Argon2id runs

The CLI process runs Argon2id (in `secrets4 unlock`), derives the wrap-key, and decrypts the DEK. The CLI sends the **already-unwrapped DEK** to the daemon. The daemon never sees the plaintext password and never runs Argon2id. Reasons:

- Single locus for password handling — easier to audit.
- Daemon is long-lived; minimizing what touches it minimizes blast radius.
- Failed unlocks (wrong password) don't churn daemon state.

The CLI zeroizes the password buffer immediately after Argon2id, and the wrap-key immediately after AEAD-decrypting the DEK. Only the DEK travels to the daemon.

### Operations

| Op | Args | Returns |
|---|---|---|
| `status` | — | `{unlocked, ttl_remaining, secret_count}` |
| `set_dek` | `{dek: <32 bytes>, ttl?}` | `{unlocked: true}` (sent by CLI after it decrypted DEK; daemon stores it) |
| `lock` | — | `{}` |
| `list` | `{tag?}` | `{names: [...]}` |
| `get_for_run` | `{names: [...], req_id}` | `{values: {...}}` (only invoked by `secrets4 run`; daemon enforces caller-pid check via `SO_PEERCRED` / `getpeereid`) |
| `get_for_view` | `{name, fd: tty_fd}` | streams value to provided tty fd, refuses if not a tty |

`get_for_view` does **not** re-prompt for the password. An unlocked session is the gate. The exfil defense is the tty-only output channel: when stdout is a pipe (which it always is under Claude Code's Bash tool), `view` returns an error before any value travels through the daemon.

The daemon **never** returns secret values over the socket as JSON the CLI prints. `view` writes directly to a tty file descriptor passed via SCM_RIGHTS; if the caller doesn't have a tty, view fails. This closes the "AI runs `secrets4 view X` and reads the output" path.

`get_for_run` returns values to the CLI process which then immediately exec's the subprocess (see §7). The values exist in the CLI's memory only between socket read and `execvpe`. The CLI process is short-lived.

### Authentication of the socket

Socket is `0600`, owned by the user. macOS UDS file-permission ACL is sufficient — no code running as the user is excluded from any of the user's stuff anyway, by threat model. This matches scrt4's posture.

## 7. The injection contract — *the* fix for the leak bug

### scrt4's bug, precisely

scrt4's `run 'curl -H "Bearer $env[X]"...'`:

1. Reads the command string.
2. **Performs literal string substitution** of `$env[X]` with the value.
3. Passes the resulting string to `bash -c`.

If the value is `p@ssw"rd$with$specials`, the substituted string becomes:
```
curl -H "Bearer p@ssw"rd$with$specials"...
```
The shell tokenizer breaks. Bash emits a parse error to stderr containing the value. Claude reads stderr. **Secret in AI context.**

### secrets4's contract

`secrets4 run 'curl -H "Bearer $env[GITHUB_PAT]" https://api.github.com'`:

1. Parse the command string ourselves looking for `$env[NAME]` tokens. Validate each NAME against `[A-Z_][A-Z0-9_]*`.
2. **Replace each `$env[NAME]` with the literal string `${NAME}` in the command string.** This is a syntactic rewrite. Now the command is `curl -H "Bearer ${GITHUB_PAT}" ...`.
3. Fetch values from daemon for the requested names. Build an `envp` map: `{GITHUB_PAT=<actual-value>, ...}`.
4. `posix_spawn` (or `fork`+`execvpe`) `bash -c <rewritten-command>` with the env populated.

The shell expands `${GITHUB_PAT}` from its environment at runtime. The secret value is passed through the kernel's environ-vector to the subprocess; **it is never substituted into the command string and never goes through the shell parser**. Special characters in the value are irrelevant to the shell because the shell sees only `${GITHUB_PAT}`.

### Why this is bulletproof

- The bytes between `secrets4` and the subprocess are the kernel's `envp`, a length-prefixed binary array. No quoting, no parsing, no escaping.
- The subprocess receives the value in its `extern char **environ`. Whatever the subprocess does with it (passes to a `curl` call, base64-encodes it, etc.) is between the subprocess and its libraries.
- Empty values, NUL bytes (rejected at `add` time), 8-bit binary, multibyte UTF-8 — all pass through `envp` cleanly.
- If parsing finds `$env[NAME]` with no matching secret, `secrets4 run` fails BEFORE spawning anything. No silent value-of-empty.

### Belt-and-suspenders: optional output redaction

By default, `secrets4 run` does NOT redact subprocess output. The threat model says "subprocess prints its own secrets" is the subprocess's problem.

Optional `--redact` flag enables an output filter: the CLI knows the values it injected; it scans the subprocess's stdout/stderr in fixed-size buffers and replaces matches with `[REDACTED:<NAME>]`. Caveats explicitly documented:
- May miss values split across read boundaries (we mitigate with a sliding window of `max_value_len` bytes).
- Adds latency (~one memmem per chunk).
- NOT a security boundary. Just a courtesy.

`--redact` is off by default. the user's discipline is to never invoke commands that print their own secrets; the redactor is for paste-into-curl-with-typo cases.

### Forbidden command shapes

`secrets4 run` rejects (before spawning):
- `$env[X]` where X is not a known secret name → error.
- `$env[X]` where X is not `[A-Z_][A-Z0-9_]*` → error.
- Any byte in a secret value that is `\0` → rejected at `add`, never stored.

Notably, we do NOT block `echo $env[X]` or `cat << EOF\n$env[X]\nEOF`. The user is allowed to do dumb things. Documented.

## 8. Command surface (v1)

```
secrets4 setup                       # one-time: pick passphrase, init vault
secrets4 unlock [--stdin] [--ttl N]  # start session; password from tty or stdin
secrets4 lock                        # end session
secrets4 status                      # is unlocked? ttl? secret count?
secrets4 list [--tag T]              # list NAMES (never values)
secrets4 add NAME                    # prompts for value via tty (no echo); rejects \0
secrets4 add NAME --stdin            # value from stdin (for piping); rejects \0
secrets4 add NAME --from-file PATH   # value from file (binary or text)
                                     # NOTE: NO `add NAME=VALUE` form — that would put the value
                                     # in argv where `ps` and process listings can read it.
secrets4 rm NAME [--force]           # confirm-prompt unless --force
secrets4 view NAME                   # print to tty; refuses on non-tty
secrets4 run 'CMD ... $env[NAME]...'  # the main verb
secrets4 rotate                      # new DEK, new password (prompts both old + new), re-encrypt
secrets4 export-backup PATH [--to-pubkey FILE]   # see §9
secrets4 import-backup PATH                       # restore
secrets4 import-from-scrt4           # one-shot migration (see §10)
secrets4 daemon                      # foreground daemon (for launchd)
secrets4 verify-self                 # check binary against pinned SHA256SUMS
```

10 user-facing commands + 1 daemon + 1 self-check. Compare scrt4: 30+ across modules.

## 9. Backup export — where post-quantum actually earns its keep

### Threat we care about here

A backup file (`vault.bak`) sits in the user's Drive / iCloud / S3 for years. Captured today, attacked decades from now with a CRQC. Anything ECDH-bound falls. We need this blob to survive.

### Approach: hybrid X25519 + ML-KEM-768 KEM

Backup format wraps the DEK with a hybrid KEM. Two paths to recipient key, depending on `--to-pubkey`:

- **No recipient (default):** wraps DEK with the same Argon2id-derived wrap-key as the live vault (i.e., the master passphrase decrypts both). Symmetric → already PQ-safe. Simple. This is the path the user uses for self-backup.
- **With recipient (`--to-pubkey FILE`):** generates ephemeral X25519 + ML-KEM-768 keypair, performs both KEMs against the recipient's public key (which is also a hybrid bundle), concatenates the two shared secrets, runs HKDF, AEADs the DEK with the result. Encodes ephemeral pubkeys + ML-KEM ciphertext + AEAD'd DEK + AEAD'd vault body into the file.

For v1, the **no-recipient path is enough** — the user's backup is for himself. Recipient-public-key support is implemented but no `setup` flow promotes it; users can opt in for "give my emergency contact a sealed copy" later.

### Backup file format

```
"S4B\x01"                # magic + version
header_len: u32
header: cbor             # KemParamsV1 (type, salt OR ephem pubkeys, etc.)
ciphertext_dek: ...      # AEAD'd DEK
ciphertext_vault: ...    # AEAD'd vault body, key derived per §5
```

Crate choices:
- ML-KEM: `ml-kem` (RustCrypto) — pure Rust, NIST FIPS 203 compliant.
- X25519: `x25519-dalek`.
- KDF: `hkdf` over SHA-256.
- AEAD: `chacha20poly1305`.

### What this DOESN'T do

It doesn't re-key the live vault with PQ crypto. The live vault is symmetric-only (Argon2id → wrap-key → AEAD), already PQ-safe. PQ enters only at the backup-export boundary because that's the only on-disk artifact whose recipient public key would otherwise be ECDH-bound.

## 10. Migration from scrt4

### The constraint that shapes this

scrt4's run-command shell substitution is the very bug we're rewriting around. Any migration path that goes through `scrt4 run 'cmd $env[X]'` would re-trigger the special-character leak for the affected secrets — which is precisely the subset most worth migrating safely.

So `import-from-scrt4` cannot rely on `scrt4 run`. Two acceptable paths, both supported:

### Path A: scrt4 view (recommended for the bulk)

`scrt4 view --cli NAME` prints the value to its stdout once. We capture it via:

```
val_bytes=$(scrt4 view --cli "$name")    # captured by the import tool, not the AI
secrets4 add "$name" --stdin <<< "$val_bytes"
```

The import tool runs as a single Rust process — values flow through pipes between scrt4 and secrets4 only, never echoed, never written to a tempfile that touches the AI's view. The tool never prints the value itself. Trailing newline (if any) from `view --cli` is stripped from `val_bytes` before storing — documented behavior.

### Path B: vault-file decryption (fallback for affected values)

For values where Path A is suspect (e.g., the user knows a particular secret was failing in scrt4), we bypass scrt4's runtime entirely:

1. User runs `scrt4 backup-key --reveal` once to obtain the master key (base64).
2. `secrets4 import-from-scrt4 --vault-key <base64-key> --vault-path ~/.config/scrt4/vault`.
3. We decrypt scrt4's vault format directly (it's documented in scrt4's source — AES-256-GCM with the master key as KEK).
4. Walk the decrypted entries and `secrets4 add` each.

The master-key-reveal flow is brief and we instruct the user to lock their session after.

### Verification

The import tool runs in a single Rust process. For each name:

1. Read value from scrt4 (Path A or B) into `Zeroizing<Vec<u8>>` buffer A.
2. Call `secrets4 add NAME --stdin` with buffer A.
3. Re-read the just-stored value from secrets4 into `Zeroizing<Vec<u8>>` buffer B.
4. Constant-time compare A and B; mismatch → flag the secret in a per-run report.
5. Drop both buffers (zeroized).

No external hash. The tool never prints either buffer. The summary report contains only names + ok/mismatch flags.

### After migration

- User keeps scrt4 installed for a week as fallback.
- `secrets4 status --compare-scrt4` shows side-by-side secret-count diffs.
- Once confident: `scrt4 logout`, then `brew uninstall scrt4 && rm -rf ~/.config/scrt4`.

## 11. Testing strategy

### Unit tests

- Argon2id round-trip with known vectors.
- Vault round-trip: encrypt → decrypt with same params; tampered header rejected.
- Atomic write under simulated crash (kill the process between tmp-write and rename; assert old vault intact).
- Concurrent-write test: two threads each call `add`; both succeed; both values present at end.
- `$env[NAME]` rewriter: covers all bytes 0x00–0xFF in values; pass through `envp` unchanged.
- Refuses NAME with non-conformant chars; refuses value containing `\0`.

### Integration tests

- Spawn daemon, unlock, run a real subprocess (`echo $X`), assert stdout is exactly the value with no shell parse errors.
- View command: invoke from a non-tty (pipe) → fails. Invoke from a pty → succeeds.
- Crash the daemon mid-session → no plaintext on disk.

### Adversarial corpus

A property-based test (`proptest`) generates arbitrary byte sequences (including all shell metacharacters, NULs, valid/invalid UTF-8, very long values) as secret values and asserts:
1. Round-trip through vault: identical.
2. `secrets4 run 'printf "%s" "$env[X]"'` prints exactly the bytes; no extra characters; no error on stderr.
3. `secrets4 run` never invokes `bash` with the value embedded in argv (verified by ptrace-style spawn intercept in tests).

### Manual / end-to-end

- Set up fresh; passphrase generation flow.
- Add 30 secrets matching the user's scrt4 list; export-backup; nuke vault dir; import-backup; verify all 30 round-trip.
- Inject several known scrt4-leak-inducing values (passwords with `$`, `"`, `\n`) and confirm no leak.

## 12. Implementation phases

| Phase | Deliverable | Estimate |
|---|---|---|
| 1 | Vault format + atomic writes + Argon2id + AEAD round-trip (no daemon, no run) | 1 day |
| 2 | CLI: `setup`, `unlock` (in-process key cache), `add`, `list`, `view`, `rm`, `lock` | 1 day |
| 3 | `run` with `$env[NAME]` envp injection, full adversarial test corpus | 1 day |
| 4 | Daemon + socket protocol + `view`-via-tty-fd | 1 day |
| 5 | `rotate`, `export-backup` / `import-backup` (Argon2id path; PQ later) | 0.5 day |
| 6 | `import-from-scrt4` migration | 0.5 day |
| 7 | Hybrid X25519 + ML-KEM-768 backup recipient path | 0.5 day |
| 8 | Hardening: zeroize, mlock, audit log rotation, `verify-self` | 0.5 day |

Realistic 5–6 days end to end given the design is solid and we only spend time on code, not architecture.

## 13. Open questions (resolved or deferred)

- **Should `secrets4` be a separate binary or replace `scrt4` symlinks?** → Separate. Coexist during migration. the user `scrt4 logout` and remove later.
- **Should we ship a Claude Code hook that gates `secrets4 view`?** → No; `view` already refuses on non-tty, which is the equivalent gate. The 1Password Guard plugin pattern is unnecessary because `secrets4`'s contract is tighter than `op`'s.
- **Should we ship a Homebrew tap?** → Not v1. Build locally. Tap is a v1.1 polish item.
- **Where does the audit log live in a backup?** → Excluded. `export-backup` ships `vault.enc` only. Audit history is per-machine, not vault content.

## 14. Out-of-scope work that this design does NOT preclude

- v1.1: YubiKey HMAC-SHA1 second factor (`factors[]` array in header reserves room).
- v2: Phone-approval workflow (Pushover/iMessage). Daemon grows a "pending approval" state; `unlock` becomes "request → approve → unlock". The vault format is unchanged.
- v2: Per-secret access policies (some secrets need re-prompt regardless of session).
- v2: Web UI / TUI for browsing.
