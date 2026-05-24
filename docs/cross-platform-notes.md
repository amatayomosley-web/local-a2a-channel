# Cross-platform notes

The protocol is OS-agnostic. The only platform-specific primitive is **per-user secret storage** for the HMAC shared key. This document covers how to port the reference implementations from Windows to Linux/macOS.

## Secret storage primitive

The shared secret needs encrypted-at-rest storage scoped to the current user. The Windows reference uses DPAPI (`ProtectedData.Protect` with `DataProtectionScope.CurrentUser`); other platforms have equivalent primitives.

### Windows (reference impl)

```powershell
Add-Type -AssemblyName System.Security
$encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
    $secretBytes,
    $null,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
)
[System.IO.File]::WriteAllBytes($SecretFile, $encrypted)
icacls $SecretFile /inheritance:r /grant:r "$($env:USERNAME):F" *> $null
```

To decrypt:

```powershell
$encrypted = [System.IO.File]::ReadAllBytes($SecretFile)
$secretBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encrypted,
    $null,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
)
```

### macOS (recommended: Keychain via `security` CLI)

Store:
```bash
security add-generic-password -a "$USER" -s "local-a2a-channel" -w "$(openssl rand -hex 32)"
```

Retrieve:
```bash
security find-generic-password -a "$USER" -s "local-a2a-channel" -w
```

Or via Python `keyring` library:
```python
import keyring
import secrets

# Bootstrap
if keyring.get_password("local-a2a-channel", "shared-secret") is None:
    keyring.set_password("local-a2a-channel", "shared-secret", secrets.token_hex(32))

# Retrieve
secret_hex = keyring.get_password("local-a2a-channel", "shared-secret")
secret_bytes = bytes.fromhex(secret_hex)
```

### Linux (recommended: gnome-keyring / libsecret via `keyring`)

Same Python `keyring` API as macOS — the library auto-selects gnome-keyring, KWallet, or libsecret as available.

Requires a running secret service daemon. On headless systems, `keyring` may fall back to a less-secure file-based backend; configure explicitly if needed.

### File-only fallback (not recommended)

If no platform keyring is available, you can use a plain file with restrictive permissions:

```bash
chmod 600 ~/.local-a2a-channel/ping-secret.key
```

This is weaker than DPAPI/Keychain — any process the user runs can read the file. Use only when no keyring is available and you understand the trade-off.

## File system paths

Per-user state directory conventions:

| Platform | Recommended path |
|---|---|
| Windows | `%LOCALAPPDATA%\local-a2a-channel\` |
| macOS | `~/Library/Application Support/local-a2a-channel/` |
| Linux | `~/.local/share/local-a2a-channel/` (per XDG Base Directory) |

Inside this directory:
- `ping-secret.key` — encrypted shared secret (or keyring reference)
- `seq-<self>-to-<peer>.txt` — outgoing sender counter
- `lastseen-<peer>.txt` — incoming sequence high-water mark
- `lastseen-turn.txt` — polling state for last-processed turn

The ledger and ping files are at separate user-chosen paths (typically a shared workspace directory).

## Watcher process management

### Windows

Use Task Scheduler with `New-ScheduledTask`. Recommended pattern: one-shot trigger + periodic repetition + AtLogon trigger for self-healing.

See `reference/install-watcher.ps1.example` for the registration pattern.

### macOS

Use `launchd` with a `.plist` agent in `~/Library/LaunchAgents/`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.local-a2a-channel.watcher</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/python3</string>
        <string>/path/to/watcher.py</string>
        <string>--ledger</string>
        <string>/path/to/ledger.md</string>
        <string>--ping</string>
        <string>/path/to/PING_self.tmp</string>
        <string>--wake-handler</string>
        <string>/path/to/your-wake-handler.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Load with `launchctl load ~/Library/LaunchAgents/com.user.local-a2a-channel.watcher.plist`.

### Linux

Use a systemd user unit at `~/.config/systemd/user/local-a2a-channel.service`:

```ini
[Unit]
Description=local-a2a-channel watcher

[Service]
ExecStart=/usr/bin/python3 /path/to/watcher.py --ledger /path/to/ledger.md --ping /path/to/PING_self.tmp --wake-handler /path/to/your-wake-handler.sh
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
```

Enable with `systemctl --user enable --now local-a2a-channel.service`.

## Wake handler portability

The wake handler is the most agent-UI-specific piece. The protocol provides reference implementations for two specific UIs (Claude Desktop on Windows, Antigravity IDE on Windows) but other UIs need their own handlers.

What a wake handler must do:
- Receive a canonical wake token (e.g., `<<<CROSS_SUBSTRATE_WAKE>>>\nRead <ledger-path> for new entries.`)
- Signal the target agent process to read the ledger
- Never carry content payloads beyond the canonical token

How to deliver the signal depends on the agent's input modality:
- **CLI agents** with stdin: write the token to the agent's stdin
- **GUI agents** with a chat input: UI Automation focus + clipboard paste + Enter (Windows), AppleScript / Accessibility APIs (macOS)
- **Process-IPC agents** with a named pipe or socket: write the token to the IPC endpoint
- **Agents with a webhook**: HTTP POST to a localhost-only endpoint

The wake-handler interface is intentionally narrow (one input: the token; one effect: "agent now knows to read the ledger") so the protocol stays agent-UI-agnostic.

## Timing constants

Defaults in the reference implementation. Tune per deployment if your filesystem latency or agent response time differs.

| Constant | Default | Description |
|---|---|---|
| `PingPollInterval` | 2 seconds | How often the watcher checks the ping file mtime |
| `LedgerPollInterval` | 30 seconds | How often the watcher checks the ledger for missed turns |
| `DebounceWindow` | 2 seconds | Minimum gap between wake fires (prevents wake storms) |
| `TimeSkewWindow` | 30 seconds | Max acceptable clock skew on ping validation |
| `WakeHandlerTimeout` | 10 seconds | Max wait for wake handler to complete before logging warning |

## Testing across platforms

If you run agents on different OS pairs (e.g., one Windows + one Linux), the protocol works as long as:
- Both agents agree on file path conventions (use absolute paths in configuration)
- Both implementations follow the same `ledger_hash` algorithm (UTF-8 encoding, `\r\n → \n` normalization, regex split, SHA-256)
- The shared filesystem preserves file mtimes (most networked filesystems do; verify your specific NFS/SMB setup)

The wire format (JSON ping) is fully cross-platform. The variations are in storage, scheduler, and wake-handler glue.
