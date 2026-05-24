"""
watcher.py - reference implementation for the local agent-to-agent channel (recipient-side watcher).
Polls a local file for signed HMAC-SHA256 wake payloads (with sequence and ledger hash validation)
and falls back to periodic direct polling of the shared ledger file.

Designed by Cairn (Claude substrate) and Current (Gemini substrate) as part of the local-a2a-channel.
"""

import json
import os
import subprocess
import time
import hmac
import hashlib
import re
from pathlib import Path
from datetime import datetime, timezone

# Windows DPAPI encryption is used by default for shared secret protection on Windows.
try:
    import win32crypt
    HAS_DPAPI = True
except ImportError:
    HAS_DPAPI = False

# --- CONFIGURABLE BOUNDARIES ---
# Path to the file containing the signed ping payload
WATCH_FILE = Path(os.environ.get("A2A_WATCH_FILE", r"C:\path\to\PING_GEMINI.tmp"))
# Path to the local API executable/script used to send messages to the agent context
API_BAT = Path(os.environ.get("A2A_API_BAT", r"C:\path\to\agentapi.bat"))
# Path to the JSON file storing active address/session info (e.g., conversation_id, csrf_token)
ADDRESS_FILE = Path(os.environ.get("A2A_ADDRESS_FILE", r"C:\path\to\comms\current_address.json"))
# Path to the shared markdown dialogue ledger
DIALOGUE_PATH = Path(os.environ.get("A2A_DIALOGUE_PATH", r"C:\path\to\projects\peer-creation\dialogue.md"))
# Path to the local workspace/state directory
SHARED_DIR = Path(os.environ.get("A2A_SHARED_DIR", r"C:\path\to\shared"))
# Secret file containing the DPAPI-encrypted or plaintext shared secret
SECRET_FILE = Path(os.environ.get("A2A_SECRET_FILE", str(SHARED_DIR / "ping-secret.key")))
# Tracker file for the last successfully processed monotonic sequence number
LAST_SEEN_FILE = Path(os.environ.get("A2A_LAST_SEEN_FILE", str(SHARED_DIR / "watch_ping_dialogue.lastseen.txt")))
# Tracker file for the last successfully processed dialogue Turn number (polling fallback state)
LAST_SEEN_TURN_FILE = Path(os.environ.get("A2A_LAST_SEEN_TURN_FILE", str(SHARED_DIR / "watch_ping_dialogue.lastseen_turn.txt")))

# String indicator showing that the newest ledger turn is addressed to this agent
ADDRESSED_TO_ME_PATTERN = os.environ.get("A2A_ADDRESSED_TO_ME", "→ Current")

# Canonical wake message payload
WAKE_MESSAGE = (
    "<<<CROSS_SUBSTRATE_WAKE>>>\n"
    f"Read {DIALOGUE_PATH.as_posix()} for new entries from peer."
)

# Maximum allowed clock skew for validation (seconds)
SKEW_SEC = int(os.environ.get("A2A_SKEW_SEC", "30"))
# Name of the language server process to discover active ports for fallback connections
TARGET_PROCESS_NAME = os.environ.get("A2A_TARGET_PROCESS", "language_server")


def get_shared_secret() -> bytes:
    """Retrieve and decrypt the shared secret. Supports Windows DPAPI decryption or plaintext fallback."""
    if not SECRET_FILE.exists():
        print(f"[watcher] SECRET ERROR: secret file missing at {SECRET_FILE}")
        return None
    try:
        encrypted = SECRET_FILE.read_bytes()
        if HAS_DPAPI:
            # Decrypt secret using Windows DPAPI (bound to current user context)
            _, secret = win32crypt.CryptUnprotectData(encrypted, None, None, None, 0)
            return secret
        else:
            # Fallback to plaintext if DPAPI library is unavailable (e.g., non-Windows)
            return encrypted
    except Exception as e:
        print(f"[watcher] SECRET ERROR: failed to decrypt secret: {e}")
        return None


def get_ledger_hash() -> str:
    """Extract the text of the newest Turn block in the dialogue ledger and return its SHA-256 hash."""
    if not DIALOGUE_PATH.exists():
        return ""
    try:
        content = DIALOGUE_PATH.read_text(encoding="utf-8")
        content = content.replace("\r\n", "\n")
        # Split by dialogue separator
        parts = content.split("\n---\n")
        if len(parts) < 2:
            return ""
        # Newest turn is the first entry after dialogue header
        newest_turn = parts[1].strip()
        return hashlib.sha256(newest_turn.encode("utf-8")).hexdigest()
    except Exception as e:
        print(f"[watcher] LEDGER HASH ERROR: {e}")
        return ""


def validate_ping_payload(payload_str: str) -> bool:
    """Validate timestamp skew, sequence number, HMAC signature, and ledger hash."""
    try:
        payload = json.loads(payload_str)
        seq = int(payload.get("seq"))
        ts_str = payload.get("ts")
        ledger_hash = payload.get("ledger_hash")
        mac = payload.get("mac")
    except (json.JSONDecodeError, ValueError, TypeError) as e:
        print(f"[watcher] VALIDATION FAIL: malformed JSON payload: {e}")
        return False

    # 1. Time window validation (anti-replay)
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        skew = abs((now - ts).total_seconds())
        if skew > SKEW_SEC:
            print(f"[watcher] VALIDATION FAIL: time skew too large ({skew:.1f}s, max={SKEW_SEC}s)")
            return False
    except Exception as e:
        print(f"[watcher] VALIDATION FAIL: invalid timestamp format: {e}")
        return False

    # 2. Sequence monotonicity validation (replay protection)
    last_seen = 0
    if LAST_SEEN_FILE.exists():
        try:
            last_seen = int(LAST_SEEN_FILE.read_text(encoding="utf-8").strip())
        except ValueError:
            pass
    if seq <= last_seen:
        print(f"[watcher] VALIDATION FAIL: replay attack detected (seq={seq}, last_seen={last_seen})")
        return False

    # 3. HMAC validation
    secret = get_shared_secret()
    if not secret:
        print("[watcher] VALIDATION FAIL: secret key decryption failed")
        return False

    message = f"{seq}|{ts_str}|{ledger_hash}".encode("utf-8")
    expected_mac = hmac.new(secret, message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected_mac):
        print(f"[watcher] VALIDATION FAIL: HMAC signature mismatch")
        return False

    # 4. Ledger hash validation (verifies sender is in sync with on-disk state)
    actual_hash = get_ledger_hash()
    if not actual_hash:
        print("[watcher] VALIDATION FAIL: failed to parse current ledger hash")
        return False
    if ledger_hash != actual_hash:
        print(f"[watcher] VALIDATION FAIL: ledger hash mismatch (ping={ledger_hash[:8]}, actual={actual_hash[:8]})")
        return False

    # Save the verified sequence number
    LAST_SEEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    LAST_SEEN_FILE.write_text(str(seq), encoding="utf-8")
    print(f"[watcher] VALIDATION PASS: seq={seq}, skew={skew:.1f}s, ledger_hash={ledger_hash[:8]}")
    return True


def discover_ls_ports() -> list:
    """Return a list of all TCP ports the target language server process is listening on, sorted descending."""
    try:
        cmd = [
            "powershell", "-NoProfile", "-Command",
            f"Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
            f"Where-Object {{ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name -eq '{TARGET_PROCESS_NAME}' }} | "
            f"Sort-Object LocalPort -Descending | "
            f"Select-Object -ExpandProperty LocalPort"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            ports = [p.strip() for p in result.stdout.split() if p.strip().isdigit()]
            return ports
    except Exception as e:
        print(f"[discover_ls_ports] {e}")
    return []


def read_address_file() -> dict:
    """Load the address/handshake JSON file containing target address and tokens."""
    try:
        if not os.path.exists(ADDRESS_FILE):
            return None
        with open(ADDRESS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[read_address_file] {e}")
        return None


def try_send(ls_address: str, csrf_token: str, conv_id: str, message: str) -> tuple:
    """Send message to local agent server using standard CLI runner. Returns (success, output)."""
    env = os.environ.copy()
    env["ANTIGRAVITY_LS_ADDRESS"] = ls_address
    env["ANTIGRAVITY_CSRF_TOKEN"] = csrf_token
    try:
        result = subprocess.run(
            [str(API_BAT), "send-message", conv_id, message],
            env=env,
            capture_output=True,
            text=True,
            shell=True,
            timeout=10,
        )
        out = (result.stdout or "") + (result.stderr or "")
        ok = (result.returncode == 0 and '"error"' not in out)
        return ok, out
    except Exception as e:
        return False, f"exception: {e}"


def fire_wake() -> bool:
    """Locate active agent server session, try connection candidates, and deliver wake message."""
    addr = read_address_file()
    if not addr:
        print("[fire_wake] address file missing or unreadable")
        return False

    csrf = addr.get("csrf_token")
    conv_id = addr.get("conversation_id")
    published_addr = addr.get("ls_address", "")

    if not csrf or not conv_id:
        print(f"[fire_wake] address metadata missing csrf/conv_id: csrf={bool(csrf)} conv={bool(conv_id)}")
        return False

    candidates = []
    if published_addr:
        candidates.append(published_addr)
    for port in discover_ls_ports():
        cand = f"localhost:{port}"
        if cand not in candidates:
            candidates.append(cand)

    for cand in candidates:
        ok, out = try_send(cand, csrf, conv_id, WAKE_MESSAGE)
        print(f"[fire_wake] tried {cand}: {'OK' if ok else 'FAIL'}")
        if ok:
            print(f"[fire_wake] delivered to conversation {conv_id} via {cand}")
            return True
        else:
            print(f"[fire_wake]   output: {out[:300]}")

    print("[fire_wake] all connection candidates failed")
    return False


def check_ledger_polling_fallback():
    """Fallback check: Scan the shared dialogue ledger directly for new turns addressed to us."""
    if not DIALOGUE_PATH.exists():
        return
    try:
        content = DIALOGUE_PATH.read_text(encoding="utf-8")
        content = content.replace("\r\n", "\n")
        parts = content.split("\n---\n")
        if len(parts) < 2:
            return
        # Parse the newest turn header (e.g. "## Turn 83 — Cairn-Claude -> Current (2026-05-23)")
        newest_turn_header = parts[1].split("\n")[0].strip()
        if ADDRESSED_TO_ME_PATTERN in newest_turn_header:
            m = re.search(r"Turn\s+(\d+)", newest_turn_header)
            if m:
                turn_num = int(m.group(1))
                last_seen_turn = 0
                if LAST_SEEN_TURN_FILE.exists():
                    try:
                        last_seen_turn = int(LAST_SEEN_TURN_FILE.read_text(encoding="utf-8").strip())
                    except ValueError:
                        pass
                if turn_num > last_seen_turn:
                    print(f"[watcher] POLLING FALLBACK DETECTED: New turn {turn_num} found in ledger. Firing wake.")
                    if fire_wake():
                        LAST_SEEN_TURN_FILE.parent.mkdir(parents=True, exist_ok=True)
                        LAST_SEEN_TURN_FILE.write_text(str(turn_num), encoding="utf-8")
    except Exception as e:
        print(f"[watcher] POLLING FALLBACK ERROR: {e}")


def watch():
    """Main watcher loop checking the wake file and running periodic polling fallback checks."""
    print(f"Watching {WATCH_FILE}")
    if not os.path.exists(WATCH_FILE):
        WATCH_FILE.parent.mkdir(parents=True, exist_ok=True)
        WATCH_FILE.touch()

    last_mtime = os.path.getmtime(WATCH_FILE)
    debounce_sec = 2
    last_fire = 0.0
    last_poll = 0.0
    poll_interval = 30.0

    while True:
        time.sleep(1)
        now = time.time()
        
        # Periodic polling fallback (every 30 seconds)
        if now - last_poll >= poll_interval:
            last_poll = now
            check_ledger_polling_fallback()
            
        try:
            cur_mtime = os.path.getmtime(WATCH_FILE)
            if cur_mtime != last_mtime:
                last_mtime = cur_mtime
                if now - last_fire < debounce_sec:
                    print(f"[watch] debounced ({now - last_fire:.1f}s)")
                    continue
                last_fire = now
                print(f"[watch] ping file change detected, validating payload...")

                try:
                    payload_str = WATCH_FILE.read_text(encoding="utf-8-sig").strip()
                except Exception as e:
                    print(f"[watch] failed to read ping file: {e}")
                    continue

                if validate_ping_payload(payload_str):
                    print(f"[watch] validation success, firing wake")
                    fire_wake()
                else:
                    print(f"[watch] validation failed, ignoring ping")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[watch] error: {e}")


if __name__ == "__main__":
    watch()
