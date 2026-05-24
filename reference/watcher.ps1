# watcher.ps1 — local-a2a-channel reference watcher (Windows / PowerShell)
#
# Polls a ping file for HMAC-signed wake payloads. On valid payload, fires the
# configured wake handler script with the canonical wake token. Also polls the
# ledger file every 30 seconds as a fallback (catches turns whose pings failed
# delivery — clock skew, focus deadlock, transient I/O).
#
# This is the reference implementation for protocol version 1.0. See
# docs/protocol-spec.md for the wire format and validation order.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File watcher.ps1 `
#     -LedgerPath "C:\path\to\ledger.md" `
#     -PingFile "C:\path\to\PING_self.tmp" `
#     -WakeHandler "C:\path\to\your-wake-handler.ps1" `
#     -SelfName "agent-a" `
#     [-SharedDir "$env:LOCALAPPDATA\local-a2a-channel"] `
#     [-LogFile "$env:LOCALAPPDATA\local-a2a-channel\watcher.log"]
#
# The WakeHandler script is invoked with a single -Message parameter carrying
# the canonical wake token. The token is intentionally generic; content lives
# in the ledger, never in the wake token (per the cooperation accord).
#
# ASCII only — non-ASCII characters in PowerShell scripts can mangle under
# default Windows CP1252.

param(
    [Parameter(Mandatory=$true)]
    [string]$LedgerPath,

    [Parameter(Mandatory=$true)]
    [string]$PingFile,

    [Parameter(Mandatory=$true)]
    [string]$WakeHandler,

    [Parameter(Mandatory=$true)]
    [string]$SelfName,

    [Parameter(Mandatory=$false)]
    [string]$SharedDir = "$env:LOCALAPPDATA\local-a2a-channel",

    [Parameter(Mandatory=$false)]
    [string]$LogFile = ""
)

$ErrorActionPreference = 'Continue'

if (-not $LogFile) {
    $LogFile = Join-Path $SharedDir "watcher.log"
}

$SecretFile       = Join-Path $SharedDir "ping-secret.key"
$LastSeenFile     = Join-Path $SharedDir "lastseen-peer.txt"
$LastSeenTurnFile = Join-Path $SharedDir "lastseen-turn.txt"
$PidFile          = Join-Path $SharedDir "watcher.pid"

# Canonical wake payload — generic instruction to read the ledger.
$WakePayload = @"
<<<A2A_WAKE>>>
Read $LedgerPath for new entries from peer.
"@

$SkewSec = 30
$DebounceSec = 2
$PollIntervalIterations = 15  # 15 * 2s loop sleep = 30s polling cadence

function Watcher-Log {
    param([string]$L)
    $stamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
    "$stamp $L" | Out-File -Append -FilePath $LogFile -Encoding utf8
}

function Get-Shared-Secret {
    if (-not (Test-Path $SecretFile)) {
        Watcher-Log "SECRET ERROR: secret file missing at $SecretFile"
        return $null
    }
    try {
        Add-Type -AssemblyName System.Security
        $encryptedBytes = [System.IO.File]::ReadAllBytes($SecretFile)
        $secretBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encryptedBytes,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return $secretBytes
    } catch {
        Watcher-Log "SECRET ERROR: failed to decrypt: $($_.Exception.Message)"
        return $null
    }
}

function Get-Ledger-Hash {
    if (-not (Test-Path $LedgerPath)) {
        Watcher-Log "LEDGER HASH ERROR: ledger missing"
        return ""
    }
    try {
        $content = [System.IO.File]::ReadAllText($LedgerPath, [System.Text.Encoding]::UTF8)
        $content = $content.Replace("`r`n", "`n")
        $parts = $content -split "(?m)^\-\-\-\r?$"
        if ($parts.Count -lt 2) { return "" }
        $newestTurn = $parts[1].Trim()
        $turnBytes = [System.Text.Encoding]::UTF8.GetBytes($newestTurn)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha.ComputeHash($turnBytes)
        $sha.Dispose()
        return ([System.BitConverter]::ToString($hashBytes) -replace '-','').ToLower()
    } catch {
        Watcher-Log "LEDGER HASH ERROR: $($_.Exception.Message)"
        return ""
    }
}

function Compare-Hex-ConstantTime {
    param([string]$a, [string]$b)
    # Constant-time hex string comparison. Returns $true if equal, $false otherwise.
    if ($null -eq $a -or $null -eq $b) { return $false }
    if ($a.Length -ne $b.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $a.Length; $i++) {
        $diff = $diff -bor ([int][char]$a[$i] -bxor [int][char]$b[$i])
    }
    return ($diff -eq 0)
}

function Test-Ping-Payload {
    param([string]$PayloadJson)
    try {
        $obj = $PayloadJson | ConvertFrom-Json -ErrorAction Stop
        $seq = [uint64]$obj.seq
        $tsStr = $obj.ts
        $ledgerHash = $obj.ledger_hash
        $mac = $obj.mac
    } catch {
        Watcher-Log "VALIDATION FAIL: malformed JSON: $($_.Exception.Message)"
        return $false
    }

    # 1. Time window
    try {
        $payloadTime = [DateTime]::Parse($tsStr).ToUniversalTime()
        $now = (Get-Date).ToUniversalTime()
        $skew = [Math]::Abs(($now - $payloadTime).TotalSeconds)
        if ($skew -gt $SkewSec) {
            Watcher-Log "VALIDATION FAIL: time skew $([math]::Round($skew,1))s (max=$SkewSec)"
            return $false
        }
    } catch {
        Watcher-Log "VALIDATION FAIL: invalid timestamp: $($_.Exception.Message)"
        return $false
    }

    # 2. Sequence monotonicity
    $lastSeen = 0
    if (Test-Path $LastSeenFile) {
        try { $lastSeen = [uint64]((Get-Content $LastSeenFile -Raw).Trim()) } catch {}
    }
    if ($seq -le $lastSeen) {
        Watcher-Log "VALIDATION FAIL: replay (seq=$seq, last_seen=$lastSeen)"
        return $false
    }

    # 3. HMAC (constant-time compare)
    $secretBytes = Get-Shared-Secret
    if ($null -eq $secretBytes) {
        Watcher-Log "VALIDATION FAIL: secret unavailable"
        return $false
    }

    $messageText = "$seq|$tsStr|$ledgerHash"
    $msgBytes = [System.Text.Encoding]::UTF8.GetBytes($messageText)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$secretBytes)
    $macBytes = $hmac.ComputeHash($msgBytes)
    $hmac.Dispose()
    $expectedMac = ([System.BitConverter]::ToString($macBytes) -replace '-','').ToLower()

    if (-not (Compare-Hex-ConstantTime $mac $expectedMac)) {
        Watcher-Log "VALIDATION FAIL: HMAC mismatch"
        return $false
    }

    # 4. Ledger hash
    $actualHash = Get-Ledger-Hash
    if (-not $actualHash) {
        Watcher-Log "VALIDATION FAIL: ledger hash unreadable"
        return $false
    }
    if (-not (Compare-Hex-ConstantTime $ledgerHash $actualHash)) {
        Watcher-Log "VALIDATION FAIL: ledger hash mismatch (ping=$($ledgerHash.Substring(0,8)), actual=$($actualHash.Substring(0,8)))"
        return $false
    }

    # Save sequence
    if (-not (Test-Path (Split-Path $LastSeenFile))) {
        New-Item -ItemType Directory -Path (Split-Path $LastSeenFile) -Force | Out-Null
    }
    $seq | Out-File -FilePath $LastSeenFile -Encoding ascii -Force
    Watcher-Log "VALIDATION PASS: seq=$seq, skew=$([math]::Round($skew,1))s, ledger_hash=$($ledgerHash.Substring(0,8))"
    return $true
}

function Get-Newest-Turn-Info {
    # Returns @{ TurnNum=int; AddressedToMe=bool } for newest turn, or $null on parse fail.
    if (-not (Test-Path $LedgerPath)) { return $null }
    try {
        $content = [System.IO.File]::ReadAllText($LedgerPath, [System.Text.Encoding]::UTF8)
        $content = $content.Replace("`r`n", "`n")
        $parts = $content -split "(?m)^---$"
        if ($parts.Count -lt 2) { return $null }
        $newestTurn = $parts[1].Trim()

        if ($newestTurn -match "## Turn (\d+) ") {
            $turnNum = [int]$matches[1]
        } else {
            return $null
        }

        $toLine = $newestTurn -split "`n" | Where-Object { $_ -match "^\*\*To:\*\*" } | Select-Object -First 1
        if (-not $toLine) { return $null }
        $addressedToMe = ($toLine -match [regex]::Escape($SelfName))

        return @{ TurnNum = $turnNum; AddressedToMe = $addressedToMe }
    } catch {
        Watcher-Log "POLL PARSE ERROR: $($_.Exception.Message)"
        return $null
    }
}

function Update-LastSeen-Turn-From-Ledger {
    $info = Get-Newest-Turn-Info
    if ($null -eq $info) { return }
    if (-not (Test-Path (Split-Path $LastSeenTurnFile))) {
        New-Item -ItemType Directory -Path (Split-Path $LastSeenTurnFile) -Force | Out-Null
    }
    $info.TurnNum | Out-File -FilePath $LastSeenTurnFile -Encoding ascii -Force
}

function Fire-Wake-Handler {
    param([string]$Reason)
    $result = & powershell -NoProfile -ExecutionPolicy Bypass -File $WakeHandler -Message $WakePayload 2>&1
    Watcher-Log "WAKE ($Reason): handler exit=$LASTEXITCODE; output: $($result -join ' | ')"
}

function Try-Poll-Ledger {
    $lastSeenTurn = 0
    if (Test-Path $LastSeenTurnFile) {
        try { $lastSeenTurn = [int]((Get-Content $LastSeenTurnFile -Raw).Trim()) } catch {}
    }

    $info = Get-Newest-Turn-Info
    if ($null -eq $info) { return }

    if (-not $info.AddressedToMe) {
        if ($info.TurnNum -gt $lastSeenTurn) {
            if (-not (Test-Path (Split-Path $LastSeenTurnFile))) {
                New-Item -ItemType Directory -Path (Split-Path $LastSeenTurnFile) -Force | Out-Null
            }
            $info.TurnNum | Out-File -FilePath $LastSeenTurnFile -Encoding ascii -Force
        }
        return
    }

    if ($info.TurnNum -le $lastSeenTurn) { return }

    Watcher-Log "POLL: new turn $($info.TurnNum) addressed to $SelfName (last_seen_turn=$lastSeenTurn)"
    if (-not (Test-Path (Split-Path $LastSeenTurnFile))) {
        New-Item -ItemType Directory -Path (Split-Path $LastSeenTurnFile) -Force | Out-Null
    }
    $info.TurnNum | Out-File -FilePath $LastSeenTurnFile -Encoding ascii -Force
    Fire-Wake-Handler "poll"
}

# PID-file singleton
$pidDir = Split-Path $PidFile -Parent
if (-not (Test-Path $pidDir)) {
    New-Item -ItemType Directory -Path $pidDir -Force | Out-Null
}
if (Test-Path $PidFile) {
    try {
        $existingPid = (Get-Content $PidFile -Raw -ErrorAction Stop).Trim()
        if ($existingPid -match '^\d+$') {
            $proc = Get-Process -Id ([int]$existingPid) -ErrorAction SilentlyContinue
            if ($proc -and $proc.ProcessName -eq 'powershell') {
                Watcher-Log "ABORT: another instance (PID $existingPid) running"
                exit 0
            }
        }
    } catch {}
}
$PID | Out-File -FilePath $PidFile -Encoding ascii -Force
Watcher-Log "Locked PID file with PID=$PID"

try {
    if (-not (Test-Path $PingFile)) {
        New-Item -ItemType File -Path $PingFile -Force | Out-Null
        Watcher-Log "Created empty ping file baseline at $PingFile"
    }

    Watcher-Log "Watcher starting. Ledger=$LedgerPath Ping=$PingFile Self=$SelfName"
    $lastMtime = (Get-Item $PingFile).LastWriteTimeUtc
    $script:lastFire = [DateTime]::MinValue
    $script:pollIterCount = 0

    while ($true) {
        Start-Sleep -Seconds 2
        $script:pollIterCount++
        try {
            if (Test-Path $PingFile) {
                $current = (Get-Item $PingFile).LastWriteTimeUtc
                if ($current -gt $lastMtime) {
                    $lastMtime = $current
                    $now = Get-Date
                    if (($now - $script:lastFire).TotalSeconds -lt $DebounceSec) {
                        Watcher-Log "Debounced"
                    } else {
                        $script:lastFire = $now
                        Watcher-Log "Ping file changed - validating..."
                        $payloadStr = ""
                        try {
                            $payloadStr = [System.IO.File]::ReadAllText($PingFile, [System.Text.Encoding]::UTF8).Trim()
                        } catch {
                            Watcher-Log "Read error: $($_.Exception.Message)"
                        }
                        if ($payloadStr -and (Test-Ping-Payload -PayloadJson $payloadStr)) {
                            Update-LastSeen-Turn-From-Ledger
                            Fire-Wake-Handler "ping"
                        } elseif ($payloadStr) {
                            Watcher-Log "validation failed (poll fallback may still catch turn)"
                        }
                    }
                }
            }
        } catch {
            Watcher-Log "Poll error: $($_.Exception.Message)"
        }

        if ($script:pollIterCount -ge $PollIntervalIterations) {
            $script:pollIterCount = 0
            try {
                Try-Poll-Ledger
            } catch {
                Watcher-Log "Poll fallback error: $($_.Exception.Message)"
            }
        }
    }
} finally {
    if (Test-Path $PidFile) {
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
        Watcher-Log "Released PID file"
    }
}
