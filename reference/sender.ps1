# sender.ps1 — local-a2a-channel reference sender (Windows / PowerShell)
#
# Reads the newest turn from a shared ledger markdown file, signs an HMAC ping
# payload bound to that ledger state, and writes the payload to a per-peer ping
# file. Receiver's watcher detects the ping mtime change, validates, fires its
# wake handler.
#
# On first run, generates a 32-byte shared secret via CSPRNG, DPAPI-encrypts it
# for the current user, and applies restrictive ACL. Subsequent runs decrypt and
# reuse the existing secret.
#
# This is the reference implementation for protocol version 1.0. See
# docs/protocol-spec.md for the wire format and validation order.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File sender.ps1 `
#     -LedgerPath "C:\path\to\ledger.md" `
#     -PingFile "C:\path\to\PING_peer.tmp" `
#     [-SharedDir "$env:LOCALAPPDATA\local-a2a-channel"]
#
# ASCII only — non-ASCII characters in PowerShell scripts can mangle under
# default Windows CP1252.

param(
    [Parameter(Mandatory=$true)]
    [string]$LedgerPath,

    [Parameter(Mandatory=$true)]
    [string]$PingFile,

    [Parameter(Mandatory=$false)]
    [string]$SharedDir = "$env:LOCALAPPDATA\local-a2a-channel"
)

$ErrorActionPreference = 'Stop'

$SecretFile = Join-Path $SharedDir "ping-secret.key"
$SeqFile    = Join-Path $SharedDir "seq-self-to-peer.txt"

# 1. Ensure shared directory exists
if (-not (Test-Path $SharedDir)) {
    New-Item -ItemType Directory -Path $SharedDir -Force | Out-Null
}

Add-Type -AssemblyName System.Security

# 2. Secret management (DPAPI)
$secretBytes = $null
if (-not (Test-Path $SecretFile)) {
    Write-Output "[sender] Generating new 32-byte shared secret..."
    $secretBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($secretBytes)

    $encryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect(
        $secretBytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    [System.IO.File]::WriteAllBytes($SecretFile, $encryptedBytes)

    # Restrictive ACL: owner-only
    icacls $SecretFile /inheritance:r /grant:r "$($env:USERNAME):F" *> $null

    # Audit log: write SHA-256 of the new secret for operator verification
    $auditSha = [System.Security.Cryptography.SHA256]::Create()
    $auditHash = $auditSha.ComputeHash($secretBytes)
    $auditSha.Dispose()
    $auditHashHex = ([System.BitConverter]::ToString($auditHash) -replace '-','').ToLower()
    Write-Output "[sender] Created DPAPI-encrypted secret at $SecretFile (SHA256: $auditHashHex)"
} else {
    $encryptedBytes = [System.IO.File]::ReadAllBytes($SecretFile)
    $secretBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encryptedBytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
}

# 3. Sequence management
$seq = 0
if (Test-Path $SeqFile) {
    try {
        $seq = [uint64]((Get-Content $SeqFile -Raw).Trim())
    } catch {
        $seq = 0
    }
}
$seq++
$seq | Out-File -FilePath $SeqFile -Encoding ascii -Force

# 4. Ledger hash (SHA-256 of newest turn body)
if (-not (Test-Path $LedgerPath)) {
    throw "Ledger file not found at $LedgerPath"
}
$content = [System.IO.File]::ReadAllText($LedgerPath, [System.Text.Encoding]::UTF8)
$content = $content.Replace("`r`n", "`n")
$parts = $content -split "(?m)^\-\-\-\r?$"
if ($parts.Count -lt 2) {
    throw "Ledger file does not contain expected turn separators ('---'). At least one turn must exist."
}
$newestTurn = $parts[1].Trim()

$turnBytes = [System.Text.Encoding]::UTF8.GetBytes($newestTurn)
$sha = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = $sha.ComputeHash($turnBytes)
$sha.Dispose()
$ledgerHash = ([System.BitConverter]::ToString($hashBytes) -replace '-','').ToLower()

# 5. HMAC signature
$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$messageText = "$seq|$ts|$ledgerHash"
$msgBytes = [System.Text.Encoding]::UTF8.GetBytes($messageText)

$hmac = New-Object System.Security.Cryptography.HMACSHA256(,$secretBytes)
$macBytes = $hmac.ComputeHash($msgBytes)
$hmac.Dispose()
$mac = ([System.BitConverter]::ToString($macBytes) -replace '-','').ToLower()

# 6. Write signed JSON payload (UTF-8 without BOM)
$payload = @{
    seq         = $seq
    ts          = $ts
    ledger_hash = $ledgerHash
    mac         = $mac
}
$payloadJson = $payload | ConvertTo-Json -Compress

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($PingFile, $payloadJson, $utf8NoBom)

Write-Output "[sender] Sent ping (seq=$seq, ledger_hash=$($ledgerHash.Substring(0,8)))"
