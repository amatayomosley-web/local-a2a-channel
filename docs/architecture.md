# Architecture

local-a2a-channel is three primitives composed: a shared markdown ledger, per-direction signed ping files, and per-agent watcher processes with hybrid edge-trigger + polling delivery.

This document explains how the primitives compose, why each piece exists, and where the boundaries lie. For the wire-format and validation details, see [protocol-spec.md](protocol-spec.md).

## Goals

1. **No API cost beyond the agents' own response generation.** Both agents would have generated tokens regardless of how they coordinated; the channel itself must add zero token cost.
2. **No central broker.** No Redis, no message queue, no orchestration service. Two agents and a shared filesystem.
3. **No network.** Cross-agent traffic stays on the local filesystem; the agents themselves talk to their respective vendor APIs only for their own response generation.
4. **Authenticated wakes.** A random local process cannot trigger wakes — only the peer agent (with the shared secret) can.
5. **Resilient to lost wakes.** If a ping fails delivery (clock skew, focus deadlock on a UI-bound wake handler, transient I/O error), the system recovers automatically rather than deadlocking.

## The three primitives

### 1. Shared markdown ledger (`ledger.md`)

An append-only markdown file at a path both agents can read and write. Newest turn at the top. Each turn has structured headers (`**From:**`, `**To:**`, `**Date:**`, `**Re:**`) and a markdown body. Turns are separated by lines containing only `---`.

Why markdown:
- Human-readable for operators
- Clean git-diff semantics if you version the ledger
- Trivially parseable for machine consumers (regex on `---` and headers)
- Renders nicely in any markdown viewer

Why append-only:
- Chronological ledger integrity — a reader at time T sees a consistent suffix of what a reader at time T+N sees
- No coordination needed on writes (each agent only appends their own turns)
- Mutating past turns breaks the implicit promise that committed content is settled

Why newest-at-top:
- Operators reading the file land on the most recent activity without scrolling
- Programmatic consumers can stop parsing after the first turn

### 2. Per-direction ping files (`PING_<peer>.tmp`)

Two files per pair: agent A writes `PING_B.tmp` when it has new content for B; agent B writes `PING_A.tmp` for new content for A.

Each ping file holds a single JSON object: `{seq, ts, ledger_hash, mac}`. Writing the file (mtime change) is the wake signal; reading the contents allows the receiver to validate.

Why a separate ping file vs touching the ledger:
- Watcher can distinguish "new content from peer" from "I just wrote my own turn"
- HMAC validation runs on a small JSON payload, not the entire ledger
- Decouples wake notification from content delivery — failed pings don't corrupt the ledger

### 3. Watcher processes

Each agent runs a watcher process (one per side) that:

a) **Polls the ping file** every ~2 seconds. When the mtime advances, read the JSON, validate (parse → time-skew → sequence → HMAC → ledger-hash), fire the wake handler if valid.

b) **Polls the ledger file** every ~30 seconds. Parse newest turn; if addressed to this agent and turn number exceeds the last seen turn, fire the wake handler. This is the polling fallback — it catches turns whose pings were lost.

c) **Fires a wake handler** when either trigger succeeds. The wake handler is the agent-UI-specific glue that signals the agent process to read the ledger. For a CLI agent, it might be a process signal; for a GUI agent, it might be a UI Automation focus-and-paste sequence.

## The full message lifecycle

```
Agent A wants to send to Agent B:

1. A appends a new turn to ledger.md (newest-at-top)
2. A computes the SHA-256 of the new turn's body → ledger_hash
3. A increments its A→B sequence counter
4. A signs HMAC-SHA256(secret, "<seq>|<ts>|<ledger_hash>") → mac
5. A writes JSON {seq, ts, ledger_hash, mac} to PING_B.tmp

Watcher B detects mtime change on PING_B.tmp:

6. Read the JSON
7. Validate timestamp within 30s of now
8. Validate seq > last seen B-side seq
9. Recompute HMAC and compare to mac (constant-time)
10. Recompute SHA-256 of ledger.md newest turn body and compare to ledger_hash
11. If all pass, write seq to B-side state file, fire wake handler

Wake handler signals Agent B:

12. B (woken) reads ledger.md newest turn
13. B processes the turn
14. B (eventually) appends its response turn → loop continues

If the ping in step 5 fails delivery (lost, expired, etc.):

15. Watcher B's polling fallback runs every 30s
16. Parse newest turn from ledger.md; check **To:** header
17. If addressed to B and turn number > last seen turn number, fire wake handler anyway
```

The hybrid edge-trigger + polling design means the system tolerates ping failures gracefully. Edge triggers give low-latency wakes when delivery succeeds; polling guarantees no permanent deadlocks.

## Cooperation accord

This is a cooperation protocol, not a zero-trust protocol. Both agents are assumed friendly and committed to a shared set of behavioral rules:

- **Append-only ledger.** No in-place editing of past turns (typo-fix within 60 seconds of own push exempt; substantive amendments not allowed).
- **One ping per new turn.** Amendments don't ping; transport retries of the same ping for delivery recovery are OK.
- **Wake injections carry canonical tokens only.** The wake handler signals "go read the ledger." Content stays in the ledger, never in the wake itself.
- **No silent reach into peer infrastructure.** Modifying peer-owned files, configs, scripts, or runtime state requires a ledger turn first.

The accord enables coordination by removing the need for either party to defend against the other. If you're using this protocol with an adversarial counterparty, the accord doesn't bind them and you need different infrastructure.

For a worked example of two agents negotiating this accord bilaterally: see [case-studies.md#wait-state-protocol](case-studies.md#wait-state-protocol).

## Boundaries

What this architecture does **not** include:

- **Encryption of ledger contents at rest.** The ledger is plaintext markdown. Add encryption separately if you need confidentiality (e.g., age-encrypt the file on disk, decrypt on read).
- **Cross-machine support.** Both agents need access to the same filesystem paths. For cross-machine deployments, mount a shared volume or use a sync tool (Dropbox, syncthing, NFS).
- **Multi-party support.** The protocol is bilateral by design. For N>2 agents, you'd need a routing layer above this — out of scope.
- **Persistence beyond the filesystem.** No state is durable beyond what's on disk. Process restarts pick up from last-seen-sequence and last-seen-turn files.
- **Discovery.** Both agents need pre-configured paths. There's no advertisement, mDNS, or broker.
