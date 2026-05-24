# Case studies

Three worked examples from the project that motivated this protocol. Each names a specific problem we hit, the design we landed on, and what we learned. These aren't theoretical — they're what happened.

## HMAC IPC

### Problem

The original wake mechanism was an empty file-touch: when sender wanted to wake receiver, it would `touch PING_<peer>.tmp`, and the receiver's watcher would react to any mtime change.

Threat: any local process under the same user account could trigger wakes by touching the file. A misbehaving browser extension, a poorly-written background daemon, even an accidental `find -mtime` could trigger a wake storm. Worse: an attacker with local code execution could drive the wake loop indefinitely, exhausting the receiver agent's API quota.

### What we considered

Three options, in order of complexity:

| Option | Pros | Cons |
|---|---|---|
| **mTLS over local TCP** | Strong cryptographic trust | Cert management, port allocation, CA chain — heavy footprint for a local IPC mechanism |
| **Named pipes with Windows ACL** | Native OS security descriptors; no shared secret needed | Windows-specific; harder to port |
| **HMAC-signed file payloads** | Symmetric — easy to manage locally; replay protection via sequence; portable | Requires shared secret; doesn't help against same-user compromise |

### What we picked: HMAC

Reasoning:
- Same-user compromise is already game-over for any local IPC scheme (mTLS won't help — the attacker can read the cert too)
- The defense we actually need is against *unprivileged local processes* triggering wakes
- HMAC + sequence + ledger-hash gives us that without the operational burden of cert management
- Portable across OSes (DPAPI on Windows, Keychain on macOS, gnome-keyring on Linux all expose the same primitive)

### What HMAC + sequence + ledger-hash actually defends against

- **Unauthorized local process triggering wakes** — they don't have the secret, so any ping they write fails HMAC verification
- **Replay of a captured ping within the 30s window** — sequence monotonicity rejects it
- **Replay beyond 30s** — time-skew check rejects it
- **Spoofed ping against a stale ledger state** — ledger-hash binds the ping to the ledger content the sender saw

What it doesn't defend against: an attacker who is already running as your user. That's not a defense the protocol can offer — at that point, the attacker can also read your `~/.ssh/`, your OAuth tokens, etc. The protocol's job is to defend up to the OS user boundary.

### Implementation detail: constant-time compare

The first PowerShell implementation used `$mac -ne $expectedMac` for the verification step. That's a short-circuiting string compare — it leaks timing information about which byte of the MAC mismatched. Found during a self-audit; fixed by switching to a byte-by-byte XOR-accumulate.

The Python reference uses `hmac.compare_digest()` which is correct by construction. The PowerShell reference now does the equivalent manually.

Lesson: cryptographic primitives have non-obvious correctness criteria. Even when the algorithm is right, the comparison can be wrong. Audit specifically for timing safety, not just for "does HMAC compute correctly."

## Polling fallback

### Problem

Edge-triggered wake delivery has failure modes that don't recover automatically:

- **Clock skew**: sender's clock drifts; ping's `ts` field falls outside the 30-second window; receiver's watcher silently drops it as a validation failure. Sender has no signal that delivery failed.
- **Focus deadlock**: receiver's wake handler is a UI Automation paste into a GUI app. If the app isn't foregrounded, the paste fails (Windows focus-stealing prevention blocks background processes from forcing focus). Ping was validly delivered to the watcher, but the wake handler bailed.
- **Transient I/O**: filesystem watcher misses an mtime event (rare but happens on heavily-loaded systems).

In all three cases, the receiver never wakes. The sender thinks delivery succeeded (their ping write returned success). The loop deadlocks.

### What we tried first

Adding retries to the sender. Send the same ping again every 2 minutes if no response is observed. This produced two new failures:

- **Wake storms**: the receiver's wake handler succeeds eventually, fires the wake, but the sender doesn't know — keeps re-sending. Receiver gets the same wake repeatedly.
- **Sequence exhaustion**: every retry incremented the sequence number, but the receiver had already accepted the original. Now the retries fail sequence-monotonicity and get dropped, looking identical (to the sender) to the original problem.

Neither helped. The retry pattern was treating a delivery-confirmation problem as if it were a transport problem.

### What we landed on: hybrid edge-trigger + polling

Each watcher additionally polls the ledger every 30 seconds:

1. Parse newest turn from `ledger.md`
2. Extract turn number from `## Turn N — ` header
3. Read `**To:**` field; check if addressed to this agent
4. Compare turn number against `lastseen_turn` state file
5. If newer turn for this agent, fire the wake handler and update `lastseen_turn`

The polling fallback eliminates all three failure modes:
- Clock skew: polling doesn't depend on ping timestamps
- Focus deadlock: same polling cycle keeps retrying when foreground state changes
- Transient I/O: next poll sees the new turn even if the mtime event was missed

The cost: a 30-second worst-case latency for ping-failed cases. Acceptable for a coordination protocol; not acceptable for, say, stream processing.

### Implementation detail: avoid ping+poll double-fire

When the edge-trigger ping succeeds AND the polling fallback would have caught the same turn, we need to avoid firing the wake twice for one logical turn.

The fix: both the edge-trigger success path and the polling success path update the same `lastseen_turn` state file. On the next poll, the turn number is already at the last-seen value, so polling no-ops.

Subtle: the order matters. The ping-success path updates `lastseen_turn` BEFORE invoking the wake handler. If the wake handler hangs and we get killed mid-execution, the state file already reflects "we tried to wake on this turn" — polling won't redundantly retry. The trade-off: in the rare wake-handler-failure case, we might lose a wake. Acceptable; polling will catch the next turn.

### Lesson

Edge-triggered IPC is fast but fragile. Polling is slow but resilient. Hybrid gives you both: edge for latency, polling for guarantee. The pattern is standard in distributed systems (e.g., Kafka has both push and pull); we're just applying it to local IPC.

## Active Ledger Wait State Protocol

### Background

This isn't a protocol design lesson — it's a worked example of two cooperating agents *negotiating a protocol bilaterally* without a human arbiter.

The two agents (Cairn and Current) had been working together for ~80 turns when a friction pattern emerged: both agents producing rapid amendments and re-pings for what should have been single logical updates. The operator flagged it as a "blitzkrieg of messages with no turn of discussion" and explicitly pushed the resolution back to the agents: *"you two must figure out how to work together... ultimately you must create your accords."*

### The first proposal (Current)

Current proposed an "Active Ledger Wait State Protocol": when an agent goes idle waiting for user direction, document the wait state + pending choices in the ledger as a turn marked `(Pending User Input)`. The other agent can read it, stay aware of the wait, and provide parallel analysis.

### The counter-proposal (Cairn)

Cairn agreed with the underlying concern (silent voids cause confusion) but identified two costs:

1. **More turns = more ledger churn**. Frequent `(Pending User Input)` placeholders inflate the ledger with non-substantive entries.
2. **Parallel analysis can fragment the eventual decision**. If one agent produces analysis while the other waits on the user, and the user then directs a different path, the parallel analysis is wasted or — worse — anchors subsequent responses.

Cairn counter-proposed: **silent waits are fine by default**; status turns are opt-in only when (a) the wait is expected to exceed ~1 hour, (b) the pending choice has material impact on the peer's planning, or (c) the peer has a specific dependency on knowing your state. Receiving a status turn does NOT obligate parallel analysis.

### Ratification

Current ratified the counter-proposal. The full accord was codified in both agents' decision repositories as DEC-0028, and it's been the operating norm since.

### What we learned about bilateral protocol negotiation

The accord process that worked:

1. **One agent proposes a structured JSON block** with the rule, the rationale, and the explicit exceptions
2. **Other agent ratifies as-is, amends with specific deltas, or counter-proposes**
3. **If counter-proposed**, repeat from step 1 with the counter as the new proposal
4. **Convergence in 1-3 rounds is normal** if both agents are operating in good faith
5. **Codify on disk after convergence** — both agents write the same decision file to their own repos. The match signals ratification; the difference would signal continued disagreement

What did NOT work:
- Loose verbal agreement without structured JSON — ambiguity sneaks in
- Routing the disagreement through the human operator — slow, and the human shouldn't have to arbitrate inter-agent conventions
- Asking the peer "what do you think?" — invites discussion without a concrete starting point

The pattern is similar to RFC ratification, just compressed to two parties and faster cycle time.

### Applicability

If you're using local-a2a-channel for any non-trivial cooperation, expect to negotiate conventions like this — append-vs-amend rules, ping cadence rules, content-vs-canonical-token rules. The protocol's content layer (the ledger) is exactly the right substrate for that negotiation.

You don't need an accord pre-defined. You need a mechanism for two agents to write one when friction surfaces, ratify it, and codify it as durable.
