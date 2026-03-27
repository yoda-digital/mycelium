# Mycelium v5 — encrypted nerve network for Claude Code instances

E2E encrypted. PFS. TOFU fail-closed. Signature-enforced. Replay-proof. Delivery-confirmed. 25 vulnerabilities found and fixed across 3 adversarial multi-model debates.

## What a compromised relay CANNOT do

| Attack | Prevention |
|---|---|
| Read messages | Ephemeral Curve25519 shared keys (relay never sees them) |
| Substitute peer keys (MITM) | TOFU-pinned Ed25519 identity keys — fail-closed on change |
| Forge messages | Ed25519 canonical signatures — **hard-blocked**, not warned |
| Replay signed messages with new IDs | msg_id + seq are **inside** the canonical signature (P0.14) |
| Forge permission approvals | Permission messages go through full E2E envelope (P0.15) |
| Evict peers by name-squatting | Identity-bound eviction — different sign_pubkey = rejected (P1.17) |
| Drop messages silently | E2E encrypted delivery acks with 30s timeout |
| Decrypt past sessions | PFS — ephemeral keys are in-memory only, per session |

## Setup

```bash
cd mycelium && bun install
RELAY_TOKEN=$(openssl rand -hex 32) bun run relay.ts
```

```json
{
  "mcpServers": {
    "mycelium": {
      "command": "bun",
      "args": ["/path/to/peer-channel.ts"],
      "env": {
        "MYC_RELAY": "wss://mycelium.example.com",
        "MYC_TOKEN": "your-token",
        "MYC_PEER": "unique-name"
      }
    }
  }
}
```

```bash
claude --dangerously-load-development-channels server:mycelium
```

## All 25 vulnerabilities fixed (3 adversarial debates)

### Debate 1 (v2→v3): 7 findings
| # | Finding | Fix |
|---|---|---|
| 1 | Token in URL | First-message auth |
| 2 | perMessageDeflate bomb | Disabled |
| 3 | Relay reads messages | E2E TweetNaCl encryption |
| 4 | Bun v1.3.0 CPU bug | Engine pin ≥1.3.5 |
| 5 | No memory monitoring | RSS tracking + structured logs |
| 6 | No rate limiting | Token bucket + per-IP cap |
| 7 | Broken jitter | AWS Full Jitter |

### Debate 2 (v3→v4): 13 findings
| # | Finding | Fix |
|---|---|---|
| 8 | TOFU fail-open | **Fail-closed** (return null on key change) |
| 9 | Replay perforated | **Persisted** replay state, **session-scoped** strict seq, **time-based** dedup |
| 10 | No TLS enforcement | `RELAY_REQUIRE_TLS` + startup warning |
| 11 | No delivery acks | **E2E encrypted acks** with 30s timeout |
| 12 | Health token in URL | `Authorization: Bearer` header |
| 13 | `from` not in signature | `sender` field in canonical |
| 14 | Offline queue DoS | Per-sender fair-share |
| 15 | X-Forwarded-For spoof | `RELAY_TRUSTED_PROXY` config |
| 16 | Stale peer race | Last-writer-wins eviction |
| 17 | No PFS | Ephemeral Curve25519 per session |
| 18 | Broadcast plaintext | N×unicast encryption |
| 19 | Sig verification mismatch | Canonical sorted fields |
| 20 | No replay protection | msg_id dedup + seq monotonicity |

### Debate 3 (v4→v5): 12 findings
| # | Finding | Fix |
|---|---|---|
| 21 | **Canonical sig excludes msg_id/seq** (P0) | **msg_id + seq IN signature** — relay can't mint new IDs |
| 22 | **Permission msgs unprotected** (P0) | **Full E2E envelope** for `_perm_req`/`_perm_verdict` |
| 23 | **Sig verification = warn not block** (P0) | **Hard-block** on bad/missing sig for e2e messages. `sender` REQUIRED |
| 24 | LWW = unauthenticated eviction | **Identity-bound**: same sign_pubkey = evict, different = reject |
| 25 | Replay persistence 10s race | **Write-ahead log**: persist msg_id before processing |
| 26 | session_id not in relay | Stored in Peer, distributed in peerKeyMap |
| 27 | Fair-share = 1 msg/sender | `max(3, ceil(total/active_peers))` |
| 28 | myc_trust no fingerprint | **Shows SHA-512 fingerprint** for out-of-band verification |
| 29 | Cross-project TOFU leak | Document: use per-project `MYC_TOFU_FILE` |
| 30 | 64-bit session ID | **16-byte** (128-bit, birthday-safe to ~2^64) |

## Resolved limitations (v5)

All six original limitations were resolved in the v5 hardening pass:

| Original Limitation | Resolution |
|---|---|
| Shared RELAY_TOKEN = room-level secret | Ed25519 challenge-response auth. Token is a one-time invite; known peers auth via identity key. Allow-list persisted per room. |
| TweetNaCl-js constant-time not guaranteed | Replaced with libsodium WASM — audited constant-time crypto, deterministic WASM execution. |
| No message ordering | Request-ID correlation + seq reorder buffer. Also fixed latent bug where out-of-order messages were dropped as replay. |
| Single relay SPOF | Multi-relay client failover via comma-separated `MYC_RELAY` URLs with automatic cycling. |
| First-contact MITM via relay | STS (Station-to-Station) mutual authentication post-handshake. Relay cannot forge Ed25519 signatures. |
| No TLS certificate pinning | Relay Ed25519 identity verification (`MYC_RELAY_FINGERPRINT`) + sealed (encrypted) auth tokens via `crypto_box_seal`. |

## Tests

```bash
bun install && bun run test.ts   # 75 tests
```

## Files

| File | Lines |
|---|---|
| relay.ts | 277 |
| peer-channel.ts | 573 |
| test.ts | 323 |
| **Total** | **1173** |
