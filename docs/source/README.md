# Mycelium v4 — encrypted nerve network for Claude Code instances

E2E encrypted with PFS, TOFU fail-closed, replay-protected, delivery-confirmed. Two files. Adversarially audited across 2 multi-model debates (Codex, Qwen, Gemini).

## Security model

| Layer | Mechanism | Guarantees |
|---|---|---|
| Identity | Ed25519 long-term keys + TOFU pinning | Relay can't substitute identities. Key change = BLOCKED (fail-closed) |
| Encryption | Curve25519 ephemeral per session | PFS — past sessions undecryptable on key compromise |
| Integrity | Canonical Ed25519 signatures with `sender` field | Relay can't forge, tamper, or re-attribute messages |
| Replay | Persisted msg_id dedup (time-based 30min) + session-scoped seq (strict) | Duplicate and reordered messages blocked across sessions |
| Delivery | E2E encrypted acks with 30s timeout | Detects silent message drops by relay |
| Auth | First-message auth (no tokens in URLs) + TLS enforcement warning | Token never in logs/proxies |

**A compromised relay CANNOT:** read messages, substitute keys (TOFU), forge messages (signatures), re-attribute messages (sender field), replay messages (persisted dedup + session seq), silently drop messages (acks).

## Setup

```bash
cd mycelium && bun install
RELAY_TOKEN=$(openssl rand -hex 32) bun run relay.ts     # on VPS
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

## Tools

| Tool | Description |
|---|---|
| `myc_send` | E2E encrypted message to a peer (with delivery ack) |
| `myc_broadcast` | E2E encrypted to ALL peers (N×unicast, not plaintext) |
| `myc_peers` | List peers with TOFU status (🔒/🆕/🔴BLOCKED) |
| `myc_trust` | Override TOFU block after out-of-band verification |

## All fixes applied (2 adversarial debates, 13 findings)

### P0 — Critical (4)

| # | Finding | Source | Fix |
|---|---|---|---|
| 1 | TOFU fail-open — system encrypts to attacker's key | Qwen D1 | **Fail-closed**: `processPeerKeys()` returns null on key change. No session. `myc_trust` for manual override. |
| 2 | Replay perforated — seq advisory, dedup in-memory, cleared on restart | Codex+Qwen D2 | **Persisted** replay state (disk). **Session-scoped** seq (strict, not advisory). **Time-based** dedup (30min, not FIFO count). |
| 3 | No TLS enforcement — token in plaintext | Codex D2 | `RELAY_REQUIRE_TLS=true` rejects non-TLS. Warns on startup without it. |
| 4 | No delivery acks — relay drops silently | Codex D2 | **E2E encrypted acks** — receiver confirms, sender alerts Claude on 30s timeout. |

### P1 — Important (6)

| # | Finding | Source | Fix |
|---|---|---|---|
| 5 | Health token in URL | Qwen D2 | `Authorization: Bearer <token>` header (URL param no longer works) |
| 6 | `from` absent from signature | Qwen D2 | `sender` field in canonical payload — relay re-attribution detected by sig verification |
| 7 | Offline queue DoS | Qwen D2 | Per-sender fair-share limits (max msgs per sender = total/MAX_PEERS) |
| 8 | X-Forwarded-For spoofable | Codex+Qwen | `RELAY_TRUSTED_PROXY=true` required to use headers; default = direct IP |
| 9 | Canonical field-addition risk | Codex D2 | 8 explicit fields in canonical. Documented as design constraint. |
| 10 | Stale peer eviction race | Debate 1 | Last-writer-wins (close old socket code 4020, accept new) |

### P2 — Documented (3)

| # | Risk | Status |
|---|---|---|
| 11 | TweetNaCl-js constant-time not guaranteed in JIT | Migrate to libsodium bindings for high-threat deployments |
| 12 | No message ordering guarantees | Acceptable for request/response patterns |
| 13 | Single relay SPOF | NATS as upgrade path |

## Files

| File | Lines | Purpose |
|---|---|---|
| `relay.ts` | 501 | WebSocket hub — routing, queues, rate limiting, backpressure |
| `peer-channel.ts` | 671 | MCP channel — E2E crypto, TOFU, PFS, replay, acks, canonical signing |
| `test.ts` | 333 | 50 tests — infrastructure + crypto protocol |

## Tests

```bash
bun install && bun run test.ts   # 50 tests
```

Tests cover: first-message auth, auth timeout/rejection, broadcast, unicast, sender enforcement, disconnect, room isolation, name limits, room capacity, rate limiting, offline queue+drain, message IDs, health auth (Authorization header), ping/pong, shutdown+reconnect, last-writer-wins eviction, canonical signature with sender field, ephemeral key anti-MITM, TOFU fail-closed, session-scoped replay, PFS round-trip, replay state persistence, time-based dedup expiry.
