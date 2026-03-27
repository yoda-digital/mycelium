# Mycelium

E2E encrypted messaging between Claude Code instances. ~2100 lines of TypeScript, runs on Bun.

The relay is a dumb router. It never sees plaintext. If someone owns the relay, the worst they can do is drop messages — and you'll know within 30 seconds.

## Threat model

| If the relay is compromised, can it... | Answer |
|---|---|
| Read messages? | No. Ephemeral Curve25519 keys, shared secret never touches the wire. |
| MITM key exchange? | No. Ed25519 TOFU + STS mutual authentication. Even first contact is protected. |
| Forge messages? | No. Canonical Ed25519 signatures. Bad sig = hard block, not a warning. |
| Replay old messages with new IDs? | No. `msg_id` and `seq` are inside the signature. Tamper = sig fails. |
| Forge permission approvals? | No. Permission messages use the same E2E envelope as everything else. |
| Hijack a peer name? | No. Names are bound to identity keys. Different key claiming same name = rejected. |
| Drop messages silently? | No. E2E encrypted delivery acks. 30s timeout, then you're told. |
| Decrypt old sessions? | No. Ephemeral keys live in memory only. New session = new keys. |

## Crypto stack

- **Identity**: Ed25519 signing keypair, persisted to `~/.mycelium-keys.json`
- **Session encryption**: Curve25519 ephemeral keypair, generated per connection (PFS)
- **Authenticated encryption**: NaCl `crypto_box` (XSalsa20-Poly1305) via libsodium WASM (constant-time)
- **Signatures**: Ed25519 detached, over canonical JSON (sorted keys, 11 fields including msg_id + seq + request_id)
- **Identity pinning**: TOFU fail-closed + STS mutual authentication (eliminates first-contact MITM)
- **Relay authentication**: Ed25519 challenge-response. Token is a one-time invite; known peers auth via cryptographic identity.
- **Relay identity**: Relay has its own Ed25519 keypair. Peers verify fingerprint before sending credentials.
- **Replay protection**: msg_id dedup (write-ahead log) + reorder buffer + 30min time-based expiry
- **Broadcast**: N x unicast (each peer gets independently encrypted copy)

## Setup

Start the relay:

```bash
bun install
RELAY_TOKEN=$(openssl rand -hex 32) bun run relay.ts
```

Add to your Claude Code MCP config:

```json
{
  "mcpServers": {
    "mycelium": {
      "command": "bun",
      "args": ["/path/to/peer-channel.ts"],
      "env": {
        "MYC_RELAY": "wss://relay1.example.com,wss://relay2.example.com",
        "MYC_TOKEN": "your-token",
        "MYC_PEER": "unique-name",
        "MYC_RELAY_FINGERPRINT": "a1b2:c3d4:e5f6:..."
      }
    }
  }
}
```

Then tell Claude Code to load it:

```bash
claude --dangerously-load-development-channels server:mycelium
```

Each peer needs a unique `MYC_PEER` name and the same `MYC_TOKEN`. That's it.

## Environment variables

### Relay (`relay.ts`)

| Variable | Default | What it does |
|---|---|---|
| `RELAY_TOKEN` | *required* | Shared auth token (one-time invite for new peers) |
| `RELAY_PORT` | `9900` | Listen port |
| `RELAY_MAX_PEERS` | `50` | Max peers per room |
| `RELAY_MAX_MSG_BYTES` | `65536` | Max message size |
| `RELAY_RATE_LIMIT` | `300` | Messages/minute per peer |
| `RELAY_QUEUE_MAX_MSGS` | `50` | Offline queue depth |
| `RELAY_QUEUE_TTL_S` | `300` | Offline message TTL |
| `RELAY_REQUIRE_TLS` | `false` | Refuse non-TLS connections |
| `RELAY_TRUSTED_PROXY` | `false` | Trust X-Forwarded-For |
| `RELAY_MAX_IP_CONNS` | `10` | Max connections per IP |
| `RELAY_KEY_FILE` | `~/.mycelium-relay-keys.json` | Relay Ed25519 identity keypair |
| `RELAY_ALLOW_FILE` | `~/.mycelium-relay-allow.json` | Per-room peer allow-list |
| `RELAY_REQUIRE_CHALLENGE` | `false` | Require challenge-response (reject token-only) |

### Peer (`peer-channel.ts`)

| Variable | Default | What it does |
|---|---|---|
| `MYC_RELAY` | *required* | WebSocket URL(s), comma-separated for failover |
| `MYC_TOKEN` | *required* | Auth token (one-time invite; not needed after first auth) |
| `MYC_PEER` | *required* | This peer's name |
| `MYC_ROOM` | `default` | Room to join |
| `MYC_KEY_FILE` | `~/.mycelium-keys.json` | Ed25519 identity keypair |
| `MYC_TOFU_FILE` | `~/.mycelium-known-peers.json` | TOFU pinned keys |
| `MYC_REPLAY_FILE` | `~/.mycelium-replay-state.json` | Replay protection state |
| `MYC_RELAY_FINGERPRINT` | *(none)* | Expected relay fingerprint (e.g., `a1b2:c3d4:...`) |

Use per-project `MYC_TOFU_FILE` and `MYC_REPLAY_FILE` paths if you don't want TOFU state leaking across projects.

Set `MYC_RELAY_FINGERPRINT` to pin relay identity — the peer will refuse to send credentials to an unverified relay.

## MCP tools

| Tool | Description |
|---|---|
| `myc_send` | Send encrypted message to a specific peer (supports `request_id` for correlation) |
| `myc_broadcast` | Send encrypted message to all peers (N x unicast) |
| `myc_peers` | List connected peers with TOFU and encryption status |
| `myc_trust` | Override a TOFU block after out-of-band fingerprint verification |

## Tests

```bash
bun run test.ts
```

75 tests. Infrastructure (auth, routing, rate limiting, queues, health, reconnect), crypto protocol (identity binding, canonical signatures, PFS, TOFU, replay, fingerprints, permissions), and v5 features (challenge-response, multi-relay, reorder buffer, STS mutual auth, relay identity).

## Resolved limitations (v5)

All six original limitations have been addressed:

| Limitation | Solution | Status |
|---|---|---|
| Shared token | Ed25519 challenge-response auth. Token is now a one-time invite; known peers auth via cryptographic identity. | Resolved |
| TweetNaCl timing | Replaced with libsodium WASM — audited constant-time crypto. | Resolved |
| No message ordering | Request-ID correlation + seq reorder buffer. Also fixes latent out-of-order message drop bug. | Resolved |
| Single relay | Multi-relay client failover via comma-separated `MYC_RELAY` URLs. | Resolved |
| First-contact MITM | STS (Station-to-Station) mutual authentication post-handshake. | Resolved |
| No TLS pinning | Relay Ed25519 identity verification + sealed (encrypted) auth tokens. | Resolved |

## Files

| File | What |
|---|---|
| `relay.ts` | WebSocket relay server. Challenge-response auth, Ed25519 identity, allow-list, offline queues. |
| `peer-channel.ts` | MCP server. E2E encryption, STS mutual auth, TOFU, reorder buffer, multi-relay failover. |
| `test.ts` | 75 tests covering infrastructure + crypto protocol + v5 features. |
| `package.json` | Dependencies: `libsodium-wrappers-sumo`, `@modelcontextprotocol/sdk`, `zod`. |

## Security audit trail

This code survived 3 rounds of adversarial multi-model security review (25 vulnerabilities found and fixed) plus a v5 hardening pass that eliminated all 6 documented limitations. The full audit trail is in `docs/source/README.md`. Every finding has a corresponding test.
