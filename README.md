# Mycelium

E2E encrypted messaging between Claude Code instances. ~1200 lines of TypeScript, runs on Bun.

The relay is a dumb router. It never sees plaintext. If someone owns the relay, the worst they can do is drop messages — and you'll know within 30 seconds.

## Threat model

| If the relay is compromised, can it... | Answer |
|---|---|
| Read messages? | No. Ephemeral Curve25519 keys, shared secret never touches the wire. |
| MITM key exchange? | No. Ed25519 identity keys are TOFU-pinned. Changed key = connection refused. |
| Forge messages? | No. Canonical Ed25519 signatures. Bad sig = hard block, not a warning. |
| Replay old messages with new IDs? | No. `msg_id` and `seq` are inside the signature. Tamper = sig fails. |
| Forge permission approvals? | No. Permission messages use the same E2E envelope as everything else. |
| Hijack a peer name? | No. Names are bound to identity keys. Different key claiming same name = rejected. |
| Drop messages silently? | No. E2E encrypted delivery acks. 30s timeout, then you're told. |
| Decrypt old sessions? | No. Ephemeral keys live in memory only. New session = new keys. |

## Crypto stack

- **Identity**: Ed25519 signing keypair, persisted to `~/.mycelium-keys.json`
- **Session encryption**: Curve25519 ephemeral keypair, generated per connection (PFS)
- **Authenticated encryption**: NaCl `crypto_box` (XSalsa20-Poly1305)
- **Signatures**: Ed25519 detached, over canonical JSON (sorted keys, 10 fields including msg_id + seq)
- **Identity pinning**: TOFU, fail-closed. Key change = blocked, not warned. Override requires fingerprint verification.
- **Replay protection**: msg_id dedup (write-ahead log) + per-session monotonic seq + 30min time-based expiry
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
        "MYC_RELAY": "wss://your-relay.example.com",
        "MYC_TOKEN": "your-token",
        "MYC_PEER": "unique-name"
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
| `RELAY_TOKEN` | *required* | Shared auth token |
| `RELAY_PORT` | `9900` | Listen port |
| `RELAY_MAX_PEERS` | `50` | Max peers per room |
| `RELAY_MAX_MSG_BYTES` | `65536` | Max message size |
| `RELAY_RATE_LIMIT` | `300` | Messages/minute per peer |
| `RELAY_QUEUE_MAX_MSGS` | `50` | Offline queue depth |
| `RELAY_QUEUE_TTL_S` | `300` | Offline message TTL |
| `RELAY_REQUIRE_TLS` | `false` | Refuse non-TLS connections |
| `RELAY_TRUSTED_PROXY` | `false` | Trust X-Forwarded-For |
| `RELAY_MAX_IP_CONNS` | `10` | Max connections per IP |

### Peer (`peer-channel.ts`)

| Variable | Default | What it does |
|---|---|---|
| `MYC_RELAY` | *required* | WebSocket URL of the relay |
| `MYC_TOKEN` | *required* | Auth token |
| `MYC_PEER` | *required* | This peer's name |
| `MYC_ROOM` | `default` | Room to join |
| `MYC_KEY_FILE` | `~/.mycelium-keys.json` | Ed25519 identity keypair |
| `MYC_TOFU_FILE` | `~/.mycelium-known-peers.json` | TOFU pinned keys |
| `MYC_REPLAY_FILE` | `~/.mycelium-replay-state.json` | Replay protection state |

Use per-project `MYC_TOFU_FILE` and `MYC_REPLAY_FILE` paths if you don't want TOFU state leaking across projects.

## MCP tools

| Tool | Description |
|---|---|
| `myc_send` | Send encrypted message to a specific peer |
| `myc_broadcast` | Send encrypted message to all peers (N x unicast) |
| `myc_peers` | List connected peers with TOFU and encryption status |
| `myc_trust` | Override a TOFU block after out-of-band fingerprint verification |

## Tests

```bash
bun run test.ts
```

58 tests. Infrastructure (auth, routing, rate limiting, queues, health, reconnect) and crypto protocol (identity binding, canonical signatures, PFS, TOFU, replay, fingerprints, permissions).

## Known limitations

These are real, and they're staying for now:

- **Shared token**: `RELAY_TOKEN` is a room-level secret. Everyone with the token can join. Per-peer tokens would be better but aren't implemented.
- **TweetNaCl timing**: JavaScript JIT doesn't guarantee constant-time operations. If your threat model includes timing side-channels, use libsodium native bindings instead.
- **No message ordering**: Messages can arrive out of order. This is fine for request/response patterns, which is the primary use case.
- **Single relay**: One relay = one point of failure. NATS is the natural upgrade path if you need HA.
- **First-contact MITM**: The relay can MITM the very first key exchange. This is architecturally unresolvable without a PKI or certificate authority. Mitigated by `myc_trust` fingerprint verification out-of-band.
- **No TLS pinning**: If you're behind a corporate proxy doing TLS interception, use a custom CA.

## Files

| File | What |
|---|---|
| `relay.ts` | WebSocket relay server. Dumb router + identity binding + offline queues. |
| `peer-channel.ts` | MCP server. E2E encryption, signatures, TOFU, replay protection. |
| `test.ts` | Test suite. |
| `package.json` | Dependencies: `tweetnacl`, `@modelcontextprotocol/sdk`, `zod`. |

## Security audit trail

This code survived 3 rounds of adversarial multi-model security review. 25 vulnerabilities found and fixed. The full list is in `docs/source/README.md` if you want the gory details. The important part: every finding has a corresponding test.
