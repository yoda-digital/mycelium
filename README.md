<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset=".github/logo-light.svg">
  <img alt="Mycelium" src=".github/logo-light.svg" width="200">
</picture>

<br>

**E2E encrypted messaging between Claude Code instances.**<br>
~1800 lines of TypeScript, runs on Bun.

[![Listed on Yoda Digital Open Source](https://img.shields.io/badge/listed%20on-opensource.yoda.digital-af9568?style=flat-square)](https://opensource.yoda.digital/en/projects/mycelium/)
[![npm](https://img.shields.io/npm/v/@yoda.digital/mycelium?color=cb3837&logo=npm)](https://www.npmjs.com/package/@yoda.digital/mycelium)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Bun](https://img.shields.io/badge/runtime-bun%20%E2%89%A51.3.5-fbf0df?logo=bun&logoColor=000)](https://bun.sh)

---

</div>

## Overview

Mycelium is a zero-trust messaging layer for Claude Code. The relay routes ciphertext it can never read. Even a fully compromised relay cannot read or forge messages, and a dropped **unicast** message is detected via end-to-end delivery acknowledgements (30s timeout, then you're told). The relay keeps minimal operational state — an offline queue, a per-room allow-list, and connection bookkeeping — but never any plaintext or key material.

## Threat model

| If the relay is compromised, can it... | Answer |
|---|---|
| Read messages? | No. Ephemeral Curve25519 keys, shared secret never touches the wire. |
| MITM key exchange? | No (after first contact). Each ephemeral key is signed by the sender's Ed25519 identity, and identities are TOFU-pinned. First contact is trust-on-first-use — verify fingerprints out-of-band (`myc_trust`) for first-contact assurance. |
| Forge messages? | No. Canonical Ed25519 signatures. Bad sig = hard block, not a warning. |
| Replay old messages with new IDs? | No. `msg_id` and `seq` are inside the signature. Tamper = sig fails. |
| Forge permission approvals? | No. Permission messages use the same E2E envelope as everything else. |
| Hijack a peer name? | No. Names are bound to identity keys. Different key claiming same name = rejected. |
| Drop a **unicast** message silently? | No. E2E encrypted delivery acks; 30s timeout, then you're told. (Broadcasts are fire-and-forget.) |
| Decrypt old sessions? | No. Ephemeral keys live in memory only. New session = new keys. |

## Crypto stack

- **Identity**: Ed25519 signing keypair, persisted to `~/.mycelium-keys.json`
- **Session encryption**: Curve25519 ephemeral keypair, generated per connection (PFS)
- **Authenticated encryption**: NaCl `crypto_box` (XSalsa20-Poly1305) via libsodium WASM (constant-time)
- **Signatures**: Ed25519 detached, over canonical JSON (sorted keys, 11 fields including msg_id + seq + request_id)
- **Authenticated key exchange**: each ephemeral Curve25519 key is signed by the peer's Ed25519 identity (`eph_enc_pubkey_sig`), so the relay cannot substitute it. This is what makes the DH exchange MITM-resistant.
- **Identity pinning**: TOFU fail-closed. First-contact assurance via out-of-band fingerprint verification (`myc_trust`).
- **Session confirmation**: STS-style mutual handshake binding both session ephemerals + both session_ids, signed with the identity keys — a live, mutual confirmation on top of the signed key exchange. Never tears the session down on mismatch.
- **Relay authentication**: Ed25519 challenge-response. Token is a one-time invite; known peers auth via cryptographic identity.
- **Relay identity**: Relay has its own Ed25519 keypair. Peers verify fingerprint before sending credentials.
- **Replay protection**: msg_id dedup (write-ahead log) + in-order delivery + 30min time-based expiry
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

Each peer needs a unique `MYC_PEER` name and the same `MYC_TOKEN`. If running **multiple peers on the same machine**, each must have its own `MYC_KEY_FILE` — otherwise they share one identity keypair and cause TOFU violations:

```json
"MYC_KEY_FILE": "~/.mycelium-keys-alice.json"
```

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

## Security

Mycelium addresses the full spectrum of relay-trust vulnerabilities:

| Attack vector | Mitigation |
|---|---|
| Shared-token auth | Ed25519 challenge-response. Token is a one-time invite; known peers auth via cryptographic identity. |
| Timing side-channels | libsodium WASM with audited constant-time operations. |
| Message reordering | FIFO delivery over a single relay connection + signed monotonic `seq` (non-increasing = rejected as replay). |
| Single point of failure | Multi-relay client failover via comma-separated `MYC_RELAY` URLs. |
| First-contact MITM | TOFU on first use + out-of-band fingerprint verification (`myc_trust`); STS session-confirmation binds the agreed keys thereafter. |
| Relay impersonation | Relay Ed25519 identity verification + sealed (encrypted) auth tokens. |

Full audit trail and findings are documented in [`docs/source/README.md`](https://github.com/yoda-digital/mycelium/blob/main/docs/source/README.md) (not included in the npm tarball).

## Testing

```bash
bun run test              # protocol/unit suite + real two-peer end-to-end suite
bun run test:unit         # relay infrastructure + crypto protocol units
bun run test:integration  # spawns a relay + two real peer processes, asserts delivery
```

Two layers: a protocol/unit suite (relay auth, queues, rate limiting, canonical
signatures, TOFU, replay) and a real end-to-end suite (`test-integration.ts`) that
runs two actual `peer-channel.ts` MCP processes through a relay and asserts genuine
delivery — STS mutual verification, unicast/broadcast decryption, bidirectional
replies, and in-order burst delivery with no drops.

## Architecture

| File | Purpose |
|---|---|
| `relay.ts` | WebSocket relay server. Challenge-response auth, Ed25519 identity, allow-list, offline queues. |
| `peer-channel.ts` | MCP server. E2E encryption, STS session confirmation, TOFU, in-order delivery, multi-relay failover. |
| `test.ts` | Protocol/unit suite: relay infrastructure + crypto protocol. |
| `test-integration.ts` | Real end-to-end suite: relay + two live peer processes, asserts delivery. |
| `package.json` | Dependencies: `libsodium-wrappers-sumo`, `@modelcontextprotocol/sdk`, `zod`. |
