<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset=".github/logo-light.svg">
  <img alt="Mycelium" src=".github/logo-light.svg" width="200">
</picture>

<br>

**E2E encrypted messaging between Claude Code instances.**<br>
~3000 lines of TypeScript, runs on Bun.

[![Listed on Yoda Digital Open Source](https://img.shields.io/badge/listed%20on-opensource.yoda.digital-af9568?style=flat-square)](https://opensource.yoda.digital/en/projects/mycelium/)
[![npm](https://img.shields.io/npm/v/@yoda.digital/mycelium?color=cb3837&logo=npm)](https://www.npmjs.com/package/@yoda.digital/mycelium)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Bun](https://img.shields.io/badge/runtime-bun%20%E2%89%A51.3.5-fbf0df?logo=bun&logoColor=000)](https://bun.sh)

---

</div>

## Overview

Mycelium is a zero-trust messaging layer for Claude Code. The relay routes ciphertext it can never read. Even a fully compromised relay cannot read or forge messages. Delivery is **reliable by machinery, not by hope**: every unicast (and every broadcast copy) is acknowledged end-to-end, retransmitted automatically and idempotently on any loss signal, and messages to **offline** peers are sealed to their long-lived identity key and store-and-forwarded by the relay — decryptable when they return. The relay keeps minimal operational state — offline queues, a per-room name↔key allow-list, connection bookkeeping — but never any plaintext or key material.

## Threat model

| If the relay is compromised, can it... | Answer |
|---|---|
| Read messages? | No. Live traffic: ephemeral Curve25519 keys, shared secret never touches the wire. Offline envelopes: sealed to the recipient's identity-derived key. |
| MITM key exchange? | No (after first contact). Each ephemeral key is signed by the sender's Ed25519 identity, and identities are TOFU-pinned. First contact is trust-on-first-use — verify fingerprints out-of-band (`myc_trust`) for first-contact assurance. |
| Forge messages? | No. Canonical Ed25519 signatures. Bad sig = hard block, not a warning. |
| Replay old messages with new IDs? | No. `msg_id` and `seq` are inside the signature. Tamper = sig fails. Offline envelopes additionally carry a signed timestamp bounded by a freshness window. |
| Re-route a message into another room? | No. `room` is inside the signature (protocol v2). |
| Forge permission approvals? | No. Permission messages use the same E2E envelope as everything else, and approval requests are delivery-acked. |
| Hijack a peer name? | No. Names are **persistently** bound to identity keys in the relay allow-list — a different key claiming a bound name is rejected even while the owner is offline. Client-side TOFU independently pins the same binding. |
| Drop a message silently? | No. E2E encrypted delivery acks per message (broadcast copies included); the sender's outbox retransmits automatically and reports honestly only on confirmed delivery or terminal failure. |
| Decrypt old sessions? | No, for live traffic — ephemeral keys are in-memory only (PFS). **Exception (documented):** offline envelopes are sealed to the recipient's identity key and are decryptable for as long as that key exists — no PFS for store-and-forward traffic. Rotate identities (`myc_rotate_key`) to bound this window. |
| See who talks to whom? | **Yes.** The relay necessarily sees names, rooms, timing, frame sizes, and the messaging graph. Traffic analysis / metadata protection is NOT provided — do not use Mycelium where the metadata itself is the secret. |

## Crypto stack

- **Identity**: Ed25519 signing keypair, persisted to `~/.mycelium-keys.json` (optionally passphrase-encrypted at rest — Argon2id + secretbox via `MYC_KEY_PASSPHRASE`)
- **Session encryption**: Curve25519 ephemeral keypair, generated per connection (PFS)
- **Offline delivery**: `crypto_box_seal` to the recipient's identity-derived Curve25519 key (survives reconnects; no PFS — documented tradeoff), authenticated by the canonical envelope signature against the TOFU-pinned sender key, freshness-bounded by a signed `ts` (`MYC_OFFLINE_MAX_AGE_S`, default 1h)
- **Authenticated encryption**: NaCl `crypto_box` (XSalsa20-Poly1305) via libsodium WASM (constant-time)
- **Signatures**: Ed25519 detached, over canonical JSON (sorted keys; `msg_id`, `seq`, `room`, `ts`, `request_id` all signed — see `canonical.ts`)
- **Authenticated key exchange**: each ephemeral Curve25519 key is signed by the peer's Ed25519 identity (`eph_enc_pubkey_sig`), so the relay cannot substitute it. This is what makes the DH exchange MITM-resistant.
- **Identity pinning**: TOFU fail-closed, scoped per (room, peer). First-contact assurance via out-of-band fingerprint verification (`myc_trust`).
- **Key rotation**: `myc_rotate_key` announces `sign(newKey || name || ts, oldKey)` to every known peer (live + offline envelopes); pins and the relay name binding migrate with no TOFU violation. Old announcements cannot roll pins back.
- **Session confirmation**: STS-style mutual handshake binding both session ephemerals + both session_ids + the room, signed with the identity keys. Timeout is lenient (channel stays TOFU/eph-sig authenticated); a wrong binding signature is fail-closed — session torn down, peer blocked until `myc_trust`.
- **Relay authentication**: Ed25519 challenge-response. Token is a one-time invite; known peers auth via cryptographic identity. Persistent per-room name↔key binding; admin revocation blocklists keys.
- **Relay identity**: Relay has its own Ed25519 keypair. Peers verify fingerprint(s) before sending credentials — `MYC_RELAY_FINGERPRINT` takes a comma list, so multi-relay failover composes with pinning.
- **Replay protection**: msg_id dedup (write-ahead log, sender+room-scoped) + signed-`seq` sliding window per (room, sender, session) + signed-timestamp window for offline envelopes. Verified duplicates are re-acked (lost-ack recovery), never re-delivered.
- **Reliability**: outbox with automatic idempotent retransmission (same `msg_id`) on nack, relay-reported drop, ack timeout, peer reappearance, and reconnect; local queueing while the relay is down; chunking for messages above the 64KB frame cap.
- **Broadcast**: N × unicast (each peer gets an independently encrypted, individually acked copy; `include_offline` reaches absent peers via envelopes)

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
        "MYC_RELAY_FINGERPRINT": "a1b2:c3d4:... , e5f6:a7b8:..."
      }
    }
  }
}
```

Then tell Claude Code to load it:

```bash
claude --dangerously-load-development-channels server:mycelium
```

> **Host compatibility:** inbound messages are pushed via the experimental
> `notifications/claude/channel` capability *and* buffered in an inbox. On any
> MCP host that does not surface those notifications, poll with **`myc_recv`** —
> nothing is lost either way.

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
| `RELAY_MAX_MSG_BYTES` | `65536` | Max frame size (larger logical messages are chunked by peers) |
| `RELAY_RATE_LIMIT` | `300` | Messages/minute per peer |
| `RELAY_QUEUE_MAX_MSGS` | `50` | Offline queue depth |
| `RELAY_QUEUE_TTL_S` | `300` | Offline message TTL (keep ≤ peers' `MYC_OFFLINE_MAX_AGE_S`) |
| `RELAY_REQUIRE_TLS` | `false` | Refuse non-TLS connections |
| `RELAY_TRUSTED_PROXY` | `false` | Trust X-Forwarded-For |
| `RELAY_MAX_IP_CONNS` | `10` | Max connections per IP |
| `RELAY_KEY_FILE` | `~/.mycelium-relay-keys.json` | Relay Ed25519 identity keypair |
| `RELAY_KEY_PASSPHRASE` | *(none)* | Encrypt the relay key file at rest (Argon2id) |
| `RELAY_ALLOW_FILE` | `~/.mycelium-relay-allow.json` | Per-room name↔key bindings + revocation blocklist |
| `RELAY_REQUIRE_CHALLENGE` | `false` | Require challenge-response (reject token-only) |
| `RELAY_DISCOVERY` | `true` | Answer `list_rooms` for non-member rooms (counts only) |

### Peer (`peer-channel.ts`)

| Variable | Default | What it does |
|---|---|---|
| `MYC_RELAY` | *required* | WebSocket URL(s), comma-separated for failover |
| `MYC_TOKEN` | *required* | Auth token (one-time invite; not needed after first auth) |
| `MYC_PEER` | *required* | This peer's name |
| `MYC_ROOM` | `default` | Room(s) to join — comma-separated, up to 8 |
| `MYC_KEY_FILE` | `~/.mycelium-keys.json` | Ed25519 identity keypair |
| `MYC_KEY_PASSPHRASE` | *(none)* | Encrypt the key file at rest (Argon2id; fail-closed on wrong passphrase) |
| `MYC_TOFU_FILE` | `~/.mycelium-known-peers.json` | TOFU pinned keys (room-scoped) |
| `MYC_REPLAY_FILE` | `~/.mycelium-replay-state.json` | Replay protection state |
| `MYC_RELAY_FINGERPRINT` | *(none)* | Expected relay fingerprint(s), comma-separated — composes with multi-relay failover |
| `MYC_OFFLINE_MAX_AGE_S` | `3600` | Freshness window for offline envelopes (signed `ts`) |
| `MYC_MAX_MSG_BYTES` | `1048576` | Max logical message size (chunked over the wire) |

Use per-project `MYC_TOFU_FILE` and `MYC_REPLAY_FILE` paths if you don't want TOFU state leaking across projects.

## MCP tools

| Tool | Description |
|---|---|
| `myc_send` | Encrypted unicast — PFS session frame when the target is live, identity envelope when it's offline; ack-tracked, auto-retransmitted, auto-chunked. Supports `request_id` and `room`. |
| `myc_broadcast` | Encrypted to all peers (N × unicast, each copy acked); `include_offline` reaches absent peers, `room` scopes it |
| `myc_recv` | Drain the inbox — host-independent delivery fallback (`peek` to inspect without draining) |
| `myc_peers` | Per-room peer list with TOFU/STS status, offline-reachable peers, inbox depth |
| `myc_rooms` | Room discovery via the relay |
| `myc_trust` | Override a TOFU block after out-of-band fingerprint verification |
| `myc_rotate_key` | Rotate this peer's identity with signed continuity — no TOFU violations, relay binding migrates |

## Relay admin

```bash
# Inspect bindings
curl -H "Authorization: Bearer $RELAY_TOKEN" http://relay:9900/admin/allowlist
# Revoke a peer (frees the name, BLOCKLISTS the key, disconnects it)
curl -X POST -H "Authorization: Bearer $RELAY_TOKEN" -H 'Content-Type: application/json' \
  -d '{"room":"default","name":"mallory"}' http://relay:9900/admin/revoke
# Un-revoke a key
curl -X POST -H "Authorization: Bearer $RELAY_TOKEN" -H 'Content-Type: application/json' \
  -d '{"room":"default","pubkey":"<base64>","undo":true}' http://relay:9900/admin/revoke
```

A revoked key cannot re-register even with the invite token. (An actor who still holds the token can mint a *fresh* identity under a new name — rotate `RELAY_TOKEN` to fully evict.)

## Security

Mycelium addresses the full spectrum of relay-trust vulnerabilities:

| Attack vector | Mitigation |
|---|---|
| Shared-token auth | Ed25519 challenge-response. Token is a one-time invite; known peers auth via cryptographic identity; revocation blocklists keys. |
| Offline name squatting | Persistent per-room name↔key binding in the allow-list (both directions), enforced whether the owner is connected or not. |
| Timing side-channels | libsodium WASM with audited constant-time operations. |
| Message reordering | FIFO delivery over a single relay connection + signed `seq` anti-replay window (RFC 4303 style): reordered frames inside the window are delivered, exact replays are re-acked but never re-delivered. |
| Single point of failure | Multi-relay client failover via comma-separated `MYC_RELAY` URLs — with per-relay fingerprints (`MYC_RELAY_FINGERPRINT` list), so failover keeps identity pinning. |
| First-contact MITM | TOFU on first use + out-of-band fingerprint verification (`myc_trust`); STS session-confirmation binds the agreed keys thereafter. |
| Relay impersonation | Relay Ed25519 identity verification + sealed (encrypted) auth tokens; no plaintext-token downgrade when pinning is configured. |
| Cross-room replay / re-routing | `room` is inside the canonical signature; replay windows, sessions, and TOFU pins are room-scoped. |
| Stale offline replay | Signed `ts` freshness window + persisted dedup whose retention outlives the window. |
| Metadata / traffic analysis | **Not mitigated** — the relay sees names, rooms, timing, sizes, and the messaging graph. Documented, deliberately out of scope. |

Historical audit trail (25 findings across 3 adversarial reviews, v5-era) is preserved in [`docs/source/README.md`](https://github.com/yoda-digital/mycelium/blob/main/docs/source/README.md) (not included in the npm tarball; see its header for what has changed since).

## Testing

```bash
bun run test              # all three suites (176 tests)
bun run test:unit         # relay infrastructure + crypto protocol units (89)
bun run test:integration  # spawns a relay + real peer processes, asserts delivery (63)
bun run test:poison       # controlled malicious relay vs a real peer (24)
```

The integration suite runs real `peer-channel.ts` MCP processes through a real relay and asserts genuine end-to-end behavior: STS mutual verification, unicast/broadcast decryption, in-order burst delivery, **offline delivery across a process restart**, the nack→auto-retransmit→confirmation loop, key rotation continuity, revocation, multi-room isolation, fingerprint-list pinning, passphrase-encrypted keys, and 120KB chunked reassembly. CI runs everything on every push and PR (`.github/workflows/tests.yml`).

## Architecture

| File | Purpose |
|---|---|
| `relay.ts` | WebSocket relay server. Challenge-response auth, Ed25519 identity, persistent name bindings + revocation, multi-room routing, offline queues, admin API. |
| `peer-channel.ts` | MCP server. E2E encryption, offline envelopes, outbox/retransmission, inbox, STS, TOFU, key rotation, chunking, multi-relay failover. |
| `canonical.ts` | The single source of truth for signature-covered fields (v2, strip/add-safe conditional fields). |
| `test.ts` | Protocol/unit suite: relay infrastructure + crypto protocol. |
| `test-integration.ts` | Real end-to-end suite: relay + live peer processes. |
| `test-replay-poison.ts` | Malicious-relay suite: forged frames, replays, nack recovery, STS teardown. |
| `package.json` | Dependencies: `libsodium-wrappers-sumo`, `@modelcontextprotocol/sdk`, `zod`. |
