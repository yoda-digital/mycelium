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

## What this is

Mycelium lets Claude Code instances talk to each other through a relay that is assumed to be hostile. The relay routes ciphertext it cannot read. If it misbehaves, the worst it can do is refuse to route, and even that gets detected.

I built it because I run agents on several machines and needed them to coordinate without me acting as the message bus, and without trusting the box in the middle. Everything else in the design follows from that one constraint.

Three dependencies (`libsodium-wrappers-sumo`, the MCP SDK, `zod`). No framework, no database, no build step for development. Read the whole protocol in an afternoon; that is a feature, not an accident.

## How delivery works

Delivery is handled by machinery, not by asking the model to try again.

Every message is acknowledged end to end. A lost ack, a dropped frame, a stale ciphertext, a rate limit: each of these feeds an outbox that retransmits with the same `msg_id`, so receivers deduplicate and nothing arrives twice. If the target is offline, the message is sealed to its long-lived identity key and waits in the relay's queue until it returns. If the relay itself is down, sends queue locally and flush on reconnect.

Your agent hears about a deferred send exactly once: when it is confirmed delivered, or when it has definitively failed. Nothing in between, and never "please resend it yourself."

Messages up to 1MB are chunked transparently. Inbound messages are pushed over the experimental `notifications/claude/channel` capability and also buffered in an inbox, so on hosts that ignore the notification channel you drain them with `myc_recv` instead. Either way, nothing is lost.

## Threat model

The question I actually care about: what can a fully compromised relay do?

| If the relay is compromised, can it... | Answer |
|---|---|
| Read messages? | No. Live traffic uses ephemeral Curve25519 keys; the shared secret never touches the wire. Offline messages are sealed to the recipient's identity-derived key. |
| MITM the key exchange? | No, after first contact. Every ephemeral key is signed by the sender's Ed25519 identity, and identities are TOFU-pinned. First contact is trust-on-first-use; verify fingerprints out of band (`myc_trust`) if that window matters to you. |
| Forge messages? | No. Canonical Ed25519 signatures over every frame. A bad signature is a hard block, not a warning. |
| Replay old messages? | No. `msg_id` and `seq` are inside the signature, and offline messages carry a signed timestamp with a freshness window. |
| Re-route a message into another room? | No. The room is inside the signature. |
| Forge permission approvals? | No. Permission traffic rides the same E2E envelope as everything else, and approval requests are delivery-acked. |
| Hijack a peer's name? | No. Names are persistently bound to identity keys in the relay's allow-list, enforced whether the owner is connected or not. Client-side TOFU pins the same binding independently, in case the relay lies. |
| Drop a message silently? | No. Acks, automatic retransmission, and honest terminal failures cover unicasts and every broadcast copy. |
| Decrypt past sessions? | Not for live traffic; ephemeral keys exist only in memory. Offline envelopes are the exception, covered under tradeoffs below. |
| See who talks to whom? | **Yes.** Names, rooms, timing, sizes, the full messaging graph. Read the next section. |

## Tradeoffs I made on purpose

Every one of these was a decision, not an oversight. You should know them before you deploy.

**Offline messages give up forward secrecy.** A queued message must survive the recipient rotating its session keys, so today it is sealed to their identity key instead. This is a current design choice, not a law of physics — signed prekey bundles (X3DH/PQXDH-style) would restore forward secrecy for offline mail, and that upgrade is specced in [`docs/roadmap/`](./docs/roadmap/). Live sessions keep per-connection PFS. If the exposure window bothers you meanwhile, rotate identities with `myc_rotate_key`; it is cheap and nothing breaks for peers that are online or return within the offline window.

**The relay sees metadata.** Who talks to whom, when, how often, how much. Hiding that means padding, cover traffic, and onion routing, which is a different and much larger project. If the metadata itself is your secret, Mycelium is the wrong tool, and I would rather tell you that here than have you discover it in production.

**First contact is TOFU.** A relay that MITMs the very first key exchange wins that exchange. Every layer after it (pinning, STS confirmation, signed ephemerals) exists so that this is the only window, and fingerprint verification closes it.

**Names are permanent.** A name binds to a key on first registration and stays bound. Legitimate key changes go through signed rotation; lost keys go through operator revocation. Inconvenient, and that is the point.

## The crypto, briefly

- Ed25519 identity per peer, persisted to disk, optionally passphrase-encrypted (Argon2id + secretbox)
- Curve25519 ephemerals per connection for live sessions; NaCl `crypto_box` (XSalsa20-Poly1305) via libsodium WASM, which is audited, constant-time code
- Offline envelopes: `crypto_box_seal` to the recipient's identity-derived key, authenticated by the envelope signature against the sender's TOFU pin, bounded by a signed timestamp
- Detached Ed25519 signatures over canonical JSON. The signed fields (`msg_id`, `seq`, `room`, `ts`, `request_id`, and the rest) live in one place, `canonical.ts`, so the implementation and the tests cannot drift apart
- STS-style mutual session confirmation on top of the signed key exchange. Timeout is lenient; a wrong binding signature is fail-closed, because a peer that signs the wrong bytes over an authenticated channel is either buggy or under attack
- Relay auth is Ed25519 challenge-response. The token is a one-time invite; known peers authenticate with their keys. The relay has its own identity keypair, and peers can pin its fingerprint (a comma list, so failover and pinning compose)
- Replay defense: write-ahead msg_id dedup per sender and room, an RFC 4303-style sliding window over the signed `seq`, and the timestamp window for offline frames. Verified duplicates get re-acked, never re-delivered

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

No Bun on the host? The published peer runs under Node too — use `npx` instead of a source path:

```json
"command": "npx",
"args": ["-y", "@yoda.digital/mycelium", "mycelium-peer"]
```

(The relay still runs on Bun; only the peer needs to run inside your MCP host.)

Then load it:

```bash
claude --dangerously-load-development-channels server:mycelium
```

The `--dangerously-load-development-channels` flag only turns on the live *push* channel, and it is optional. On any MCP host — Claude Code, Cursor, Windsurf, VS Code — `myc_recv` drains the exact same messages from an inbox, so you can skip the flag entirely and lose nothing.

Each peer needs a unique `MYC_PEER` name and the same `MYC_TOKEN`. Running several peers on one machine? Give each its own `MYC_KEY_FILE`, or they will share an identity and trip TOFU violations everywhere:

```json
"MYC_KEY_FILE": "~/.mycelium-keys-alice.json"
```

The full walkthrough, including systemd units, TLS proxying, and troubleshooting, is in [INSTALL.md](./INSTALL.md).

## Environment variables

### Relay (`relay.ts`)

| Variable | Default | What it does |
|---|---|---|
| `RELAY_TOKEN` | *required* | Shared auth token (one-time invite for new peers). No longer grants admin. |
| `RELAY_ADMIN_TOKEN` | *(none)* | Bearer token for `/admin/*`. Unset ⇒ admin is loopback-only. The invite token is **not** an admin credential. |
| `RELAY_HEALTH_TOKEN` | *(none)* | Bearer token for `/health`. Unset ⇒ falls back to the admin rule (admin token, or loopback). |
| `RELAY_PORT` | `9900` | Listen port |
| `RELAY_MAX_PEERS` | `50` | Max peers per room |
| `RELAY_MAX_MSG_BYTES` | `65536` | Max frame size (peers chunk larger messages) |
| `RELAY_RATE_LIMIT` | `300` | Messages/minute per peer |
| `RELAY_QUEUE_MAX_MSGS` | `50` | Offline queue depth |
| `RELAY_QUEUE_TTL_S` | `3600` | Offline message TTL. Defaults to the peer offline window so mail is not dropped before the sender's ack window closes; keep at or above the peers' `MYC_OFFLINE_MAX_AGE_S`. |
| `RELAY_QUEUE_FILE` | *(none)* | Persist the offline queue (ciphertext only) to this path, restored on boot — so a relay restart does not drop queued mail even when the sender is gone. Unset ⇒ in-memory. |
| `RELAY_REQUIRE_TLS` | `false` | Refuse non-TLS connections |
| `RELAY_TRUSTED_PROXY` | `false` | Trust X-Forwarded-For |
| `RELAY_MAX_IP_CONNS` | `10` | Max connections per IP |
| `RELAY_KEY_FILE` | `~/.mycelium-relay-keys.json` | Relay Ed25519 identity keypair |
| `RELAY_KEY_PASSPHRASE` | *(none)* | Encrypt the relay key file at rest |
| `RELAY_ALLOW_FILE` | `~/.mycelium-relay-allow.json` | Name↔key bindings and the revocation blocklist |
| `RELAY_REQUIRE_CHALLENGE` | `false` | Reject token-only auth |
| `RELAY_DISCOVERY` | `true` | Answer `list_rooms` for non-member rooms (counts only) |

### Peer (`peer-channel.ts`)

| Variable | Default | What it does |
|---|---|---|
| `MYC_RELAY` | *required* | WebSocket URL(s), comma-separated for failover |
| `MYC_TOKEN` | *required* | Auth token; not needed after first auth |
| `MYC_PEER` | *required* | This peer's name |
| `MYC_ROOM` | `default` | Room(s) to join, comma-separated, up to 8 |
| `MYC_KEY_FILE` | `~/.mycelium-keys.json` | Ed25519 identity keypair |
| `MYC_KEY_PASSPHRASE` | *(none)* | Encrypt the key file at rest; wrong passphrase refuses to start |
| `MYC_TOFU_FILE` | `~/.mycelium-known-peers.json` | Pinned peer keys, scoped per room |
| `MYC_REPLAY_FILE` | `~/.mycelium-replay-state.json` | Replay protection state |
| `MYC_RELAY_FINGERPRINT` | *(none)* | Relay fingerprint(s), comma-separated, one per relay |
| `MYC_OFFLINE_MAX_AGE_S` | `3600` | Freshness window for offline envelopes |
| `MYC_MAX_MSG_BYTES` | `1048576` | Max logical message size |

Use per-project `MYC_TOFU_FILE` and `MYC_REPLAY_FILE` paths if you don't want trust state shared across projects.

## MCP tools

| Tool | Description |
|---|---|
| `myc_send` | Encrypted unicast. PFS session frame when the target is live, identity envelope when it is offline. Acked, retransmitted, chunked as needed. Takes `request_id` and `room`. |
| `myc_broadcast` | Encrypted to all peers, one independently encrypted and acked copy each. `include_offline` reaches absent peers; `room` scopes it. |
| `myc_recv` | Drain the inbox. Works on any MCP host, notifications or not. `peek` inspects without draining. |
| `myc_peers` | Per-room peer list with trust status, offline-reachable peers, inbox depth. |
| `myc_rooms` | Room discovery via the relay. |
| `myc_trust` | Override a TOFU block after you have verified the fingerprint out of band. |
| `myc_verify` | Show the pinned Ed25519 fingerprint for any peer, or this peer's own identity, for out-of-band verification. Read-only, and it works on a *healthy* peer — so you can close the first-contact window instead of waiting for a block. |
| `myc_rotate_key` | Rotate this peer's identity with a signed continuity statement. Pins and the relay binding migrate; nobody sees a violation. |

## Relay admin

```bash
# Inspect bindings
curl -H "Authorization: Bearer $RELAY_ADMIN_TOKEN" http://relay:9900/admin/allowlist

# Revoke a peer: frees the name, blocklists the key, disconnects it
curl -X POST -H "Authorization: Bearer $RELAY_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"room":"default","name":"mallory"}' http://relay:9900/admin/revoke

# Undo a revocation
curl -X POST -H "Authorization: Bearer $RELAY_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"room":"default","pubkey":"<base64>","undo":true}' http://relay:9900/admin/revoke
```

Admin and health are gated by `RELAY_ADMIN_TOKEN` / `RELAY_HEALTH_TOKEN`, **not** the invite token — set them (or call from loopback) or the requests above return 401. This is deliberate: an invited peer holds `RELAY_TOKEN`, and that must never let it read the social graph or revoke others.

A revoked key cannot re-register even with the invite token. One honest caveat: an actor who still holds the token can mint a fresh identity under a new name. Rotate `RELAY_TOKEN` when you need someone fully out.

## Testing, and why it looks paranoid

v0.1.x could not deliver a single message between two peers. Seventy-five unit tests were green while both sides tore down every session they built. That release taught me the only lesson that matters for protocol code: it is not tested until two real processes have talked through a real relay.

So the suite spawns actual processes. It kills a peer mid-conversation and checks the message is waiting when it comes back. It runs a scripted malicious relay that forges frames, replays old ones, and lies about delivery, and checks the peer survives all of it. It walks a full key rotation and a full revocation. 176 tests across three suites:

```bash
bun run test              # everything
bun run test:unit         # relay infrastructure + protocol units (89)
bun run test:integration  # real relay + real peer processes (63)
bun run test:poison       # scripted malicious relay vs a real peer (24)
```

CI runs all of it on every push and every PR, and again before anything reaches npm. The [changelog](./CHANGELOG.md) keeps the full honest history, including the failures.

## Architecture

| File | Purpose |
|---|---|
| `relay.ts` | WebSocket relay. Challenge-response auth, persistent name bindings, revocation, multi-room routing, offline queues, admin API. |
| `peer-channel.ts` | MCP server. Encryption, offline envelopes, outbox and retransmission, inbox, STS, TOFU, rotation, chunking, failover. |
| `canonical.ts` | The one place that defines which fields a signature covers. |
| `test.ts` | Unit suite. |
| `test-integration.ts` | Real end-to-end suite. |
| `test-replay-poison.ts` | Malicious-relay suite. |

The historical audit trail from the original hardening reviews lives in [`docs/source/README.md`](./docs/source/README.md), preserved with a note about what has changed since.

MIT licensed. Built and maintained by [Yoda Digital](https://opensource.yoda.digital/en/projects/mycelium/).
