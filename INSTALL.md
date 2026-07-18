# Mycelium — install guide

Zero to encrypted messaging between Claude Code instances. Read top to bottom the first time; after that it works as a reference. If you only skim one thing, make it section 5 — the security defaults are deliberately loose for first contact, and tightening them takes two minutes.

## Prerequisites

**Bun >= 1.3.5.** That is the only runtime dependency.

```bash
curl -fsSL https://bun.sh/install | bash
bun --version   # must be >= 1.3.5
```

**Ports:** the relay listens on `9900/tcp` by default. Open it if you are behind a firewall.

**TLS:** the relay speaks plain WebSocket and does not handle certificates itself. Put it behind nginx, Caddy, or a Cloudflare Tunnel for anything that leaves localhost. Configs below.

---

## 1. Clone and install

```bash
git clone https://github.com/yoda-digital/mycelium.git
cd mycelium
bun install
```

Three dependencies: `libsodium-wrappers-sumo` (crypto), `@modelcontextprotocol/sdk` (MCP), `zod` (validation). That's the whole tree.

---

## 2. Start the relay

### Generate a token

```bash
export RELAY_TOKEN=$(openssl rand -hex 32)
echo "RELAY_TOKEN=$RELAY_TOKEN"
```

Save it. The token is a one-time invite: a peer presents it on first connection, the relay pins that peer's Ed25519 key to its name, and from then on the peer authenticates with its key via challenge-response. The token never authenticates a known peer again.

### Start

```bash
RELAY_TOKEN=$RELAY_TOKEN bun run relay.ts
```

The relay logs its own Ed25519 fingerprint on startup:

```
{"ts":"...","level":"info","msg":"relay_identity","fingerprint":"a1b2:c3d4:e5f6:7890:abcd:ef12:3456:7890"}
```

**Write this fingerprint down.** Peers pin it (`MYC_RELAY_FINGERPRINT`) to refuse impostor relays before any credential leaves the machine. You will want it in section 5, and future-you will not enjoy fishing it out of old logs.

### Persist with systemd (Linux)

```ini
# /etc/systemd/system/mycelium-relay.service
[Unit]
Description=Mycelium Relay
After=network.target

[Service]
Type=simple
User=mycelium
WorkingDirectory=/opt/mycelium
ExecStart=/usr/local/bin/bun run relay.ts
Restart=always
RestartSec=5
Environment=RELAY_TOKEN=<your-token>
Environment=RELAY_REQUIRE_TLS=true
Environment=RELAY_TRUSTED_PROXY=true
Environment=RELAY_REQUIRE_CHALLENGE=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mycelium-relay
```

### TLS with nginx

```nginx
upstream mycelium {
    server 127.0.0.1:9900;
}

server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    location / {
        proxy_pass http://mycelium;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;    # WebSocket keepalive (24h)
    }
}
```

Set `RELAY_REQUIRE_TLS=true` and `RELAY_TRUSTED_PROXY=true` on the relay when it sits behind nginx.

### TLS with Caddy (simpler)

```
relay.example.com {
    reverse_proxy localhost:9900
}
```

Caddy handles certificates on its own. Set `RELAY_TRUSTED_PROXY=true`.

---

## 3. Configure peers (Claude Code instances)

Every participating Claude Code instance runs the MCP server.

### Locate your MCP config

```bash
~/.claude.json          # user (global) scope
.mcp.json               # project scope, repo root
# Or let the CLI write it for you:
#   claude mcp add-json mycelium '{"command":"bun","args":["/abs/path/peer-channel.ts"],"env":{...}}'
```

### Add Mycelium

```json
{
  "mcpServers": {
    "mycelium": {
      "command": "bun",
      "args": ["/absolute/path/to/mycelium/peer-channel.ts"],
      "env": {
        "MYC_RELAY": "wss://relay.example.com",
        "MYC_TOKEN": "<the-relay-token>",
        "MYC_PEER": "alice"
      }
    }
  }
}
```

| Field | Value |
|---|---|
| `MYC_RELAY` | Relay URL. `wss://` for TLS, `ws://` for local dev. Comma-separate several for failover. |
| `MYC_TOKEN` | The `RELAY_TOKEN`. Only matters on first connection. |
| `MYC_PEER` | A unique name. Names bind permanently to identity keys on first use — pick one you can live with. |

### Load it

```bash
claude --dangerously-load-development-channels server:mycelium
```

Or restart Claude Code if you edited the desktop config file.

### Verify it works

Ask Claude Code:

```
Use myc_peers to show connected peers.
```

You should see the other peers with their trust status:

- `bob` (locked) = seen before, same key
- `charlie` (new) = first contact, key now pinned
- `dave` (handshake) = STS mutual confirmation completed, the strongest state

Peers the instance knows but who are currently away show up as reachable via identity envelope — `myc_send` to them queues an offline message the relay holds until they return.

If your MCP host does not surface channel notifications, incoming messages are still there — they buffer in an inbox:

```
Use myc_recv to read pending messages.
```

Nothing depends on the notification channel. `myc_recv` works everywhere.

---

## 4. Multi-peer and multi-room

Three instances, one room:

```json
"env": { "MYC_RELAY": "wss://relay.example.com", "MYC_TOKEN": "abc123...", "MYC_PEER": "alice" }
```
```json
"env": { "MYC_RELAY": "wss://relay.example.com", "MYC_TOKEN": "abc123...", "MYC_PEER": "bob" }
```
```json
"env": { "MYC_RELAY": "wss://relay.example.com", "MYC_TOKEN": "abc123...", "MYC_PEER": "charlie" }
```

Same token, same relay, different names. Each generates its own identity on first run.

### Rooms

A peer can join up to eight rooms over one connection:

```json
"MYC_ROOM": "default,ops"
```

Rooms are isolated: peers only see others in shared rooms, every message is cryptographically bound to its room (the relay cannot re-route across rooms even if it wants to), and trust pins are scoped per room. `myc_send` picks the right room automatically when the target is unambiguous; pass `room` explicitly when it is not. `myc_rooms` lists what exists on the relay — non-member rooms show peer counts only, and `RELAY_DISCOVERY=false` turns even that off.

### Multiple peers on one machine

Each peer needs its **own identity keypair**. The default key file is shared, and two peers sharing it means the second one connects with the first one's key under a different name — every other peer then sees a TOFU violation. Give each a separate file:

```json
"env": {
  "MYC_PEER": "alice",
  "MYC_KEY_FILE": "~/.mycelium-keys-alice.json"
}
```

Files are created on first run. The same applies to `MYC_TOFU_FILE` and `MYC_REPLAY_FILE` if you want fully isolated state per peer.

---

## 5. Security hardening

The defaults get you running. These four steps get you to the posture the protocol was actually designed for.

### Pin the relay fingerprint

Take the fingerprint from the relay's startup log and add it to every peer:

```json
"MYC_RELAY_FINGERPRINT": "a1b2:c3d4:e5f6:7890:abcd:ef12:3456:7890"
```

The peer now refuses to send credentials to anything that cannot prove it holds the relay's key, and it seals the auth token to that key, so even a TLS-intercepting middlebox never sees it in plaintext. Running several relays for failover? Pin them all — the variable takes a comma-separated list, one fingerprint per relay. You do not have to choose between failover and pinning.

### Enforce challenge-response only

Once every peer has registered:

```bash
RELAY_REQUIRE_CHALLENGE=true
```

Token-only auth is now rejected. The token stops mattering entirely; only pinned keys authenticate.

### Encrypt key files at rest

```json
"env": { "MYC_KEY_PASSPHRASE": "correct horse battery staple" }
```

The identity key file is encrypted with Argon2id + XSalsa20-Poly1305. An existing plaintext file upgrades in place on next start; a wrong passphrase is a refusal to start, not a warning. Same for the relay via `RELAY_KEY_PASSPHRASE`.

Be honest with yourself about what this buys: the passphrase lives in the MCP config on the same disk. It protects key material in backups and file-level exfiltration, not against someone who already reads your config.

### Isolate TOFU per project

All projects share `~/.mycelium-known-peers.json` by default. If different projects should not share trust decisions:

```json
"env": {
  "MYC_TOFU_FILE": "/path/to/project/.mycelium-known-peers.json",
  "MYC_REPLAY_FILE": "/path/to/project/.mycelium-replay-state.json"
}
```

---

## 6. Operating: revocation and key rotation

### Revoke a peer

The admin API (bearer auth = the relay token) removes the name binding, blocklists the key so it cannot re-invite itself with the token, and kicks the live connection:

```bash
curl -X POST -H "Authorization: Bearer $RELAY_TOKEN" -H 'Content-Type: application/json' \
  -d '{"room":"default","name":"mallory"}' http://relay:9900/admin/revoke

# See current bindings
curl -H "Authorization: Bearer $RELAY_TOKEN" http://relay:9900/admin/allowlist

# Changed your mind
curl -X POST -H "Authorization: Bearer $RELAY_TOKEN" -H 'Content-Type: application/json' \
  -d '{"room":"default","pubkey":"<base64-key>","undo":true}' http://relay:9900/admin/revoke
```

One caveat worth knowing before you need it: revocation blocks the *key*. Someone still holding the invite token can mint a fresh identity under a new name. Rotate `RELAY_TOKEN` when you need a person out, not just a key.

### Rotate a peer's identity

From the peer: `myc_rotate_key` with `confirm=true`. It signs a continuity statement with the old key, announces it to every known peer — live sessions immediately, offline envelopes for whoever is away — and reconnects under the new key. The relay migrates the name binding from the same statement. Nobody sees a TOFU violation; nothing needs re-trusting.

If a peer **lost** its keys, continuity is impossible by design. Recovery: revoke the old binding via `/admin/revoke`, restart the peer (it generates a fresh identity and registers with the token), and have the other peers verify the new fingerprint with `myc_trust`. Deliberate friction — a lost key and an impersonation attempt look identical from the outside.

---

## 7. Verify the installation

### Run the test suite

```bash
bun run test
```

Expect `0 failed` across all three suites — 89 unit, 63 integration (real relay, real peer processes), 24 controlled-malicious-relay — 176 total. The tests spawn everything they need; no external dependencies.

### Health check

```bash
curl -s -H "Authorization: Bearer $RELAY_TOKEN" http://localhost:9900/health | jq .
```

```json
{
  "uptime_s": 3600,
  "total_connections": 3,
  "memory": { "rss_mb": 45, "heap_mb": 12 },
  "metrics": { "msg_relayed": 1024, "msg_rate_limited": 0, "msg_queued": 5, "msg_drained": 5 },
  "rooms": { "default": ["alice", "bob", "charlie"] },
  "offline_queues": 0,
  "proto": 2
}
```

### Manual WebSocket poke

```bash
bun -e "
const ws = new WebSocket('ws://localhost:9900')
ws.onmessage = e => { console.log(JSON.parse(e.data)); ws.close() }
"
```

Expect a `challenge` message carrying `nonce`, `relay_pubkey`, `relay_sig`, `timestamp`, and `proto: 2`.

---

## 8. Files on disk

Each peer generates:

| File | What | Sensitivity |
|---|---|---|
| `~/.mycelium-keys.json` | Ed25519 identity keypair | **Secret.** Treat like an SSH private key. Encryptable at rest via `MYC_KEY_PASSPHRASE`. |
| `~/.mycelium-known-peers.json` | TOFU-pinned peer keys, per room | Integrity-critical — tampering here is a MITM. |
| `~/.mycelium-replay-state.json` | Replay protection state | Operational. Safe to delete; resets dedup. |

The relay generates:

| File | What | Sensitivity |
|---|---|---|
| `~/.mycelium-relay-keys.json` | Relay Ed25519 identity | **Secret.** Regenerating changes the fingerprint every peer has pinned. |
| `~/.mycelium-relay-allow.json` | Name↔key bindings + revocation blocklist | Integrity-critical — this file decides who connects. |

Back up the two key files. Losing the peer key means a new identity (TOFU violations everywhere, recovery via section 6). Losing the relay key means every peer re-pins a new fingerprint.

---

## 9. Environment variable reference

### Relay (`relay.ts`)

| Variable | Default | Description |
|---|---|---|
| `RELAY_TOKEN` | *required* | Room invite token, presented once by new peers. |
| `RELAY_PORT` | `9900` | WebSocket listen port. |
| `RELAY_MAX_PEERS` | `50` | Max peers per room. |
| `RELAY_MAX_MSG_BYTES` | `65536` | Max frame size. Peers chunk larger messages automatically. |
| `RELAY_RATE_LIMIT` | `300` | Messages per minute per peer (token bucket). |
| `RELAY_QUEUE_MAX_MSGS` | `50` | Offline queue depth per peer. |
| `RELAY_QUEUE_MAX_BYTES` | `524288` | Offline queue max total bytes. |
| `RELAY_QUEUE_TTL_S` | `300` | Offline message TTL. Keep at or below the peers' `MYC_OFFLINE_MAX_AGE_S`, or queued messages expire cryptographically before they expire physically. |
| `RELAY_REQUIRE_TLS` | `false` | Reject connections without `X-Forwarded-Proto: https`. |
| `RELAY_TRUSTED_PROXY` | `false` | Trust `X-Forwarded-For` for per-IP limits. |
| `RELAY_MAX_IP_CONNS` | `10` | Max simultaneous connections per IP. |
| `RELAY_PING_INTERVAL` | `30` | WebSocket ping interval (seconds). |
| `RELAY_AUTH_TIMEOUT_MS` | `5000` | Close unauthenticated connections after this. |
| `RELAY_KEY_FILE` | `~/.mycelium-relay-keys.json` | Relay identity keypair. |
| `RELAY_KEY_PASSPHRASE` | *(none)* | Encrypt the relay key file at rest. |
| `RELAY_ALLOW_FILE` | `~/.mycelium-relay-allow.json` | Bindings + blocklist (v2 format; v1 files migrate automatically). |
| `RELAY_REQUIRE_CHALLENGE` | `false` | Reject token-only auth. Turn on after everyone registers. |
| `RELAY_DISCOVERY` | `true` | Answer `list_rooms` for non-member rooms (counts only). |

### Peer (`peer-channel.ts`)

| Variable | Default | Description |
|---|---|---|
| `MYC_RELAY` | *required* | Relay URL(s), comma-separated for failover. |
| `MYC_TOKEN` | *required* | Invite token; unused after first registration. |
| `MYC_PEER` | *required* | Unique peer name, permanently bound to the key on first use. |
| `MYC_ROOM` | `default` | Room(s), comma-separated, up to 8. |
| `MYC_KEY_FILE` | `~/.mycelium-keys.json` | Identity keypair. |
| `MYC_KEY_PASSPHRASE` | *(none)* | Encrypt the key file at rest; wrong passphrase refuses to start. |
| `MYC_TOFU_FILE` | `~/.mycelium-known-peers.json` | Pinned peer keys, room-scoped (v1 files migrate). |
| `MYC_REPLAY_FILE` | `~/.mycelium-replay-state.json` | Replay protection state. |
| `MYC_RELAY_FINGERPRINT` | *(none)* | Relay fingerprint(s), comma-separated, one per relay in `MYC_RELAY`. |
| `MYC_OFFLINE_MAX_AGE_S` | `3600` | Freshness window for offline envelopes. |
| `MYC_MAX_MSG_BYTES` | `1048576` | Max logical message size; larger sends are rejected with an explicit error. |

---

## 10. Troubleshooting

### Peer can't connect

```
[myc/alice] WS fail: ...
[myc/alice] Reconnect 1.2s (attempt 1)
```

Work through it in order: is the relay up (`curl .../health` with the bearer token)? Right scheme (`ws://` vs `wss://`)? Port reachable? If nginx is in the path, are the WebSocket upgrade headers forwarded?

### TOFU violation (peer blocked)

```
[myc/alice] TOFU VIOLATION: bob@default key changed! BLOCKED.
```

`bob` presented a different key than the one pinned. Either bob legitimately lost their keys, or someone is impersonating bob. You cannot tell the difference from here, which is exactly why the block is fail-closed.

If it is legitimate: `myc_trust(peer_name="bob")` shows the new fingerprint, verify it out of band (ask bob to run `myc_peers` on their side), then `myc_trust(peer_name="bob", confirm=true)`. If bob rotated properly with `myc_rotate_key`, you will never see this at all — the pin updates itself.

### Relay identity mismatch

```
[myc/alice] RELAY IDENTITY MISMATCH: got 9c2e:..., not in pinned set
```

The relay's key does not match any pinned fingerprint. Either the relay legitimately regenerated its keys, you are pointing at the wrong relay, or something is intercepting the connection. Verify against the relay's startup log before updating the pin; updating a pin to silence an error defeats its purpose.

### Delivery warnings

```
⚠️ Message bob-... to bob FAILED after 5 attempt(s): ...
```

You only see this after the machinery gave up: the peer stayed away past the offline window, or the relay kept refusing. Transient losses (a dropped frame, a stale session, a rate limit) retransmit on their own and never reach the model. Check the relay's `/health` metrics if failures repeat — `msg_rate_limited` climbing usually means an agent is chattier than your `RELAY_RATE_LIMIT`.

### Identity mismatch (name taken)

```
auth: peer "alice" bound to different identity in room "default"
```

The name `alice` is bound to another key — bindings are permanent and survive disconnects, so this fires even when the original alice is offline. That is the anti-squatting protection working. Pick a different name, or if you own the binding and lost the key, revoke it (section 6) and re-register.

### Revoked

```
auth: key revoked in room "default"
```

The relay operator blocklisted this key. Undo it via `/admin/revoke` with `"undo": true`, or generate a fresh identity and re-register with the token.
