# Mycelium Wire Protocol v2

**Descriptive spec of the current implementation (v0.3.0). Normative source = [`canonical.ts`](../canonical.ts).**

This document describes the bytes on the wire between a Mycelium peer
(`peer-channel.ts`) and the relay (`relay.ts`), and between two peers through
that relay. It is *descriptive*: where this prose and the code disagree, the
code wins, and the canonical signed-field set is defined by `canonicalize()` in
`canonical.ts` — not by this table. `PROTO = 2` (exported from `canonical.ts`)
is the version negotiated in the handshake and stamped on every peer frame.

The relay is assumed hostile. It routes ciphertext it cannot read, cannot forge
or replay frames (Ed25519 over canonical JSON), and cannot re-route a frame into
another room or mint new message IDs for signed frames (`room`, `msg_id`, `seq`
are all inside the signature). What it *can* see is metadata: names, rooms,
timing, sizes, the messaging graph. That is a documented tradeoff, not a bug.

---

## 1. Transport

| Property | Value |
|---|---|
| Transport | WebSocket (`ws://` or `wss://`), one active connection per peer (sequential failover across `MYC_RELAY` list) |
| Frame encoding | UTF-8 **text** frames, each a single JSON object (`JSON.stringify` / `JSON.parse`) |
| Binary framing | none — everything is JSON; binary payloads are base64 strings inside JSON |
| Compression | `perMessageDeflate: false` (disabled on the relay) |
| Max frame size | `RELAY_MAX_MSG_BYTES` (default **65536**). Relay `maxPayloadLength`; larger logical messages are chunked by the peer (§10) |
| Backpressure | relay `backpressureLimit` 512 KiB, `closeOnBackpressureLimit: true`; a `send()` returning `0` is reported to the sender as an `error` frame, never dropped silently |
| Liveness | relay sends WebSocket `ping` every `RELAY_PING_INTERVAL` (30 s) and reaps peers with no `pong`; peer runs a 45 s inactivity watchdog and closes with `4100` |
| Base64 | libsodium `base64_variants.ORIGINAL` (standard alphabet, padded) for **all** keys, signatures, nonces, ciphertext |

### Base64 / hex conventions

- `sign_pubkey`, `eph_enc_pubkey`, `eph_enc_pubkey_sig`, `encrypted`, `nonce`,
  `sig`, `challenge_sig`, `relay_pubkey`, `relay_sig`, `sealed_token`,
  continuity/STS signatures — all **base64 ORIGINAL**.
- `session_id` — 16 random bytes rendered as **32 lowercase hex chars**.
- Fingerprints (identity + relay) — first 16 bytes of `crypto_hash` (SHA-512) of
  the raw public key, hex, grouped in fours with `:` (e.g. `a1b2:c3d4:…`, 8 groups).

---

## 2. The signed envelope

Every peer-to-peer frame (data and control) is:

1. **E2E encrypted** — `encrypted` holds NaCl ciphertext; the relay never sees plaintext.
2. **Signed** — `sig` is a detached Ed25519 signature over the *canonical serialization* of the frame, made with the sender's long-term identity key.

The signature is computed as:

```
sig = base64( crypto_sign_detached( utf8( canonicalize(frame) ), identity_secret_key ) )
```

`canonicalize(frame)` is `JSON.stringify` of a **whitelisted, fixed-order**
object. It is a *whitelist*: any field on the frame that is not one of the
canonical keys below (e.g. `from`, `sig`, `no_queue`, `ttl_s`) contributes
**nothing** to the signed bytes.

### 2.1 Canonical signed field set — EXACT order

From `canonicalize()` in `canonical.ts`, keys are emitted in this order:

| # | Key | Inclusion | Default when absent | Notes |
|---|---|---|---|---|
| 1 | `e2e` | always | `null` | `true` on all real peer frames |
| 2 | `encrypted` | always | `null` | base64 ciphertext (session box, or sealed box for offline) |
| 3 | `msg_id` | always | `null` | **signed** — relay cannot re-mint IDs for signed frames |
| 4 | `nonce` | always | `null` | 24-byte box nonce (session); `null` for offline (sealed box carries its own) |
| 5 | `offline` | **conditional** — only if `offline !== undefined` | — | `true` on offline envelopes; absent on session frames |
| 6 | `payload` | always | `null` | reserved; `null` on all E2E frames (plaintext rides in `encrypted`) |
| 7 | `proto` | **conditional** — only if `proto !== undefined` | — | `2` on all v2 frames; absent on legacy 0.2.x frames |
| 8 | `request_id` | always | `null` | request/response correlation |
| 9 | `room` | **conditional** — only if `room !== undefined` | — | **signed** — relay cannot re-route into another room |
| 10 | `sender` | always | `null` | claimed sender name; receiver checks it equals relay-stamped `from` |
| 11 | `seq` | always | `null` | **signed** monotonic per-connection counter; `null` on offline envelopes |
| 12 | `session_id` | always | `null` | sender's 128-bit session id; `null` on offline envelopes |
| 13 | `target` | always | `null` | unicast recipient name (`null` would mean broadcast, but broadcasts are fanned out as unicasts client-side) |
| 14 | `ts` | **conditional** — only if `ts !== undefined` | — | **signed** ms epoch; the freshness bound for offline envelopes |
| 15 | `type` | always | `null` | frame type (§5) |

**Presence-conditional semantics.** The four v2 additions — `offline`, `proto`,
`room`, `ts` — are covered **iff present on the frame** (`!== undefined`). This
is strip/add-safe: removing a present field or adding an absent one changes the
canonical string, so the signature fails either way, and an attacker cannot forge
the alternate form without the signing key. Frames from 0.2.x peers carry none of
the four and canonicalize exactly as they did in v1, so legacy verification is
unchanged. The eleven always-present keys default to `null` when the sender omits
them (`msg.x ?? null`), so `null` is a real, signed value.

### 2.2 What each frame shape actually includes

| Frame kind | `offline` | `proto` | `room` | `ts` | `nonce` | `seq` | `session_id` |
|---|---|---|---|---|---|---|---|
| **Session frame** (`sendCtrl`) | *absent* | `2` | set | ms epoch | 24-byte b64 | `0,1,2,…` | 32-hex |
| **Offline envelope** (`sendOffline`) | `true` | `2` | set | ms epoch | `null` | `null` | `null` |
| **Legacy 0.2.x** | *absent* | *absent* | *absent* | *absent* | b64 | number | 32-hex |

### 2.3 What is NOT covered by the signature

These travel next to a signed frame but are **outside** `canonicalize`'s
whitelist, so tampering with them cannot forge a signature — the protocol is
designed so they are either self-checking or safe to ignore:

| Field | Set by | Why it is safe unsigned |
|---|---|---|
| `sig` | sender | the signature itself; added after canonicalization |
| `from` | **relay** | stamped to the relay-authenticated identity; receiver hard-blocks unless `sender === from`, binding the signed `sender` to the authenticated connection |
| `no_queue` | sender | routing hint (§5.4); tampering only restores the old, worse behavior (a session frame getting queued into a guaranteed decrypt failure) |
| `ttl_s` | relay | informational, echoed on `queued` status frames |
| handshake key fields (`eph_enc_pubkey`, `eph_enc_pubkey_sig`, `sign_pubkey`, `challenge_sig`, …) | sender | verified by their own dedicated signatures during auth/key-exchange, not by the per-frame envelope sig |

Note that the *plaintext* is not directly signed; `encrypted` (the ciphertext)
is. Authenticity of plaintext therefore rests on: (a) the Ed25519 envelope
signature over the ciphertext, plus (b) NaCl authenticated encryption
(`crypto_box`, Poly1305) for session frames. For **offline** envelopes the sealed
box (`crypto_box_seal`) is anonymous and unauthenticated by construction, so the
Ed25519 envelope signature — verified against the sender's **TOFU-pinned** key —
is the *only* sender authentication. Both sides must therefore have met at least
once while online before offline delivery can be trusted.

---

## 3. Handshake: challenge / auth / auth_ok

Three messages, relay-initiated. The relay proves its identity, the peer proves
possession of its identity key by signing the challenge, and (for a first-time
registration) presents the invite token.

```
Peer                                   Relay
 │   ── WebSocket open ──────────────▶  │
 │                                      │  open() sends:
 │  ◀───────────── challenge ────────── │
 │  verify relay_sig against pinned fp  │
 │  sign(nonce‖peer‖rooms) w/ identity  │
 │  ─────────────── auth ─────────────▶ │  verify challenge_sig, token, bindings
 │                                      │  apply rotation continuity (if present)
 │  ◀────── auth_ok  |  auth_error ───── │
 │            (+ peer key maps)         │
```

### 3.1 `challenge` (relay → peer)

```json
{
  "type": "challenge",
  "nonce": "<b64 32 random bytes>",
  "relay_pubkey": "<b64 relay Ed25519 public key>",
  "relay_sig": "<b64 sign(nonce ‖ utf8(timestamp), relay_secret)>",
  "timestamp": "<ms epoch as decimal string>",
  "proto": 2
}
```

Relay signature covers `nonce || utf8(timestamp)` (byte concatenation). If the
peer has `MYC_RELAY_FINGERPRINT` pinned (comma list, one per relay), it computes
`fingerprint(relay_pubkey)` and requires membership in the pinned set, then
verifies `relay_sig`. Pinned but no `relay_pubkey`, missing `relay_sig`, or a bad
signature ⇒ fail closed, close `4099`. Without pinning, first contact is TOFU on
the relay identity as well.

### 3.2 `auth` (peer → relay)

```json
{
  "type": "auth",
  "peer": "<name>",
  "room": "<ROOMS[0]>",            // legacy single-room field (compat)
  "rooms": ["<room>", "..."],       // v2 multi-room; up to 8
  "proto": 2,
  "sign_pubkey": "<b64 Ed25519 identity public key>",
  "eph_enc_pubkey": "<b64 Curve25519 ephemeral public key>",
  "eph_enc_pubkey_sig": "<b64 sign(eph_enc_pubkey, identity_secret)>",
  "session_id": "<32-hex 128-bit session id>",
  "challenge_sig": "<b64 sign(nonce ‖ utf8(peer) ‖ utf8(rooms.join(',')), identity_secret)>",

  "rotation": {                     // present only immediately after myc_rotate_key
    "prev_sign_pubkey": "<b64 old identity public key>",
    "continuity_sig":   "<b64 sign(newPub ‖ utf8(peer) ‖ utf8(String(ts)), OLD_secret)>",
    "ts": 1730000000000
  },

  "sealed_token": "<b64 crypto_box_seal(TOKEN, relay_curve_pubkey)>",  // preferred
  "token": "<TOKEN>"                // plaintext fallback (only when no relay_pubkey and no pinning)
}
```

- **Challenge signature** covers `nonce || utf8(peer) || utf8(rooms.join(','))`.
  Binding the room list into the signature stops a relay from re-scoping the
  peer's membership. Against a legacy single-room relay a multi-room list simply
  fails the challenge check with a clear `auth_error` rather than silently
  joining the wrong room.
- **Token.** Required only for a *new* registration (an unknown name↔key binding
  in at least one requested room). Known peers re-authenticate with their key
  alone. `sealed_token` is `crypto_box_seal` to the relay's Curve25519 key
  (derived from its Ed25519 identity); if pinning is configured the peer refuses
  to fall back to a plaintext `token` on a seal failure (no downgrade).
- **Rotation continuity** is honored only on a challenge-signed (proven) auth, so
  a token-only client cannot rewrite bindings it does not control. The relay
  verifies `sign(newPub || peer || String(ts), old_secret)` against
  `prev_sign_pubkey` and, if the old key holds the name binding, migrates it to
  the new key.

### 3.3 `auth_ok` (relay → peer)

v2 shape (sent when the client sent `rooms[]` or `proto ≥ 2`):

```json
{
  "type": "auth_ok",
  "from": "_relay",
  "proto": 2,
  "payload": {
    "peer": "<name>",
    "rooms": ["<room>", "..."],
    "peers": {
      "<room>": {
        "<peerName>": {
          "sign_pubkey": "<b64>",
          "eph_enc_pubkey": "<b64>",
          "eph_enc_pubkey_sig": "<b64>",
          "session_id": "<32-hex>"
        }
      }
    }
  }
}
```

Legacy shape (0.2.x peer): `payload: { peer, room, peers: <flat name→keyinfo map> }`.

On `auth_ok` the peer clears all session/STS/trust state, then for each advertised
peer runs the key-exchange path (§4): verify `eph_enc_pubkey_sig`, TOFU-check
`sign_pubkey`, derive the shared key, and kick off STS. A peer whose key fails
verification (bad eph sig, TOFU violation, or prior STS failure) is parked in a
**blocked / pending-trust** state, not silently trusted.

### 3.4 `auth_error` (relay → peer)

`{ "type": "auth_error", "from": "_relay", "payload": "<reason>" }` followed by a
close. Reasons/close codes: invalid peer name / no key / bad rooms (`4006`), bad
challenge sig or missing when `RELAY_REQUIRE_CHALLENGE` (`4005`), invalid token
(`4005`), name↔key `identity mismatch` or `key conflict` (`4021`), key `revoked`
(`4022`), room `full` (`4010`).

---

## 4. Key exchange & session establishment (per connection)

Live sessions get forward secrecy from a fresh Curve25519 ephemeral generated on
every connection:

1. Each peer advertises `eph_enc_pubkey` **signed by its Ed25519 identity**
   (`eph_enc_pubkey_sig = sign(eph_pub, identity_secret)`), distributed by the
   relay in `auth_ok` / `peer_joined`.
2. The receiver verifies that signature, then TOFU-checks the advertised
   `sign_pubkey` for `(room, name)`:
   - `new` — first sight, pinned now (first-contact TOFU window);
   - `trusted` — matches the pin;
   - `changed` — **fail closed**, session blocked, `myc_trust` required.
3. Shared key: `crypto_box_beforenm(their_eph_pub, my_eph_priv)`; frames use
   `crypto_box_easy_afternm` (XSalsa20-Poly1305) with a per-frame 24-byte nonce.

Because the DH ephemeral is bound to each identity by `eph_enc_pubkey_sig`, the
exchange is authenticated and relay-MITM-resistant *before* STS runs. STS (§8)
then adds an explicit, live, mutually-confirmed channel binding.

---

## 5. Frame types

`type` is a free-form string on data frames and a fixed token on control frames.
Reserved control types are `_`-prefixed. A local caller (`myc_send`) may only send
non-reserved types **plus** the single exception `_perm_verdict`; any other
`_`-prefixed type is rejected before it reaches the wire, so a prompt-injected
model cannot forge protocol traffic.

### 5.1 Peer → peer data frames

| `type` | Meaning |
|---|---|
| `info` | default; general message |
| `request` / `response` | correlated via `request_id` |
| `announcement` | broadcast-style notice |
| *custom* | any printable string ≤ 64 chars, not `_`-prefixed (multi-agent apps route on these) |
| `_perm_verdict` | remote permission approval; the one sendable reserved type. Plaintext is `{ request_id, behavior }`; flows through the full verify→dedup→decrypt→commit→ack pipeline, then is dispatched to `notifications/claude/channel/permission` |

### 5.2 Peer → peer control frames (reserved)

| `type` | Direction | Encrypted plaintext | Purpose |
|---|---|---|---|
| `_ack` | receiver → sender | `ack:<msg_id>` | positive delivery ack; terminates the sender's retransmit loop |
| `_nack` | receiver → sender | `nack:<msg_id>` | verified-but-undecryptable frame (stale session ciphertext) → sender retransmits automatically with the same `msg_id` |
| `_sts_init` | initiator → responder | `{"sts":"init"}` | begin STS session confirmation (§8) |
| `_sts_reply` | responder → initiator | `{"sts_sig":"<b64>"}` | responder's binding signature |
| `_sts_complete` | initiator → responder | `{"sts_sig":"<b64>"}` | initiator's binding signature; completes mutual confirmation |
| `_key_rotate` | rotator → all known | `{"rotate":{"new_pubkey","continuity_sig","ts"}}` | identity-rotation announcement (§9) |
| `_perm_req` | requester → approver | JSON `{ request_id, tool_name, description, input_preview }` | encrypted permission request; ack-tracked like any message |

`_ack` / `_nack` / `_key_rotate` also have an **offline** variant (sealed
envelope) so an ack for an offline message can reach a sender who has themselves
gone offline; these are dispatched inside `processOfflineEnvelope`. STS and
`_perm_req` are session-only (they need a live shared key).

### 5.3 Relay → peer control frames (`from: "_relay"`)

| `type` | Payload | Meaning |
|---|---|---|
| `challenge` | see §3.1 | handshake step 1 |
| `auth_ok` / `auth_error` | see §3.3 / §3.4 | handshake result |
| `evicted` | `"superseded"` \| `"revoked"` | connection displaced by a same-identity reconnect, or revoked by the operator (then close `4020` / `4022`) |
| `peer_joined` | `{ peer, room, peers, sign_pubkey, eph_enc_pubkey, eph_enc_pubkey_sig, session_id }` | a peer joined `room`; carries its keys so the recipient can establish a session |
| `peer_left` | `{ peer, room, peers }` | a peer left `room` |
| `rooms` | `{ discovery, rooms: [{ name, peers, members? }] }` | reply to `list_rooms` |
| `relay_shutdown` | `"restarting"` | graceful shutdown notice (then close `1001`) |
| `queued` | `{ msg_id, ttl_s }` | an offline envelope was accepted into the relay queue |
| `error` | `{ payload: <reason>, msg_id? }` | honest delivery failure: `rate limited`, backpressure drop, `offline; not queued (session frame)`, `queue full`, `not a member of room`, or `invalid JSON` / `auth required`. If `msg_id` is tracked, it feeds the retransmit loop instead of the model |

### 5.4 Relay-consumed / routing frames

| `type` | Direction | Notes |
|---|---|---|
| `list_rooms` | peer → relay | unsigned; consumed by the relay, answered with `rooms` (not routed) |
| *(any routed frame)* | peer → relay → peer(s) | relay stamps `from = <authenticated name>`; if `msg_id` is absent it mints one, but signed frames always carry `msg_id` so it cannot alter theirs |

**Routing.** A frame with `target` is unicast to that peer within `room`; without
`target` it is broadcast to the room (minus the sender). An explicit `room` must
be one of the sender's joined rooms or the relay replies `error`. `no_queue`
(session frames set it, outside the signature) tells the relay to fail fast
rather than queue a session-encrypted frame that would be undecryptable after the
target rotates ephemeral keys; the sender then re-sends as an offline envelope.

### 5.5 Session frame vs offline envelope (exact fields)

Built by `sendCtrl` (session) and `sendOffline` (offline). Fields shown are the
frame as signed (plus `sig`, plus `no_queue` on session frames, added after
signing).

```jsonc
// SESSION FRAME (live peer; PFS)
{
  "target": "bob", "room": "default", "type": "info",
  "encrypted": "<b64 crypto_box_easy_afternm ciphertext>",
  "nonce": "<b64 24 bytes>",
  "e2e": true, "sender": "alice", "session_id": "<32-hex>",
  "payload": null, "msg_id": "alice-<t36>-<n36>", "seq": 0,
  "ts": 1730000000000, "proto": 2,
  "request_id": "…",          // only if correlating
  "sig": "<b64>",             // NOT in canonical
  "no_queue": true            // NOT in canonical; routing hint
}

// OFFLINE ENVELOPE (target absent; sealed to identity key; queued by relay)
{
  "target": "bob", "room": "default", "type": "info",
  "encrypted": "<b64 crypto_box_seal to bob's identity-Curve25519 key>",
  "nonce": null,
  "e2e": true, "offline": true, "sender": "alice", "session_id": null,
  "payload": null, "msg_id": "alice-<t36>-<n36>", "seq": null,
  "ts": 1730000000000, "proto": 2,
  "sig": "<b64>"              // verified against the TOFU-pinned sender key
}
```

---

## 6. `msg_id` semantics

| Aspect | Detail |
|---|---|
| Format (peer) | `` `${PEER}-${Date.now().toString(36)}-${msgIdSeq++.toString(36)}` `` — name-prefixed, monotonic within a process |
| Format (relay-minted) | `` `${Date.now().toString(36)}-${seq++.toString(36)}` `` — only for a frame that arrived **without** a `msg_id` (never a signed peer frame) |
| Coverage | **signed** (canonical key #3) — the relay cannot substitute IDs on signed frames |
| Dedup scope | `` `${room}\0${from}\0${msg_id}` `` — scoped to room **and** relay-authenticated sender, so no peer can burn another's ID namespace |
| Chunk parts | each part carries `` `${logicalId}#${i}` `` as its own `msg_id`, so parts are independently acked/dedup'd/retransmitted; reassembly keys on the logical id inside the ciphertext |
| Idempotent retransmit | retransmissions **reuse the original `msg_id`**; a verified duplicate is **re-acked, never re-delivered** |

**Commit-after-decrypt.** `checkReplay` is a *pure* check that commits nothing.
`commitReplay` runs only after a frame is **both** signature-verified **and**
successfully decrypted. Committing on an undecryptable frame would burn its
`msg_id` and make the sender's same-`msg_id` retransmission dedup away unread —
so an undecryptable-but-authentic frame is `nack`ed and its `msg_id` left
uncommitted, letting the retransmission through.

---

## 7. `seq` semantics & the replay window

| Aspect | Detail |
|---|---|
| Value | per-**connection** monotonic counter, `outboundSeq`, reset to `0` on every (re)connect; incremented once per `sendCtrl` session frame |
| Offline frames | `seq = null` (no session ordering); replay for these rests on `msg_id` dedup + the `ts` freshness window |
| Coverage | **signed** (canonical key #11) — an attacker cannot move a frame's position |
| Window | RFC 4303-style sliding window, **64 wide** (`SEQ_WINDOW = 64n`), per `(room, sender, session_id)` |
| State | `{ last: number, mask: bigint }` — `last` is the highest seq seen; bit *i* of `mask` = seq `(last − i)` seen |

**Accept / reject (`checkReplay`).** Given an incoming `seq` for a known
`(room, sender, session_id)` window:

- `seq > last` → **new**, accept (window shifts left by `seq − last` on commit).
- `seq ≤ last` and `last − seq ≥ 64` → **below the window → stale duplicate**, reject.
- `seq ≤ last`, inside the window, bit already set → **exact replay**, reject.
- `seq ≤ last`, inside the window, bit unset → **legitimately reordered**, accept
  (relay-queue drains and offline flushes can reorder within a session).

A verified duplicate (by `msg_id` or `seq`) is **re-acked** (unless it is itself
an `_ack`/`_nack`) so the sender's loop terminates, then dropped without
re-delivery.

**Retention.** `msg_id` dedup entries are held for `OFFLINE_MAX_AGE_MS + 5 min`
(`SEEN_EXPIRY_MS`), capped at `SEEN_MAX = 10000`, so dedup **outlives** the
offline freshness window — otherwise an offline ciphertext, decryptable for its
whole window, could be replayed after the dedup entry expired. State is persisted
to `MYC_REPLAY_FILE` with a write-ahead log (`.wal`) appended before delivery and
merged/cleared on the periodic save.

**Migration.** Pre-0.3.0 replay state (bare peer-name keys, bare-number seq
floors) is migrated conservatively on load: names are scoped to the first room,
and a bare seq floor becomes `{ last, mask: all-ones }` (whole window at/below it
treated as seen).

---

## 8. STS session confirmation

On top of the already-authenticated key exchange (§4), STS adds a live,
mutually-confirmed binding over **both** session ephemerals **and** both
`session_id`s **and** the room (domain separation), signed with the long-term
identity keys.

**Binding bytes** (both peers derive them identically, ordered by peer name so the
two symmetric sides never disagree):

```
binding = loEph ‖ hiEph ‖ utf8(loSid) ‖ utf8(hiSid) ‖ utf8(room)
```

where `(lo, hi)` are the two peers sorted by name; `Eph` is the raw Curve25519
ephemeral public key, `Sid` the 32-hex session id.

**Flow.** Exactly one initiator — the lexicographically **smaller** name — sends
`_sts_init`. The responder signs `binding` and returns it in `_sts_reply`; the
initiator verifies, signs its own side into `_sts_complete`; the responder
verifies that. Both then mark the session `stsVerified` (shown as `🤝`).

- **Timeout** (10 s) is lenient: the channel stays TOFU + eph-sig authenticated,
  just without the `🤝` flag — version skew or a slow peer must not break delivery.
- **Signature mismatch is fail closed:** a peer that signs the *wrong* binding
  over an authenticated channel is buggy or under attack, so the session is torn
  down, the peer blocked, and a human must re-verify fingerprints out of band and
  run `myc_trust` (same recovery path as a TOFU violation).

---

## 9. Key rotation continuity

`myc_rotate_key` generates a new Ed25519 identity and a **continuity statement**:

```
continuity_sig = sign( newPub ‖ utf8(peerName) ‖ utf8(String(ts)), OLD_secret )
```

- **Announcement** (`_key_rotate`, before the peer swaps keys): payload
  `{"rotate":{"new_pubkey","continuity_sig","ts"}}`, sent to every known peer over
  the live session, or as an offline envelope for absent peers.
- **Receiver** verifies `continuity_sig` against the peer's **currently-pinned**
  key for each room and, on success, moves the pin to `new_pubkey`. Verifying
  against the pinned (old) key means a stale announcement cannot roll a pin back
  after a later rotation, and an attacker without the old key cannot rotate anyone.
- **Relay** receives the same continuity statement in the next `auth` (`rotation`
  field) and migrates the name↔key binding, so no peer sees a TOFU violation.

The rotating peer persists `prev = { sign_public, continuity_sig, rotated_at }` and
replays it on reconnect until the binding is confirmed migrated.

---

## 10. Chunking

Logical messages larger than `CHUNK_LIMIT` (24000 plaintext bytes, chosen to fit a
64 KiB relay frame after seal + base64) are split. Each part is an **ordinary E2E
frame** whose plaintext is a wrapper:

```json
{ "__myc_chunk": { "id": "<logicalId>", "i": 0, "n": 3, "data": "<b64 slice>" } }
```

Because the wrapper is *inside* the authenticated ciphertext, the relay sees only
opaque, similarly-sized frames, and every part gets a signature, ack, dedup entry,
and independent retransmission for free. The receiver reassembles after decryption.
Guards: `n` bounded by `ceil(MAX_LOGICAL_BYTES / CHUNK_LIMIT) + 1`, ≤ 8 in-flight
buffers per `(room, sender)`, total bytes ≤ `MYC_MAX_MSG_BYTES` (default 1 MiB),
120 s assembly timeout.

---

## 11. Delivery, acks, and honest failure

Every tracked send lives in an outbox until acked; retransmission is machinery,
not a request to the model. Triggers to retransmit (same `msg_id`): `_nack`
(stale ciphertext), a relay `error` report, ack timeout (30 s session /
`OFFLINE_MAX_AGE_MS + 5 min` offline), the target reappearing (`peer_joined`), or
relay reconnect. Path preference on resend: **live session → offline envelope →
wait**. After `RETRY_MAX = 5` attempts the failure is surfaced honestly
(`delivery_failed`). The sender's model is told about a deferred send **exactly
once** — on confirmed delivery (`delivered`) or terminal failure — never "please
resend it yourself."

Inbound authenticity gate (`processRegularMessage`), any of which hard-blocks:
`!e2e`, missing `sender`, `sender !== from`, missing `sig`, missing `encrypted`,
(session) missing `nonce`, bad signature. Offline envelopes additionally require a
TOFU pin, a non-STS-failed peer, and `|now − ts| ≤ OFFLINE_MAX_AGE_MS`.

---

## 12. Version negotiation & legacy compatibility

- `PROTO = 2` is stamped in `challenge`, `auth`, `auth_ok`, and on every peer
  frame (`sendCtrl` / `sendOffline` set `proto: PROTO`).
- A peer sending `rooms[]` **or** `proto ≥ 2` gets the v2 `auth_ok` shape
  (`payload.rooms` + per-room peer maps); otherwise the legacy single-room shape.
- Legacy 0.2.x frames carry none of `offline` / `proto` / `room` / `ts`, so they
  canonicalize exactly as under v1 and verify unchanged.
- On a signature failure, if the frame's `proto` differs from ours the log hints
  at a protocol mismatch (`upgrade the older peer`) — a v2-signed frame will not
  verify against a v1 canonicalization and vice versa, because the conditional
  fields change the signed byte string.

---

## 13. WebSocket close codes

| Code | Side | Meaning |
|---|---|---|
| `1001` | relay | graceful shutdown |
| `4000` | relay | pong timeout (zombie reap) |
| `4001` | relay | stale (no pong past threshold) |
| `4002` | relay | send failed (reap) |
| `4003` | relay | auth timeout (no `auth` within `RELAY_AUTH_TIMEOUT_MS`) |
| `4004` | relay | first frame was not `auth` |
| `4005` | relay | bad/required challenge sig, or bad token |
| `4006` | relay | bad name / missing key / bad rooms |
| `4010` | relay | room full |
| `4020` | relay | superseded (same-identity reconnect evicts the old connection) |
| `4021` | relay | identity mismatch / key conflict (name↔key binding) |
| `4022` | relay | revoked key |
| `4099` | peer | relay identity mismatch / missing / bad sig / seal failure (pinning) |
| `4100` | peer | heartbeat (45 s inactivity watchdog) |
| `4200` | peer | rekey (reconnect under a rotated identity) |

---

## 14. Cross-reference

| Concern | Authoritative code |
|---|---|
| Canonical signed field set & order | `canonical.ts` — `canonicalize()`, `PROTO` |
| Framing, sign/verify, session/offline construction, replay window, STS, rotation, chunking, acks | `peer-channel.ts` |
| Handshake, routing, bindings, revocation, offline queue, rate limits, admin API | `relay.ts` |
| Threat model & documented tradeoffs | [`README.md`](../README.md) |
