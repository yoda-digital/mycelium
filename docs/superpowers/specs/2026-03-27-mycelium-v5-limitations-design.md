# Mycelium v5 — Eliminating Known Limitations

**Date:** 2026-03-27
**Status:** Draft
**Scope:** 6 solutions for 6 documented limitations, ~380 lines total

## Context

Mycelium is a ~1900-line E2E encrypted peer-to-peer messaging system (TypeScript/Bun) with 3 completed security audits and 58 tests. The relay is a stateless WebSocket router; all crypto is client-side (TweetNaCl: Ed25519 identity + Curve25519 ephemeral PFS + NaCl crypto_box).

This spec addresses all 6 documented "Known Limitations" without losing features or adding unnecessary complexity.

## L1: Shared Token → Ed25519 Challenge-Response

**Problem:** `RELAY_TOKEN` is a room-level shared secret (relay.ts:322). Anyone with the token can join any room.

**Solution:** Token becomes a one-time invite capability. After initial registration, the relay stores the peer's Ed25519 pubkey in a persistent allow-list. On reconnection, authentication is via challenge-response using the peer's identity key.

### Protocol

```
1. Peer → ws connect
2. Relay → { type: "challenge", nonce: <32 random bytes> }
3. Peer → { type: "auth", token?, peer, room, sign_pubkey,
             challenge_sig: sign(nonce || peer || room, signSecretKey),
             eph_enc_pubkey, eph_enc_pubkey_sig, session_id }
4. Relay:
   - If sign_pubkey is in allow-list for room:
     → verify challenge_sig with stored pubkey → token field IGNORED
   - If sign_pubkey is NOT in allow-list:
     → verify token === RELAY_TOKEN AND verify challenge_sig
     → add {room, sign_pubkey, peer_name} to allow-list
5. Relay → { type: "auth_ok", peers: {...} }
```

### Changes

**relay.ts (~40 lines):**
- Import `tweetnacl` (already in package.json deps)
- Add `allowList: Map<string, Set<string>>` — maps room → set of base64 pubkeys
- Persist allow-list to `RELAY_ALLOW_FILE` (default `~/.mycelium-relay-allow.json`)
- In WebSocket open handler: send `challenge` message with 32-byte random nonce, store nonce on `ws.data`
- In auth handler: verify `challenge_sig` using provided `sign_pubkey`. If pubkey is known, skip token check. If new, require valid token AND valid sig, then add to allow-list.
- New env: `RELAY_ALLOW_FILE` (path to allow-list persistence)

**peer-channel.ts (~15 lines):**
- In `connectRelay()` message handler: when receiving `type: "challenge"`, compute `sig = nacl.sign.detached(concat(nonce, peerNameBytes, roomBytes), ltKeys.signSecretKey)`, include as `challenge_sig` in auth message.

### Revocation

Remove a pubkey from the allow-list file. Peer's next connection attempt fails challenge-response (sig verifies against a key not in the list). No token change needed.

### Backward Compatibility

Relay accepts both flows: if no challenge was sent (old relay), peer omits `challenge_sig`. If peer sends no `challenge_sig` (old peer), relay falls back to token-only auth. Feature flag: `RELAY_REQUIRE_CHALLENGE=true` to enforce challenge-response.

## L2: TweetNaCl Timing → libsodium WASM

**Problem:** JavaScript JIT doesn't guarantee constant-time operations. `nacl.box.before()` (ECDH) and `nacl.sign.detached()` (Ed25519 signing) are theoretically timing-vulnerable.

**Practical risk assessment:** Low. `box.before()` runs once per session (unattackable). `sign.detached()` runs per message but WebSocket jitter (1-50ms) drowns sub-microsecond timing signals. This is defense-in-depth.

**Solution:** Replace `tweetnacl` + `tweetnacl-util` with `libsodium-wrappers-sumo` (WASM build). API is near-identical. WASM executes with deterministic instruction dispatch — JIT cannot introduce timing variance. The underlying C libsodium is audited constant-time code.

### Changes

**package.json:**
- Remove: `tweetnacl`, `tweetnacl-util`
- Add: `libsodium-wrappers-sumo`

**peer-channel.ts (~60 lines changed, 0 net new):**
Replace all call sites (10 total):

| TweetNaCl | libsodium |
|-----------|-----------|
| `nacl.sign.keyPair()` | `sodium.crypto_sign_keypair()` |
| `nacl.sign.detached(msg, sk)` | `sodium.crypto_sign_detached(msg, sk)` |
| `nacl.sign.detached.verify(msg, sig, pk)` | `sodium.crypto_sign_verify_detached(sig, msg, pk)` |
| `nacl.box.keyPair()` | `sodium.crypto_box_keypair()` |
| `nacl.box.before(pk, sk)` | `sodium.crypto_box_beforenm(pk, sk)` |
| `nacl.box.after(m, n, k)` | `sodium.crypto_box_easy_afternm(m, n, k)` |
| `nacl.box.open.after(c, n, k)` | `sodium.crypto_box_open_easy_afternm(c, n, k)` |
| `nacl.randomBytes(n)` | `sodium.randombytes_buf(n)` |
| `nacl.hash(data)` | `sodium.crypto_hash(data)` |
| `naclUtil.encodeBase64/decodeBase64` | `sodium.to_base64/from_base64` |

**relay.ts:** If L1 adds tweetnacl to relay, use libsodium there too (same dep).

**Initialization:** Add `await sodium.ready` at boot (WASM module load).

### Unlocks

- `sodium.crypto_box_seal()` — needed for L6 (encrypted auth token)
- `sodium.crypto_sign_ed25519_pk_to_curve25519()` — needed for L6 (relay identity)

## L3: No Message Ordering → Request-ID Correlation + Reorder Buffer

**Problem:** Messages arrive out of order. Primary use case is request/response.

**Hidden bug discovered:** `checkReplay()` (peer-channel.ts:336-341) treats ANY out-of-order seq as replay (`seq <= last → seqBad = true`). If WebSocket delivery reorders messages (e.g., after reconnect with offline queue drain), legitimate messages are silently dropped. This is a correctness bug, not just a limitation.

### Part A: Request-ID Correlation (~25 lines)

Add optional `request_id` field to messages for application-layer grouping.

**peer-channel.ts changes:**
- `myc_send` tool: accept optional `request_id` parameter
- `sendEncrypted()`: include `request_id` in plaintext payload before encryption
- `canonicalSign()` / `verifySig()`: add `request_id` as 11th canonical field (sorted position between `payload` and `sender`)
- Inbound messages: include `request_id` in MCP notification if present

### Part B: Seq Reorder Buffer (~70 lines)

Replace immediate processing with a small per-peer buffer that emits messages in seq order.

**New data structure:**
```typescript
interface BufferedMsg {
  seq: number
  sessionId: string
  msg: any
  receivedAt: number
}

// Per-peer, per-session ordered buffer
const reorderBuffers: Map<string, Map<string, BufferedMsg[]>> = new Map()
```

**Buffer logic:**
```
On message arrival for peer P, session S with seq N:
  1. Insert into reorderBuffers[P][S] sorted by seq
  2. Try flush: while buffer[0].seq === expectedSeq[P][S]:
     - Remove from buffer, process message, expectedSeq++
  3. If buffer.length > 5: force-flush oldest (prevents unbounded buffering)
  4. Timer: every 100ms, force-flush any message older than 200ms

On session change (new session_id from peer):
  - Force-flush remaining buffer for old session
  - Reset expectedSeq for new session
```

**Changes to `checkReplay()`:**
- Remove the `seq <= last → seqBad` check (the buffer handles ordering)
- Keep `seenMsgIds` dedup (msg_id uniqueness is still checked before buffering)
- After buffer flush emits a message, update `peerSeqs[from][sid]` for persistence

### Backward Compatibility

Request-ID is optional — omitting it preserves current behavior. The reorder buffer is transparent to the sender; receivers get messages in order regardless of sender version.

## L4: Single Relay → Multi-Relay Client Failover

**Problem:** One relay = one point of failure.

**Key insight:** The relay is already stateless. Peers re-auth on reconnect, regenerate ephemeral keys, rebuild sessions. The offline queue is lost on relay death, but delivery acks (30s timeout) already notify senders. The system is 90% ready for redundancy.

### Solution (~20 lines in peer-channel.ts)

**New env format:** `MYC_RELAY=wss://r1.example.com,wss://r2.example.com`

**Changes:**
```typescript
const relays = RELAY!.split(',').map(s => s.trim()).filter(Boolean)
let relayIdx = 0

function connectRelay() {
  const url = relays[relayIdx % relays.length]
  log(`Connecting to relay ${relayIdx % relays.length + 1}/${relays.length}: ${url}`)
  // ... existing connection logic with url instead of RELAY
}

function scheduleReconnect() {
  relayIdx++  // try next relay
  // ... existing exponential backoff logic
}
```

**Room convergence:** All peers use the same ordered list. On failover, all converge on the same relay (first available). If r1 dies, all go to r2.

**Reconnect cycle:** After exhausting the list, wrap around with exponential backoff applied to the full cycle (not per-relay).

### Future: Cross-Relay Routing (Phase 2, not in this spec)

When multiple relays must serve simultaneously (not just failover), add NATS as message bus between relay instances (~60 lines in relay.ts). Each relay subscribes to `mycelium.{room}` subjects. This is documented as upgrade path but deferred.

## L5: First-Contact MITM → STS Mutual Authentication

**Problem:** The relay can MITM the first key exchange by substituting keys. README says "architecturally unresolvable without PKI." This is incorrect.

**Solution:** Station-to-Station (STS) protocol. After key distribution (existing flow), peers run a 2-message mutual authentication handshake through the relay. The relay sees only ciphertext. Zero relay changes.

### Protocol

After `auth_ok` distributes keys and `processPeerKeys()` computes the initial shared key:

```
Alice and Bob already have an encrypted channel (from eph key exchange).
STS upgrades it to a mutually authenticated one:

1. Alice → Bob (encrypted via existing session):
   { type: "_sts_init",
     sts_eph_pub: <Alice's fresh 32-byte DH public>,
     sender: "alice" }

2. Bob receives, generates own DH pair, computes:
   K = DH(bob_sts_secret, alice_sts_pub)
   sig_bob = sign(alice_sts_pub || bob_sts_pub, bob_sign_secret_key)

   Bob → Alice (encrypted):
   { type: "_sts_reply",
     sts_eph_pub: <Bob's DH public>,
     sig: base64(sig_bob),
     sender: "bob" }

3. Alice verifies:
   K' = DH(alice_sts_secret, bob_sts_pub)  // K' === K
   verify(sig_bob, alice_sts_pub || bob_sts_pub, bob_sign_pubkey)
   If verification fails → BLOCK peer, notify "STS auth failed"

   sig_alice = sign(alice_sts_pub || bob_sts_pub, alice_sign_secret_key)

   Alice → Bob (encrypted):
   { type: "_sts_complete",
     sig: base64(sig_alice),
     sender: "alice" }

4. Bob verifies sig_alice. If fail → BLOCK.
   Both sides mark session as "sts_verified".
```

### Why MITM Fails

If the relay substituted keys during distribution, it would need to forge signatures for both Alice and Bob in the STS handshake. It cannot — it does not have their Ed25519 private keys. The mutual signatures prove each side holds the private key corresponding to the `sign_pubkey` that was distributed.

### Changes

**peer-channel.ts (~60 lines):**
- `initSTS(peerName)`: generate DH pair, send `_sts_init`, store pending state
- `handleSTSReply(msg)`: verify peer's sig, send `_sts_complete`, mark verified
- `handleSTSComplete(msg)`: verify peer's sig, mark verified
- In `processPeerKeys()`: after session created, call `initSTS(peerName)` for newly joined peers
- In message handler: route `_sts_init`, `_sts_reply`, `_sts_complete` types
- New field on `PeerSession`: `stsVerified: boolean`
- Optional: refuse non-STS messages if `MYC_REQUIRE_STS=true`

### Graceful Degradation

STS is opportunistic. If peer doesn't respond to `_sts_init` within 10s, fall back to TOFU-only (current behavior). Old peers that don't understand `_sts_*` messages ignore them (existing unknown-type handling). Mixed deployments work: STS-capable peers verify each other, non-STS peers use TOFU.

### Composability with TOFU

STS and TOFU are complementary:
- **First connection, both STS-capable:** STS verifies, TOFU pins. No MITM possible.
- **First connection, one side old:** TOFU pins (current behavior). Vulnerable to first-contact MITM.
- **Subsequent connections:** TOFU prevents key change. STS re-verifies per session.
- **TOFU violation + STS:** Both independently block the peer. Belt and suspenders.

## L6: No TLS Pinning → Relay Ed25519 Identity + Encrypted Auth Token

**Problem:** Corporate TLS-intercepting proxies can see `MYC_TOKEN` in plaintext on the WebSocket.

**Solution (two layers):**

### Layer 1: Relay Ed25519 Identity (~50 lines)

The relay gets its own Ed25519 keypair, independent of TLS. The fingerprint is distributed out-of-band.

**New env vars:**
- Relay: `RELAY_KEY_FILE` (default `~/.mycelium-relay-keys.json`)
- Peer: `MYC_RELAY_FINGERPRINT` (expected fingerprint, e.g., `a1b2:c3d4:e5f6:...`)

**Protocol change — relay sends identity proof before peer sends auth:**
```
1. Peer → ws connect
2. Relay → { type: "challenge", nonce: <32 bytes>,
             relay_pubkey: <base64 Ed25519 pub>,
             relay_sig: sign(nonce || timestamp, relay_secret_key) }
3. Peer:
   - Compute fingerprint(relay_pubkey)
   - If MYC_RELAY_FINGERPRINT is set AND doesn't match → close, refuse to send token
   - Verify relay_sig with relay_pubkey (proves relay holds the private key)
4. Peer → auth message (now safe to send token)
```

This integrates naturally with L1's challenge-response: the `challenge` message now carries both the nonce (for peer auth) and the relay's identity proof.

**relay.ts changes (~30 lines):**
- Load/generate relay Ed25519 keypair at startup
- Include `relay_pubkey` + `relay_sig` in challenge message
- Log relay fingerprint at startup for operator reference

**peer-channel.ts changes (~20 lines):**
- On `challenge` message: verify relay identity if `MYC_RELAY_FINGERPRINT` is set
- If verification fails: close WebSocket, log error, do NOT send auth/token

### Layer 2: Encrypted Auth Token (~20 lines, requires L2 libsodium)

Even if relay identity verification is somehow bypassed, the token itself is encrypted.

**peer-channel.ts:**
```typescript
// Encrypt token to relay's Curve25519 key (derived from its Ed25519 pubkey)
const relayCurve = sodium.crypto_sign_ed25519_pk_to_curve25519(relayPubKey)
const sealedToken = sodium.crypto_box_seal(tokenBytes, relayCurve)
// Send sealedToken instead of plaintext token in auth message
```

**relay.ts:**
```typescript
// Decrypt sealed token
const relaySecretCurve = sodium.crypto_sign_ed25519_sk_to_curve25519(relaySecretKey)
const token = sodium.crypto_box_seal_open(sealedToken, relayPubKey, relaySecretCurve)
// Compare decrypted token against RELAY_TOKEN
```

### Backward Compatibility

- If `MYC_RELAY_FINGERPRINT` is unset, peer skips relay identity verification (current behavior)
- If relay doesn't send `relay_pubkey` (old relay), peer sends plaintext token (current behavior)
- Feature flag: `RELAY_REQUIRE_SEALED_TOKEN=true` to enforce encrypted tokens

## Synergy Map

```
L2 (libsodium WASM) ──unlocks──→ L6 (crypto_box_seal for encrypted token)
                     ──unlocks──→ L5 (STS with faster primitives)
                     ──shared──→ L1 (relay uses same libsodium dep)

L1 (challenge-response) ──shares message──→ L6 (challenge carries relay identity)
                         ──relay has sig verify──→ future audit capabilities

L3 (reorder buffer) ──fixes──→ L4 (offline queue drain no longer drops messages)

L4 (multi-relay) ──seamless with──→ L3 (request-ID survives reconnect)
```

## Implementation Order

1. **L2** — libsodium swap. Foundation. Unlocks L5 and L6 primitives.
2. **L1 + L6** — both modify relay auth flow. Implement together: challenge message carries both peer nonce and relay identity.
3. **L5** — STS. Pure peer-side. Independent of relay changes.
4. **L3** — reorder buffer + request-ID. Fixes latent bug.
5. **L4** — multi-relay. 20 lines, can be done anytime.

## Testing Strategy

Each limitation gets dedicated tests added to test.ts:

- **L1:** Challenge-response auth, allow-list persistence, revocation, backward compat with token-only
- **L2:** Round-trip encrypt/decrypt with libsodium, signature verify, key generation, WASM ready check
- **L3:** Out-of-order delivery handled correctly, request-ID correlation, buffer flush on timeout, buffer flush on capacity, session reset flushes buffer
- **L4:** Failover to second relay on disconnect, relay list cycling, convergence (all peers on same relay)
- **L5:** STS handshake succeeds, MITM detection (forged sig rejected), graceful degradation with non-STS peer, composability with TOFU
- **L6:** Relay identity verified, bad fingerprint rejected, sealed token decrypted correctly, plaintext token rejected when `RELAY_REQUIRE_SEALED_TOKEN=true`

## Non-Goals

- NATS integration (documented as Phase 2 upgrade path, not in this spec)
- WebRTC peer-to-peer (Bun WebRTC support not mature)
- Certificate transparency monitoring (operational, not protocol)
- Noise Protocol Framework (same guarantees as STS with 4x complexity)
- SPAKE2/OPAQUE (solves wrong threat — dictionary attack resistance, not token leakage)
