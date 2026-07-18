# Phase 3 — Peer-Gossiped Key Transparency (detection-first)

**Status: PROPOSED. Nothing in this document is implemented.** Every "add / change / new"
below is a design proposal for a future `wire protocol v3`; the shipped code is `v0.3.0`
(`PROTO = 2`). Where this document quotes behaviour, it cites the exact file and lines in the
shipped tree so the proposal cannot drift into fiction.

**Package:** `@yoda.digital/mycelium` v0.3.0 · **Target:** v0.4.0 (proto 3) · **Date:** 2026-07-18
· **Author:** maintainer design note

> **One-line thesis.** Give every identity a *self-signed, monotonically-versioned, append-only
> key-history record* (KHR), gossip its digest inside the frames peers already sign, and
> cross-check on receipt. This turns three silent failure modes — first-contact TOFU MITM, a
> rotation a peer slept through, and a revocation that never leaves one relay — into **loud,
> detectable divergence**, without trusting the relay and without building a log server. It is
> **detection-first**: inclusion/consistency proofs and auditors (full CONIKS/CT) are explicitly
> **out of scope** and deferred.

---

## 0. Why the obvious answer (a transparency log) does not apply here

Certificate Transparency, Google Key Transparency, WhatsApp AKD, and Apple's iMessage Contact Key
Verification all put keys into a **provider-operated, Merkle-backed, append-only log** and let
clients/auditors verify *inclusion* and *consistency* proofs against a signed tree head
([RFC 6962 Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962);
[google/trillian](https://github.com/google/trillian);
[Apple, *Advancing iMessage security: Contact Key Verification*](https://security.apple.com/blog/imessage-contact-key-verification/)).
CONIKS additionally makes the directory privacy-preserving with a VRF-indexed sparse Merkle tree
and detects an equivocating provider by **gossiping signed directory snapshots** between users and
auditors ([CONIKS, *Bringing Key Transparency to End Users*](https://eprint.iacr.org/2014/1004.pdf);
[VRF, RFC 9381](https://datatracker.ietf.org/doc/html/rfc9381);
[EthIKS](https://jbonneau.com/doc/B16b-BITCOIN-ethiks.pdf)).

**Mycelium cannot borrow that shape directly, because in Mycelium the log operator would be the
relay, and the relay is the adversary.** The relay is a "hostile WebSocket router" by design: it
routes ciphertext it cannot read and is assumed to try to forge, replay, re-route, strip, and
substitute (`docs/wire-protocol-v2.md` §top; `relay.ts:1-19`, `:88-120`). A log the relay signs
and serves is a log the relay can equivocate on at will; inclusion proofs it mints prove nothing
against a party that controls the tree. Any KT for Mycelium must therefore be **self-certifying at
the identity** and **cross-checked over a channel the relay cannot forge** — which Mycelium already
has: the per-frame Ed25519 envelope signature over `canonicalize()` (`canonical.ts`;
`peer-channel.ts:537-557`).

The design below keeps CONIKS' **security engine** (non-equivocation by gossip + monotonic,
append-only history) and drops its **infrastructure** (no provider log, no VRF directory, no
auditor tier). What remains is provably weaker than CONIKS — it *detects* equivocation rather than
*proving* inclusion — and this document is explicit about that boundary (§9, §11).

---

## 1. The three gaps, grounded in the shipped code

### 1.1 First-contact TOFU-MITM window

TOFU pins whatever key first arrives for a `(room, name)` and returns `'new'`; only a *later*
change is caught (`peer-channel.ts:224-240` `tofuCheck`, `:310-314`). The advertised
`sign_pubkey` is delivered by the relay in `auth_ok` / `peer_joined`
(`relay.ts:181-192` `peerKeyMap`, `:901-912`). The `eph_enc_pubkey_sig` is verified against that
same advertised `sign_pubkey` (`peer-channel.ts:305-308`), so a relay that substitutes a whole
consistent identity of its own on first contact is pinned as `'new'` with no warning. STS
(`peer-channel.ts:335-481`) then confirms a live channel to **that pinned key**, so it confirms
the MITM, not the victim. `myc_verify` (`peer-channel.ts:1382-1407`) lets a human close the window
out of band, but nothing does so automatically. **This is the classic TOFU first-use gap.**

### 1.2 Rotation catch-up gap (a valid chain hard-blocks a peer that slept)

Rotation is a **fire-and-forget push**, bounded twice by time:

- The rotator announces `_key_rotate` to online peers and as **offline envelopes** to known-offline
  peers (`peer-channel.ts:1525-1565` `rotateKey`). The offline announcement is queued by the relay
  with `RELAY_QUEUE_TTL_S` (default 3600 s; the constant comment records it was raised from **300**,
  `relay.ts:47-51`) and is **dropped** once expired (`relay.ts:275-297` `drainQueue` skips expired,
  `:299-310` cleanup deletes expired).
- Even if delivered, the receiver **rejects a stale offline envelope** when
  `|now − ts| > OFFLINE_MAX_AGE_MS` (default 3600 s) *before* it ever reaches `handleKeyRotate`
  (`peer-channel.ts:1692-1699`, dispatch at `:1717`).
- The rotator persists only **one** `prev` step (`peer-channel.ts:83`, `:1549-1554`), and the
  receiver verifies continuity **only against its currently-pinned key** (`:1567-1592`,
  esp. `:1581`). So two rotations while a peer is offline (`old→A→B`) are unrecoverable by
  announcement: the `A→B` statement is signed by `A`, which the sleeping peer never pinned.

**Net:** a peer offline past either window, or across two rotations, returns to find the relay
advertising a new key its pin does not match → `TOFU VIOLATION`, hard block, human `myc_trust`
required (`peer-channel.ts:1955-1962`) — *even though a fully valid continuity chain exists.* The
transient push has no durable, pull-able backing.

### 1.3 Revocation is relay-local only

Revocation lives entirely in the relay's allow-list: `revoked` is a per-room blocklist
(`relay.ts:428-435`, `:471-489` `checkAllowed` returns `'revoked'` → close `4022`), driven by the
operator over `POST /admin/revoke` (`relay.ts:645-657`, `:499-543` `revokeBinding`). It evicts the
live socket (`relay.ts:534-541`) and refuses re-auth on **that relay**. It does **nothing** to:

- **client TOFU pins** — every peer that already pinned the compromised key keeps trusting it and
  will still open its offline envelopes (`peer-channel.ts:1678-1725`);
- **other relays** — the multi-relay failover list (`peer-channel.ts:33`, `:1781`) means the same
  identity can simply present itself on relay B, which never heard of the revocation.

There is no identity-signed, relay-independent "this key is dead" statement that reaches clients.

---

## 2. Design principle: the record is the identity's, not the relay's

A **Key-History Record (KHR)** is a per-identity, append-only, hash-linked chain of
**self-signed statements**. Version 0 is a genesis; each later entry is a rotation or a revocation,
each links to the previous by hash, each is signed by the key that authorised the transition. The
chain **is** the identity's history; no third party signs or serves it authoritatively. Peers:

1. **gossip the compact head digest** `{v, h}` (version + 32-byte head hash) inside frames they
   already sign, so the relay can neither forge nor silently strip it (§4);
2. **cross-check** every head they see against what they have pinned, and **alert on divergence**
   (§6);
3. **pull and verify** the chain segment they are missing, anchored to their existing pin, walking
   the pin forward across *any number* of rotations (§7 — fixes §1.2);
4. treat a **revocation tombstone** in the chain as a client-side, relay-independent kill of the
   pin (§8 — fixes §1.3).

The security ceiling is CONIKS' gossip model: **an equivocating party is caught the moment its
honest head reaches the victim over any independent path.** It shrinks — it does not
cryptographically seal — the first-contact window (§1.1, §9).

---

## 3. Data model (PROPOSED)

### 3.1 KHR statement — the signed, hashed unit

Every entry has a **statement** (the fields that are hashed and signed) plus **attached
signatures** (verified independently, not re-hashed). Statement fields, fixed order:

| Field | Type | Present | Meaning |
|---|---|---|---|
| `v` | int ≥ 0 | always | monotonic version; `0` = genesis; `+1` per entry, no gaps |
| `action` | `"genesis"` \| `"rotate"` \| `"revoke"` | always | transition kind |
| `peer` | string | always | the identity's peer **name** — binds the chain to a name (§10.4) |
| `prev_hash` | b64(32) \| `null` | always | `null` at genesis; else `head_hash` of entry `v-1` |
| `key` | b64 Ed25519 pub | always | identity key **in effect after** this entry (for `revoke`: the key being retired) |
| `prev_key` | b64 Ed25519 pub | `rotate`,`revoke` | identity key in effect **before** this entry |
| `ts` | int (ms epoch) | always | wall-clock of the transition |
| `revocation_pubkey` | b64 Ed25519 pub | `genesis` (optional) | pre-committed cold key allowed to sign a future `revoke` (§8.2) |
| `reason` | string ≤ 64 | `revoke` (optional) | operator note |

**Canonical statement bytes** (`khr.ts`, PROPOSED — same whitelist/fixed-order discipline as
`canonicalize()` in `canonical.ts`):

```ts
// khr.ts (PROPOSED) — statement serialization is the single source for KHR sign+hash bytes.
export const KHR_PROTO = 1
const SIG_CTX  = 'myc-khr-entry-v1\0'   // domain tag for entry signatures
const HASH_CTX = 'myc-khr-head-v1\0'    // domain tag for the chain/head hash

export function khrStatement(e: any): string {
  const o: Record<string, any> = { v: e.v, action: e.action, peer: e.peer, prev_hash: e.prev_hash ?? null, key: e.key }
  if (e.prev_key !== undefined) o.prev_key = e.prev_key
  o.ts = e.ts
  if (e.revocation_pubkey !== undefined) o.revocation_pubkey = e.revocation_pubkey
  if (e.reason !== undefined) o.reason = e.reason
  return JSON.stringify(o)
}
```

**Head hash** (32 bytes, BLAKE2b via `crypto_generichash`, distinct domain from the signature so a
KHR value can never be replayed as a frame/STS signature — see §10.1):

```ts
export function khrHeadHash(e: any): Uint8Array {          // → prev_hash of entry v+1
  return sodium.crypto_generichash(32, sodium.from_string(HASH_CTX + khrStatement(e)))
}
function khrSignBytes(e: any): Uint8Array {
  return sodium.from_string(SIG_CTX + khrStatement(e))
}
```

Because `prev_hash` is inside the statement and the head hash covers the statement, a single
`(v, head_hash)` pair commits to the **entire** history — any change to any past entry changes
every later head hash. This is the standard hash-chain/Merkle-head property
([Trillian *Verifiable Data Structures*](https://google.github.io/trillian/)) applied to a
one-identity chain instead of a global tree.

### 3.2 Attached signatures

| Entry | `sig_new` (over `khrSignBytes`, by…) | `sig_prev` (over `khrSignBytes`, by…) |
|---|---|---|
| `genesis` | secret of `key` (proof of possession) | — |
| `rotate` | secret of `key` (new key POP) | secret of `prev_key` (**continuity**) |
| `revoke` | — | secret of `prev_key` **or** of `revocation_pubkey` committed at genesis (§8.2) |

`sig_prev` on `rotate` is exactly today's continuity idea
(`sign(newPub ‖ peer ‖ ts, oldSecret)`, `peer-channel.ts:1529-1531`, `relay.ts:555-580`) but
domain-separated and folded into the chain. **`sig_new` is new and strictly stronger:** today a
rotation is only signed by the *old* key, so a holder of the old key alone can announce a rotation
to a key it does not possess; requiring `sig_new` closes that.

### 3.3 On-disk shapes (PROPOSED)

Own chain — new file `~/.mycelium-key-history.json` (mode `0600`, like `KEY_FILE`,
`peer-channel.ts:59-66`):

```jsonc
{ "version": 1, "peer": "alice", "entries": [ /* KHR statements + sigs, v ascending */ ] }
```

Known-peer heads — **extend** `TofuEntry` (`peer-channel.ts:192-198`) in place, so a pin and the
KHR version it reflects move together atomically:

```ts
interface TofuEntry {
  sign_pubkey: string
  first_seen: string
  last_seen: string
  kt_version?: number   // NEW — KHR version this pin reflects (undefined = pre-KT / v2 peer)
  kt_head?: string      // NEW — b64 head_hash at kt_version (the anchor for catch-up, §7)
  revoked?: string      // NEW — set to the revoke reason/ts once a tombstone is verified (§8)
}
```

The v1→v2 TOFU migration (`peer-channel.ts:200-214`) is unaffected: the three new fields are
optional and simply absent for pre-KT pins, which behave exactly as today until a `kt` digest is
first seen for that peer.

---

## 4. Wire & canonical changes (PROPOSED, proto 3)

### 4.1 One new signed field: `kt`

Add a **presence-conditional** canonical field `kt` carrying the sender's **own** head digest
`{ v:int, h:"b64(32)" }`. It sorts between `encrypted` and `msg_id`. Presence-conditional keeps it
strip/add-safe exactly as the v2 fields are (`canonical.ts:7-13`, `docs/wire-protocol-v2.md`
§2.1): a hostile relay that strips `kt` or injects a forged one changes the canonical string and
the Ed25519 signature fails, so the frame is hard-blocked (`peer-channel.ts:1642-1645`).

```ts
// canonical.ts (PROPOSED) — bump PROTO to 3; insert kt after `encrypted`, before `msg_id`.
export function canonicalize(msg: any): string {
  const o: Record<string, any> = {
    e2e: msg.e2e ?? null,
    encrypted: msg.encrypted ?? null,
  }
  if (msg.kt !== undefined) o.kt = msg.kt          // PROPOSED v3 — { v, h } head digest
  o.msg_id = msg.msg_id ?? null
  o.nonce  = msg.nonce ?? null
  if (msg.offline !== undefined) o.offline = msg.offline
  o.payload = msg.payload ?? null
  if (msg.proto !== undefined) o.proto = msg.proto
  o.request_id = msg.request_id ?? null
  if (msg.room !== undefined) o.room = msg.room
  o.sender = msg.sender ?? null
  o.seq = msg.seq ?? null
  o.session_id = msg.session_id ?? null
  o.target = msg.target ?? null
  if (msg.ts !== undefined) o.ts = msg.ts
  o.type = msg.type ?? null
  return JSON.stringify(o)
}
export const PROTO = 3
```

Frames with no `kt` (all v2 and legacy frames) canonicalize **byte-for-byte as before** — the
proof is that `msg.kt === undefined` leaves `o` identical to the v2 object. So existing signatures,
tests, and the migration table in `docs/wire-protocol-v2.md` remain valid for kt-less frames.

### 4.2 Compatibility gate (mandatory — mirrors the v2 one-directional rule)

A v2 receiver's `canonicalize()` has no `kt` branch, so a v2-signed-verify of a **kt-bearing** v3
frame would fail (same asymmetry §12 of the v2 doc already documents for the v2 fields). Therefore
a v3 peer **must only attach `kt` to peers it knows speak proto ≥ 3**, and must send kt-less frames
to everyone else. To know a counterpart's proto:

- **Relay change:** `peerKeyMap` (`relay.ts:181-192`) adds `proto: p.proto`, stored from the peer's
  `auth` (`relay.ts:874-883` adds `proto: msg.proto ?? 1` to `Peer`). The relay only *transports*
  this integer; it is not trusted for anything but the emission gate (a relay that lies downgrades
  gossip to silence — no worse than dropping frames, §11).
- **Peer change:** `PeerSession` (`peer-channel.ts:264-274`) gains `proto: number`, set in
  `processPeerKeys` from the advertised map; `sendCtrl` (`:630-650`) attaches `kt` **iff**
  `session.proto >= 3`.

This is the same "upgrade the older peer" story the v2 doc tells (`§12`), and the signature-failure
log already hints at proto skew (`peer-channel.ts:1760-1765`).

### 4.3 New E2E control frames (inside the ciphertext; not new canonical fields)

All are reserved `_`-prefixed types, so `safeSendType` already forbids a prompt-injected model from
minting them (`peer-channel.ts:1439-1446`); all ride the existing verify→decrypt pipeline.

| `type` | Dir | Encrypted plaintext | Purpose |
|---|---|---|---|
| `_kt_gossip` | peer→room | `{"kt_gossip":[{ "peer","v","h" }, …]}` | third-party heads the sender has **verified**, for non-equivocation cross-check (§6.2). A **hint only** — never a trust input (§10.7) |
| `_kt_req` | peer→peer | `{"kt_req":{ "have_version":int }}` | "send me your chain from `have_version+1`"; emitted on *behind*/divergence (§7) |
| `_kt_resp` | peer→peer | `{"kt_resp":{ "entries":[ …KHR entries… ] }}` | the requested segment (statements + sigs), head-inclusive |
| `_key_rotate` (extended) | rotator→known | `{"rotate":{ …existing… , "entry": <KHR rotate entry> }}` | back-compatible superset of today's payload (`peer-channel.ts:1531`); the `entry` lets the receiver apply it as a one-hop verified segment |

`_kt_req`/`_kt_resp` are **session-only** (they need a live shared key and are a pull, not a
store-and-forward). `_kt_gossip` and extended `_key_rotate` keep their existing offline (sealed)
variants so a peer that rotates while its audience is away is still caught up on their return via
the durable chain rather than the transient envelope. Reserved-type handling in the offline path
already exists (`peer-channel.ts:1713-1721`).

---

## 5. Genesis & bootstrapping (PROPOSED)

On first boot under proto 3, if `~/.mycelium-key-history.json` is absent, synthesize `v0`:

```ts
// PROPOSED — seed a genesis for the CURRENT identity key.
const g = { v: 0, action: 'genesis', peer: PEER, prev_hash: null,
            key: toB64(ltKeys.signPublicKey), ts: Date.now() }
g.sig_new = toB64(sodium.crypto_sign_detached(khrSignBytes(g), ltKeys.signPrivateKey))
```

**Honest limitation.** An identity that was rotated *before* KT adoption kept only one `prev`
(`peer-channel.ts:83`) and **discarded the old secret** in `rotateKey` (`:1549-1554`), so its true
history cannot be reconstructed or signed retroactively. The genesis therefore roots at the
*current* key at adoption time; pre-KT rotations are outside the verifiable chain. This is a
one-time migration seam, not an ongoing property — flag it in release notes.

## 6. Cross-check on receipt (detection core)

### 6.1 From the signed `kt` field of a peer's own frame

After a frame is signature-verified and the peer is TOFU-known, compare the advertised
`kt = {v, h}` to the stored pin (`tofuGet(room, from)` → `TofuEntry`):

```
let pin = tofuGet(room, from)                        // has kt_version / kt_head after first KT contact
if pin.revoked:                    HARD BLOCK  (already dead — §8)
else if pin.kt_version === undefined:   adopt {v,h} as the pin's baseline (still TOFU — no security added yet)
else if v === pin.kt_version && h === pin.kt_head:   CONSISTENT (no-op)
else if v === pin.kt_version && h !== pin.kt_head:   EQUIVOCATION → alert, fail-closed (§6.3)
else if v  >  pin.kt_version:                        BEHIND → send _kt_req{ have_version: pin.kt_version } (§7)
else /* v < pin.kt_version */:                       STALE/rollback → ignore (monotonic; never downgrade)
```

The `EQUIVOCATION` branch is the whole point: a single honest history has exactly one head hash at
a given version, so two different `h` at the same `v` means someone (a MITM relay on first contact,
or the identity itself) presented two histories.

### 6.2 From third-party `_kt_gossip`

For each `{peer:P, v, h}` in a verified `_kt_gossip`, run the same comparison against the local pin
for `P`. This is how a first-contact MITM (§1.1) is caught **without ever reaching the real peer
directly**: any mutual, honest peer that has met the real `P` gossips `P`'s real head; if the
victim pinned an attacker's `P`, the two heads diverge at `v=0` and the victim alerts. Gossip is a
**hint that triggers verification or a fetch — it never advances a pin** (§10.7): a lying gossiper
can at worst raise a false alarm (fail-safe), never install a key.

**Emission.** Piggyback the sender's own `kt` on ordinary v3 frames (cheap, ~50 B, §4.1); send a
batched `_kt_gossip` of verified third-party heads on session establishment and on a slow timer
(e.g. every few minutes, capped per frame), scoped to same-room peers so it leaks no graph edges
the relay does not already see (`docs/wire-protocol-v2.md` §top lists the graph as known relay
metadata).

### 6.3 Divergence handling (fail-closed, human-in-the-loop)

Divergence is treated **exactly like today's TOFU violation / STS-mismatch fail-closed path**
(`peer-channel.ts:311-314`, `:365-389`): block the peer, surface an event through `deliver(...)`,
and require an out-of-band fingerprint check + `myc_trust` (`:1356-1380`) to resolve. KT cannot
decide *which* branch is the real identity — only that a fork exists — so it must not auto-pick;
it escalates to the human, same as CONIKS escalates an equivocation to the user/auditor.

## 7. Chain catch-up (fixes the §1.2 rotation gap)

On `BEHIND` (or as a probe after a divergence that might be an innocent multi-rotation), request
and verify the missing segment. Verification is anchored to the receiver's **existing** trusted
pin, so an attacker cannot substitute an unrelated valid-looking chain:

```
verifySegment(pin, entries):                          // entries = v = a+1 … n, a = pin.kt_version
  h_prev  = pin.kt_head            (b64 anchor)        // for a brand-new peer: the genesis, still TOFU
  k_prev  = pin.sign_pubkey        (current pinned key)
  expectV = pin.kt_version + 1
  for e in entries (ascending):
    require e.v === expectV                            // contiguous, monotonic, no gaps/rollback
    require e.prev_hash === h_prev                     // links to OUR anchor — the safety hinge
    require e.prev_key  === k_prev
    require verify(sig_prev, khrSignBytes(e), k_prev)  // old identity authorized the step (continuity)
    require e.action === 'revoke' || verify(sig_new, khrSignBytes(e), e.key)   // new key POP
    h_prev = khrHeadHash(e); k_prev = e.key; expectV += 1
    if e.action === 'revoke': mark pin.revoked; return REVOKED
  // atomically advance the pin
  tofuOverride-like: sign_pubkey = k_prev; kt_version = n; kt_head = h_prev
```

Because the loop walks **every** hop from the anchor to the head, a peer that missed `old→A→B→C`
while offline for a week catches up in one exchange — the failure the current single-`prev`,
TTL-bounded, freshness-bounded push cannot survive (`peer-channel.ts:1581`, `:1692-1699`;
`relay.ts:47-51`, `:299-310`). The chain is **pulled on demand** and is not subject to any relay
queue TTL or `OFFLINE_MAX_AGE_MS` freshness window; those still gate *message* envelopes, but the
key history is no longer a piece of expiring mail.

The extended `_key_rotate` (§4.3) is the online fast-path: its `entry` is a one-element segment
applied through the identical `verifySegment` (with `entries=[entry]`), so the online and
catch-up paths share one verifier — no second, drifting implementation.

## 8. Revocation tombstone (fixes the §1.3 relay-local gap)

### 8.1 Shape and effect

A `revoke` entry is an ordinary KHR entry (`action:"revoke"`) appended at the head. Its head digest
gossips like any other; a receiver that verifies it (via §7, or a pushed extended `_key_rotate`/a
dedicated `_kt_revoke` reusing the same entry transport) sets `TofuEntry.revoked` and **hard-blocks
the identity locally** — in `processRegularMessage` and `processOfflineEnvelope`
(`peer-channel.ts:1627-1725`) add an early `if (pin.revoked) BLOCK`. Because this is **client-side
pin state**, it is relay-independent: it invalidates the pin on every relay the client uses and
survives the identity reappearing on a fresh relay (§1.3). Keep the relay-side allow-list
revocation (`relay.ts:471-543`) as defense-in-depth; the tombstone is the part that reaches
clients.

### 8.2 Who may sign a revocation (the honest hard part)

- **Default:** `sig_prev` by the current key. This revokes a key the holder still controls
  (planned decommission, precautionary rotation-with-revoke). It does **not** help if the key was
  *stolen* — a thief holds the same key and could equally sign a revoke, or simply not, and could
  race a fork. This is the fundamental limit of any self-signed revocation and must be stated
  plainly.
- **Optional pre-commit (recommended):** at genesis, commit a `revocation_pubkey` — a **cold**
  Ed25519 key kept offline. A `revoke` signed by it is honoured even if the main secret is lost.
  This mirrors a recovery/break-glass key and is the standard mitigation, but it only helps if the
  cold key was *not* stolen together with the main one. No self-certifying scheme can do better
  without an external anchor (an auditor, a blockchain à la EthIKS, or an out-of-band human) — all
  explicitly out of scope (§9).

Revocation is **terminal** for a pin: recovery is a *new* identity (new genesis) verified out of
band, not an un-revoke of the dead chain.

## 9. What this is and is not (scope discipline)

**In scope (detection-first):** self-certifying per-identity KHR; monotonic append-only versioning
with rollback/equivocation invariants; signed `kt` head-digest gossip on existing frames;
third-party `_kt_gossip` cross-check; anchored multi-hop chain catch-up; self-signed revocation
tombstone that invalidates client pins across relays.

**Explicitly deferred / out of scope (do NOT claim these):**

| Deferred | Why, and what we lose |
|---|---|
| Inclusion proofs | No global log/tree exists; there is nothing to prove membership *in*. We detect forks, we do not prove "your key is the one true entry." |
| Consistency proofs / signed tree heads | Per-identity chains, not a global Merkle tree; append-only is enforced locally per chain, not globally attested. |
| Auditor / monitor tier | No third party is trusted to gossip snapshots; cross-check rides only peer gossip. A victim whose **every** gossip path is attacker-controlled indefinitely is not protected — same residual as CONIKS with no auditors. |
| VRF-indexed private directory | There is no directory; heads are per-identity and only shared with same-room peers, so CONIKS' privacy machinery is unnecessary and omitted. |
| Relay-served KHR | The relay is hostile; it may *transport* `_kt_*` frames (it already routes ciphertext) but is never an authority on any KHR. |

**The first-contact window is shrunk, not sealed.** With no CA/PKI, nothing cryptographically
prevents a first-use MITM; KT makes a *sustained* MITM require the attacker to control *all* of the
victim's gossip and out-of-band channels for as long as the deception must last, and makes any lapse
loud. That is the honest security claim.

---

## 10. Security review checklist

Each item is a property the implementation MUST satisfy, with the attack it defeats and where it
attaches in the code. Treat this as the review gate before any KT code merges.

1. **Domain separation.** KHR signatures use `SIG_CTX = "myc-khr-entry-v1\0"` and the head hash uses
   `HASH_CTX = "myc-khr-head-v1\0"`; both differ from the frame-signature input (`canonicalize()`
   bytes, `canonical.ts`) and the STS binding (`peer-channel.ts:398-409`). *Defeats:* replaying a
   KHR signature as a frame/STS signature or vice-versa. **Verify:** no signed byte-string is a
   prefix/substring of another across the four contexts.
2. **Monotonicity / no rollback.** A head with `v < pin.kt_version` is ignored; a segment must be
   contiguous from `pin.kt_version+1`. *Defeats:* a relay replaying an old rotation to roll a pin
   back to a retired (possibly compromised) key — the exact concern behind today's
   "verify against currently-pinned key" rule (`peer-channel.ts:1567-1592`).
3. **Equivocation is fail-closed, never auto-resolved.** Same `v`, different `h` ⇒ block + human
   `myc_trust`, never pick a branch. *Defeats:* a MITM steering the victim onto the attacker branch.
4. **Anchored catch-up only.** `verifySegment` requires `entries[0].prev_hash === pin.kt_head` and
   `prev_key === pin.sign_pubkey`. *Defeats:* substituting a self-consistent but unrelated chain;
   an attacker cannot forge a link to a hash they do not control.
5. **Dual signature on rotate.** Require **both** `sig_prev` (continuity, old key) and `sig_new`
   (POP, new key). *Defeats:* a holder of only the old key rotating to a key it does not possess —
   a gap in today's single-signature continuity (`peer-channel.ts:1529-1531`).
6. **`kt` is signed, presence-conditional, gated.** Stripping/forging `kt` fails the frame
   signature (blocked, `peer-channel.ts:1642-1645`); emission is gated on `session.proto >= 3` so a
   v2 peer never receives an unverifiable kt-bearing frame (§4.2). *Defeats:* silent downgrade of
   gossip to a v3 fleet; interop breakage with v2 peers.
7. **Gossip is a hint, not a trust input.** `_kt_gossip` and a peer's own `kt` may trigger an alert
   or a fetch; **only** a `verifySegment`-verified, anchored chain advances a pin. *Defeats:* a
   malicious gossiper installing a key or forcing a bad pin — worst case is a fail-safe false alarm.
8. **Revocation terminality & authority.** Only `sig_prev` (current key) or a genesis-committed
   `revocation_pubkey` may sign a `revoke`; a verified tombstone is terminal (new identity to
   recover). *Residual (documented, not fixed):* a thief holding the live key can also sign/forge —
   self-signed revocation cannot beat key theft without an external anchor (§8.2).
9. **Name binding.** `khrStatement.peer` MUST equal the relay-stamped `from`/`sender`
   (`peer-channel.ts:1632-1633`) and the pin's `(room,name)`. *Defeats:* lifting a valid chain onto
   a different name.
10. **Suppression / silence.** The relay can drop every kt-bearing frame and every `_kt_*` frame.
    This yields *no gossip*, not *false gossip* — it cannot manufacture consistency, only withhold
    detection. Mitigate with gossip redundancy (many frames, many peers, offline variants) and
    treat prolonged total silence as suspicious. **Verify:** no code path treats "no kt seen" as
    "consistent" — absence is `undefined`, handled as "adopt baseline / still TOFU," never "trusted."
11. **DoS via forced fetches.** A peer advertising ever-rising `v` could spam `_kt_req`. Bound:
    rate-limit `_kt_req` per `(room,peer)`, cap segment length, and cap `_kt_resp` bytes under the
    existing `MAX_LOGICAL_BYTES`/chunking limits (`peer-channel.ts:48`, `:1050`). Reuse the relay
    rate limiter (`relay.ts:204-213`).
12. **Hash/curve choices.** `crypto_generichash` (BLAKE2b-256) and Ed25519/`crypto_sign_*` are all
    in `libsodium-wrappers-sumo` already imported (`peer-channel.ts:23`); no new dependency. **Verify:**
    32-byte digests, constant-time `sodium.memcmp` for any secret compare (as `ctEq`,
    `relay.ts:32-37`) — though KHR compares are of public values, so ordinary equality is acceptable.
13. **Persistence integrity.** `~/.mycelium-key-history.json` is append-only in semantics; never
    rewrite or reorder past entries. Write `0600` via the existing `safeWrite`
    (`peer-channel.ts:59-66`). A corrupt/rolled-back file must fail closed (refuse to serve a
    shorter chain than a counterpart's verified `have_version`), not silently truncate history.
14. **Privacy.** Heads reveal only which same-room identities a peer has met — a subset of the graph
    the relay already sees (`docs/wire-protocol-v2.md` §top). No new metadata leaves the trust
    boundary. **Verify:** `_kt_gossip` is scoped to same-room peers and never enumerates cross-room
    identities.

## 11. Test plan

Follow the repo's stated discipline: protocol changes need the **real two-peer integration test**,
not just unit assertions (`test-integration.ts`; and the maintainer memory
*"integration-test discipline — unit suite alone masks total-delivery bugs"*).

**Unit (`test.ts` style, import from `khr.ts` + `canonical.ts` directly):**

- `canonicalize` with `kt` present vs absent → kt-less string is byte-identical to the v2 golden;
  kt-present changes the string; round-trip sign/verify holds.
- `khrStatement` field order/whitelist is stable; unknown fields contribute nothing.
- `khrHeadHash` chains: mutating any past statement changes every later head hash.
- `verifySegment`: (a) happy multi-hop `old→A→B→C`; (b) gap/rollback rejected; (c) wrong
  `prev_hash` anchor rejected; (d) missing `sig_new` rejected; (e) missing/`bad sig_prev` rejected;
  (f) `revoke` terminates and marks revoked.
- Domain separation: a valid KHR `sig_new` does **not** verify as a frame signature over any
  `canonicalize()` string, and vice-versa.

**Two-peer integration (`test-integration.ts` style, real relay + two peers):**

- **First-contact detection:** peer C gossips real head of A; B (which pinned an attacker A via a
  simulated substituting relay) raises equivocation and blocks — assert the `deliver` event and the
  hard block, not just a log line.
- **Rotation catch-up:** B goes offline; A rotates **twice**; B returns after `OFFLINE_MAX_AGE_MS`
  and after the relay queue TTL has dropped the announcements; assert B catches up via `_kt_req`/
  `_kt_resp` and does **not** hit `TOFU VIOLATION` — the precise regression the current design fails
  (§1.2). Include the negative control on a v0.3.0 build to show it *does* hard-block today.
- **Cross-relay revocation:** A publishes a revoke tombstone; B on relay-1 blocks A; A reappears on
  relay-2; assert B still blocks A there (client-side pin), while a stock v0.3.0 B would re-trust.
- **Interop / no-downgrade:** a v2 peer and a v3 peer in one room exchange messages; assert the v3
  peer omits `kt` toward the v2 peer, all frames verify, and delivery is unbroken.
- **Suppression:** relay drops all `_kt_*` and kt-bearing frames; assert peers degrade to plain
  TOFU (no false "consistent"), and no crash/leak.

**Adversarial (extend `test-replay-poison.ts` style):**

- Forged `_kt_gossip` (lying third-party head) → at most a false alarm, never a pin change.
- Replayed stale rotation / lower-`v` head → ignored.
- Malformed/oversized `_kt_resp` → rejected under existing size/chunk guards, no OOM.

## 12. Migration & rollout

1. **v0.4.0-alpha, opt-in flag** `MYC_KT=1`: peers build a genesis, persist the chain, and *emit*
   `kt` only to proto≥3 peers. Detection paths **log** divergence but do not yet hard-block
   (shadow mode) so false-positive rates can be measured before the block is armed.
2. **Bump `PROTO = 3`** only when the emission gate + `peerKeyMap.proto` land together; keep the v2
   canonicalization for kt-less frames so the fleet upgrades incrementally (`docs/wire-protocol-v2.md`
   §12 semantics preserved).
3. **Arm fail-closed** (equivocation/revocation → block) in a later minor, after shadow-mode data.
4. **Docs:** promote the finalized parts into `docs/wire-protocol-v2.md` → a new
   `wire-protocol-v3.md`, and record the design decision in the maintainer memory wing
   (`mycelium-*` notes) as the prior phases did.

Never run any of this through an auto-loop; it is protocol/security code and each step needs the
real two-peer test green before the next.

## 13. References

- CONIKS — Melara et al., *Bringing Key Transparency to End Users* — https://eprint.iacr.org/2014/1004.pdf
- EthIKS — Bonneau, *Using Ethereum to audit a CONIKS log* (gossip/equivocation) — https://jbonneau.com/doc/B16b-BITCOIN-ethiks.pdf
- Apple — *Advancing iMessage security: Contact Key Verification* (log-backed CONIKS map, SMTs, VRF) — https://security.apple.com/blog/imessage-contact-key-verification/
- Google Trillian — verifiable, append-only data structures (CT/KT foundation) — https://github.com/google/trillian · https://google.github.io/trillian/
- RFC 6962 — Certificate Transparency (Merkle log, inclusion/consistency proofs) — https://datatracker.ietf.org/doc/html/rfc6962
- RFC 9381 — Verifiable Random Functions — https://datatracker.ietf.org/doc/html/rfc9381
- RFC 4303 — the sliding-window anti-replay model Mycelium's `seq` window already follows — https://datatracker.ietf.org/doc/html/rfc4303

---

*End of PROPOSED Phase 3 spec. No code in this document ships until it passes the §11 two-peer
integration tests; every "add/change/new" is a proposal against v0.3.0, not a description of
current behaviour.*



