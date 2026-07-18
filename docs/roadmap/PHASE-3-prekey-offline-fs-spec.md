# Phase 3 — Forward Secrecy for Offline Envelopes (Prekey Bundles)

**Status: PROPOSED. Nothing in this document is implemented.** No code below exists in
`peer-channel.ts`, `relay.ts`, or `canonical.ts` today; every "add", "new", "MUST", and code
block is a design proposal to be reviewed, not a description of shipped behaviour. Where this
document describes *current* behaviour it cites the exact file and line in v0.3.0.

**Package:** `@yoda.digital/mycelium` v0.3.0 → target v0.4.0 (wire proto **v3**) ·
**Date:** 2026-07-18 · **Author:** design spec · **Depends on:** nothing shipped;
**composes with** a future PQ-hybrid spec (§13, also PROPOSED and not yet written).

---

## 0. TL;DR

Today, when a peer is offline, `myc_send` seals the message to the recipient's **permanent
identity-derived Curve25519 key** with `crypto_box_seal` (`peer-channel.ts:516-523`, called from
`sendOffline` at `:666`). That key never rotates except by full identity rotation, so a future
compromise of one long-lived secret retroactively decrypts **every** offline ciphertext an
attacker has ever captured. Live sessions do not have this problem — they use per-connection
Curve25519 ephemerals (`peer-channel.ts:316`, `crypto_box_beforenm`) and get full PFS.

This spec closes that gap by giving each peer a **published prekey bundle** — a set of medium-term
Curve25519 keys, each signed by the peer's Ed25519 identity, that survive reconnects (so
store-and-forward still works) **without** being the permanent identity key (so old ciphertext
stops being decryptable once the prekey is destroyed). It is X3DH (Signal) adapted to Mycelium's
existing Ed25519-TOFU + relay-allow-list substrate:

- a peer publishes a **signed prekey** (`SPK`, rotated on a schedule) plus a replenishable pool of
  **one-time prekeys** (`OPK`, each used exactly once);
- a sender fetches the bundle, does an **ephemeral-to-prekey DH**, derives the sealing key from a
  KDF over that DH (plus identity-binding DHs), and consumes one `OPK`;
- if no `OPK` is available, the sender falls back to the `SPK` alone — an **explicit, logged
  forward-secrecy downgrade**, not a silent one;
- the DH slot is designed to be swapped for the **PQXDH hybrid** (§13) with no wire re-cut.

It also **corrects the record**: `README.md:62` frames seal-to-identity as a necessity ("has to
survive the recipient rotating its session keys, so it is sealed to their identity key"). That is
false, and §3 explains precisely why: surviving reconnects requires a key that outlives the
*session ephemeral*, not one that equals the *permanent identity*.

---

## 1. What the code does today (grounded)

### 1.1 The offline seal

`sendOffline` (`peer-channel.ts:656-679`) builds the offline envelope. Its only key input is the
recipient's TOFU-pinned **Ed25519 identity** public key, `pin.sign_pubkey`:

```ts
// peer-channel.ts:664-666 (current)
const pin = tofuGet(room, target)
if (!pin) return null
const sealed = sealForIdentity(pin.sign_pubkey, plaintext)
```

`sealForIdentity` converts that Ed25519 key to Curve25519 and anonymously seals to it
(`peer-channel.ts:516-523`, current):

```ts
function sealForIdentity(signPubKey64: string, plaintext: string): string | null {
  try {
    const curvePk = sodium.crypto_sign_ed25519_pk_to_curve25519(fromB64(signPubKey64))
    return toB64(sodium.crypto_box_seal(sodium.from_string(plaintext), curvePk))
  } catch { return null }
}
```

`crypto_box_seal` generates a throwaway ephemeral *on the sender side*, so the ciphertext is
anonymous and the sender cannot decrypt its own message. The recipient opens it with the
identity-derived Curve25519 secret (`openSealed`, `peer-channel.ts:525-531`):

```ts
sodium.crypto_box_seal_open(fromB64(enc64), idCurve.publicKey, idCurve.privateKey)
```

`idCurve` is derived **once at boot** directly from the long-term Ed25519 secret and only ever
changes on full identity rotation (`peer-channel.ts:2175-2178` boot, `:1555-1557` rotation):

```ts
// peer-channel.ts:2175-2178 (current)
idCurve = {
  publicKey:  sodium.crypto_sign_ed25519_pk_to_curve25519(ltKeys.signPublicKey),
  privateKey: sodium.crypto_sign_ed25519_sk_to_curve25519(ltKeys.signPrivateKey),
}
```

### 1.2 Why this is not FS

The sealing public key is a deterministic function of the permanent identity key. The matching
secret (`idCurve.privateKey`) lives for the whole life of the identity. An attacker who (a) records
offline ciphertexts off the hostile relay — which is the stated threat model, `README.md:43` — and
(b) later obtains `MYC_KEY_FILE` (or the passphrase + file) can decrypt **all** of them, including
messages sent months earlier. `README.md:55` and `:62` already concede this ("Offline envelopes are
the exception"). This spec removes the exception rather than documenting it.

### 1.3 What authenticity rests on (unchanged by this spec)

Offline sender authentication does **not** come from the seal (a sealed box is anonymous —
`wire-protocol-v2.md:118-122`). It comes from the **canonical Ed25519 envelope signature** verified
against the sender's TOFU pin (`processOfflineEnvelope`, `peer-channel.ts:1688`), plus the signed
`ts` freshness window (`:1692`) and `msg_id` dedup (`:1700`). **This spec keeps all of that
untouched.** We change *what key the payload is sealed to*, never *how the envelope is
authenticated*. The signature still covers the canonical frame; the new prekey selector fields go
**inside** the signed canonical set (§7) so the relay cannot tamper with prekey selection.

### 1.4 Where offline frames are carried

- Sender queues via the relay when the target is offline and the frame is not `no_queue`
  (`relay.ts:963-972`, `enqueue` at `:254`). Offline queue entries are ciphertext-only
  (`relay.ts:223-235`), optionally persisted (`RELAY_QUEUE_FILE`).
- The wire shape is fixed in `wire-protocol-v2.md:356-365` (offline envelope: `nonce:null`,
  `seq:null`, `session_id:null`, `offline:true`, sealed `encrypted`).

Everything in §1 is current v0.3.0 behaviour. Everything from §4 on is PROPOSED.

---

## 2. Goals and non-goals

**Goals**

1. Forward secrecy for offline envelopes: destroying a consumed one-time prekey renders that
   message's ciphertext undecryptable even if the identity key later leaks.
2. Store-and-forward still works while the recipient is offline (the medium-term keys survive
   reconnects, exactly as `idCurve` does today).
3. No weakening of the existing authenticity, replay, TOFU, or STS guarantees.
4. Graceful, **logged** degradation when one-time prekeys are exhausted.
5. A DH slot that a future PQXDH hybrid (§13) can occupy without another wire cut.
6. Backward compatibility: a v0.4 peer talking to a v0.3 peer, or vice versa, degrades to today's
   seal-to-identity behaviour, explicitly and logged — never a silent failure.

**Non-goals**

- Metadata privacy (who-talks-to-whom); still out of scope (`README.md:64`).
- A full Double Ratchet for offline mail. Offline delivery is single-shot store-and-forward; we
  want *forward* secrecy (past ciphertext safe after key loss), not the ratchet's per-message
  *future* secrecy / self-healing. Post-compromise security for the *live* channel is already
  provided by per-connection ephemerals + STS.
- Changing live-session crypto. Live PFS is already correct (`peer-channel.ts:316`).
- Hiding one-time-prekey *consumption* from the relay (the relay learns a bundle was fetched; that
  is the same metadata leak it already has).

---

## 3. Correcting the record: seal-to-identity is NOT "necessary"

`README.md:62` (current text):

> **Offline messages give up forward secrecy.** A queued message has to survive the recipient
> rotating its session keys, so it is sealed to their identity key instead.

The clause "**has to** … so it is sealed to their identity key" states a false necessity. The
requirement is real; the conclusion does not follow.

- **The real requirement** is that the sealing key must outlive the recipient's *per-connection
  session ephemeral* (`ephKeys`, regenerated every connect — `peer-channel.ts:2179`,
  `genEphKeys()`), because the recipient may reconnect (and thus rotate that ephemeral) between
  send and receive. A key tied to the live session cannot be used, because the recipient will have
  thrown it away by the time it reads its mail.
- **The false leap** is from "must outlive the session ephemeral" to "must equal the permanent
  identity key." Those are not the same key. There is an entire band of **medium-term** keys that
  outlive any single session but are still periodically destroyed:
  - a **signed prekey** rotated (say) daily/weekly, and
  - **one-time prekeys**, each destroyed the instant it is consumed.

  Both survive reconnects (they are persisted, like `idCurve` is) yet neither is the identity key,
  so destroying them gives forward secrecy that seal-to-identity structurally cannot. This is
  exactly the gap X3DH's signed prekey + one-time prekeys were designed to fill
  ([Signal X3DH §2.1, §4.7](https://signal.org/docs/specifications/x3dh/)).

So seal-to-identity is a **choice** (the simplest thing that survives reconnects, zero extra key
management, zero publication channel), not a necessity. It was a reasonable v0.3 tradeoff; it is
not forced. **Proposed README correction** (to land with the implementation, not before):

> **Offline messages historically gave up forward secrecy.** A queued message must survive the
> recipient rotating its *session* keys — but that only requires a key that outlives a session, not
> the permanent identity key. As of v0.4, offline mail is sealed to a signed prekey and a one-time
> prekey (X3DH-style); consuming the one-time prekey gives the offline message forward secrecy.
> When a peer's one-time prekeys are exhausted (or the peer is still on v0.3), delivery falls back
> to the signed prekey — or, for a v0.3 peer, to the identity key — and this downgrade is logged.

Until that ships, the current README wording should be softened from "has to … so it is sealed to
their identity key" to "we seal to the identity key" (a choice, not a necessity). **This spec does
not edit README.md** — the correction lands atomically with the code.

---

## 4. Background: X3DH and PQXDH (what we are adapting)

**X3DH** ([Signal, Marlinspike & Perrin](https://signal.org/docs/specifications/x3dh/)) lets Alice
establish a shared secret with an *offline* Bob using keys Bob published in advance. Bob publishes a
**prekey bundle**: identity key `IKB`, a **signed prekey** `SPKB` with signature
`Sig(IKB, Encode(SPKB))`, and a pool of **one-time prekeys** `(OPKB1, …)`. Alice generates an
ephemeral `EKA` and computes:

```
DH1 = DH(IKA, SPKB)      DH2 = DH(EKA, IKB)      DH3 = DH(EKA, SPKB)
DH4 = DH(EKA, OPKB)      # only when a one-time prekey is present
SK  = KDF(DH1 || DH2 || DH3 [|| DH4])
```

with `KDF(KM)` = HKDF over input key material `F || KM`, where `F` is 32 `0xFF` bytes for X25519
(domain separation from other uses of the curve), a zero salt, and an application `info` string
([X3DH §2.2](https://signal.org/docs/specifications/x3dh/)). The associated data is
`AD = Encode(IKA) || Encode(IKB)`.

Two X3DH security notes we must honour:

- **One-time prekey exhaustion**: "The server should provide one of Bob's one-time prekeys if one
  exists, and then delete it. If all … have been deleted, the bundle will not contain a one-time
  prekey." When none is used, "a compromise of the private keys for `IKB` and `SPKB` … would
  compromise the `SK`" — i.e. **no forward secrecy for that message**
  ([X3DH §4.7](https://signal.org/docs/specifications/x3dh/)). This is precisely the downgrade we
  make explicit and logged (§9).
- **Replay of the initial message**: "If Alice's initial message doesn't use a one-time prekey, it
  may be replayed to Bob and he will accept it," deriving the same `SK` each time
  ([X3DH §4.6](https://signal.org/docs/specifications/x3dh/)). Mycelium already defends replay at a
  different layer (signed `msg_id` dedup + `ts` window, `peer-channel.ts:1692-1704`), so a replayed
  SPK-only envelope is dropped by dedup regardless of key reuse — §11 details the interaction.

**PQXDH** ([Signal](https://signal.org/docs/specifications/pqxdh/)) is X3DH plus a post-quantum KEM
(ML-KEM / CRYSTALS-Kyber). Bob additionally publishes a signed **post-quantum last-resort prekey**
`PQSPKB` and signed one-time PQ prekeys `(PQOPKB1, …)`. Alice encapsulates against the chosen PQ
prekey, `(CT, SS) = PQKEM-Enc(PQPKB)`, sends `CT`, and mixes the KEM shared secret into the KDF:

```
SK = KDF(DH1 || DH2 || DH3 || DH4 || SS)
```

so an attacker must break **both** X25519 and ML-KEM to recover `SK`
([PQXDH §3](https://signal.org/docs/specifications/pqxdh/); analysis:
[Cryspen](https://cryspen.com/post/pqxdh/), [Fiedler et al., eprint 2024/702](https://eprint.iacr.org/2024/702)).
§13 shows how our KDF input string reserves the `SS` slot so the hybrid is a drop-in.

### 4.1 The Mycelium adaptation (and where it differs from Signal)

| X3DH concept | Mycelium mapping | Note |
|---|---|---|
| `IKB` identity key | existing Ed25519 identity, TOFU-pinned (`peer-channel.ts:192-196`) | already exists; **not** re-published |
| `DH(·, IKB)` (X25519 on the identity) | `crypto_sign_ed25519_pk_to_curve25519(IKB)` → X25519, i.e. today's `idCurve` (`peer-channel.ts:2175-2178`) | the identity→curve map Mycelium already uses |
| `SPKB` signed prekey | **new** medium-term X25519 key, signed by the Ed25519 identity (`crypto_sign_detached`) | §5 |
| `OPKB` one-time prekeys | **new** pool of single-use X25519 keys | §5 |
| Prekey server | the **relay allow-list / signed announce** (§6) | relay is hostile → prekeys are self-signed, verified client-side |
| `EKA` sender ephemeral | **new** per-message X25519 ephemeral, public key carried in the envelope | §7 |
| `Sig(IKB, Encode(SPKB))` | Ed25519 detached signature over a domain-separated encoding of the prekey (§6.3) | uses the identity we already have |

A deliberate simplification vs Signal: Signal's `SK` seeds a Double Ratchet. Ours seeds a **single**
NaCl `secretbox` (or `box_easy`) that encrypts exactly one offline payload, then the sender-side
ephemeral secret and the recipient-side consumed OPK secret are both wiped. One shot, forward-secret,
no ratchet state to persist for offline mail.

---

## 5. New key material and storage

All new keys are **X25519** (Curve25519 for DH), distinct from the Ed25519 identity. Generated with
`crypto_box_keypair()` (already imported; used for ephemerals at `genEphKeys`). None of these
replace `idCurve`; `idCurve` remains as the **v0.3 compatibility fallback** target (§10).

### 5.1 Signed prekey (`SPK`)

- One active `SPK` at a time, plus a short grace overlap of the immediately previous one (so mail
  sealed to the just-rotated prekey is still openable — mirrors the `prev` identity overlap at
  `peer-channel.ts:83`).
- Rotated on a schedule: `MYC_PREKEY_SPK_MAX_AGE_S` (**PROPOSED** env, default `604800` = 7 days).
- Each `SPK` carries `spk_id` (a monotonic small integer), the public key, a `created_at` ms epoch,
  and the identity signature over its canonical encoding (§6.3).

### 5.2 One-time prekeys (`OPK`)

- A pool of single-use X25519 keypairs, each with an `opk_id` (monotonic integer, never reused
  within an identity), the public key, and the identity signature.
- Pool target size `MYC_PREKEY_OPK_TARGET` (**PROPOSED**, default `64`), low-water mark
  `MYC_PREKEY_OPK_MIN` (**PROPOSED**, default `16`). Replenished on connect and after consumption
  drops below the low-water mark (§10).
- **A private OPK is deleted the instant it is consumed on decrypt** (§8.2). That deletion *is* the
  forward-secrecy event; it must be durable before the plaintext is delivered.

### 5.3 On-disk layout (`MYC_PREKEY_FILE`, PROPOSED)

A **new** file, `MYC_PREKEY_FILE` (default `~/.mycelium-prekeys.json`), separate from
`MYC_KEY_FILE` so prekey churn never rewrites the identity file. Same `mode 0o600` +
optional-passphrase treatment as the key file (`readKeyFile`/`writeKeyFile`,
`peer-channel.ts:99-135`) — reuse those helpers verbatim; **OPK/SPK secrets MUST be encrypted at
rest whenever `MYC_KEY_PASSPHRASE` is set**, same as the identity secret.

```jsonc
// ~/.mycelium-prekeys.json  (PROPOSED shape; encrypted-at-rest when passphrase set)
{
  "version": 1,
  "spk": {
    "id": 7,
    "public":  "<b64 X25519 pub>",
    "secret":  "<b64 X25519 sec>",       // encrypted-at-rest with passphrase
    "created_at": 1730000000000,
    "sig": "<b64 Ed25519 over SPK encoding §6.3>"
  },
  "spk_prev": { "id": 6, "public": "...", "secret": "...", "created_at": ..., "sig": "..." },
  "opk": {
    "42": { "public": "<b64>", "secret": "<b64>", "sig": "<b64>" },
    "43": { "public": "<b64>", "secret": "<b64>", "sig": "<b64>" }
    // consumed ids are removed, not kept — the secret must not survive consumption
  },
  "opk_next_id": 44,
  "consumed_opk_ids": [ 40, 41 ]   // tombstones: bounded ring, reuse-detection (§11.2)
}
```

Note `consumed_opk_ids` keeps only **ids**, never secrets — it exists to reject a relay that
re-serves a consumed OPK (§11.2), not to decrypt anything.

---

## 6. Publishing the bundle through a hostile relay

The relay is assumed hostile (`README.md:43`, `wire-protocol-v2.md:12`). It may **withhold**,
**reorder**, or **replay** prekeys, and it may try to serve a prekey it minted. It must **not** be
able to make a victim seal to a key the victim does not control, and it must **not** be able to
strip forward secrecy without that being detectable/logged. Two publication channels are considered;
we recommend **B (signed announce)** as primary with **A** as the durable store.

### 6.1 Option A — extend the relay allow-list store (durable, relay-served)

The relay already persistently binds `name → identity pubkey` per room in the allow-list
(`relay.ts:419-435`, `AllowList.bindings`). Extend the relay with a **prekey store** keyed by
`(room, name)` that holds the peer's latest signed `SPK` and its available `OPK` pool, populated by
a new authenticated `publish_prekeys` frame and consumed by a `fetch_prekeys` request that
**pops** one `OPK` (delete-on-serve, exactly as X3DH's server does —
[X3DH §3.3](https://signal.org/docs/specifications/x3dh/)).

- **Pro:** durable; a sender can fetch a bundle for a peer that is currently offline (the common
  case for offline mail — the target is by definition not connected).
- **Con:** new relay state + new relay endpoints; the relay chooses which OPK to serve and can
  refuse to pop (serving the same OPK twice, or always serving none to force the SPK-only
  downgrade). All of these are **detectable client-side** (§11) but the relay is an active
  participant.

### 6.2 Option B — signed announce, gossiped (relay is a dumb pipe)

Peers broadcast a signed **prekey announce** (`_prekey_announce`, a new reserved control type)
carrying the current `SPK` and a *batch* of `OPK` publics, over the existing roster/broadcast path
(the same channel `peer_joined` / key maps already use, `relay.ts:181-192`, `peerKeyMap`). Receivers
cache announces per `(room, name)`. A sender picks an unused `OPK` from its **local cache** of the
target's announce and marks it locally consumed.

- **Pro:** the relay stores nothing new and cannot pop/withhold individual OPKs.
- **Con:** OPK **double-spend across senders** — two different senders, each holding the same cached
  announce, may pick the same `OPK` (there is no central pop). That reopens the FS gap for whichever
  message is decrypted second (the recipient can only consume-and-delete an OPK once; §11.2). Also,
  a sender that has never seen a fresh announce (target long offline) has a stale/empty cache.

### 6.3 Prekey signing (both options)

Every prekey is signed by the Ed25519 **identity** key the peer already holds, so a hostile relay
cannot substitute one. Domain-separated encoding (a new constant, mirrors STS domain separation at
`peer-channel.ts:398-408`):

```ts
// PROPOSED — canonical prekey signing input (buildable; sodium already imported)
const PREKEY_CTX_SPK = sodium.from_string('mycelium-prekey-spk-v1\0')
const PREKEY_CTX_OPK = sodium.from_string('mycelium-prekey-opk-v1\0')

// enc(kind, id, pub, room) = CTX(kind) || u32le(id) || raw X25519 pub (32) || utf8(room)
function prekeySignInput(ctx: Uint8Array, id: number, pub: Uint8Array, room: string): Uint8Array {
  const idb = new Uint8Array(4); new DataView(idb.buffer).setUint32(0, id, true)
  return new Uint8Array([...ctx, ...idb, ...pub, ...sodium.from_string(room)])
}
const spkSig = toB64(sodium.crypto_sign_detached(
  prekeySignInput(PREKEY_CTX_SPK, spkId, spkPub, room), ltKeys.signPrivateKey))
```

Binding `room` into the signature stops cross-room reuse of a prekey (matches how `room` is bound
into STS and the challenge, `peer-channel.ts:407`, `relay.ts:765`). Binding `id` stops a relay from
re-labelling which prekey is "current." A receiver **MUST** verify this signature against its
**TOFU-pinned** identity key for `(room, name)` before ever sealing to the prekey — a prekey whose
signature does not verify against the pin is dropped, and the sender falls back one level (§9).

### 6.4 Recommendation

Ship **A (relay-served, delete-on-serve)** as the source of truth — it is the only channel that
serves prekeys for a target that is *currently offline*, which is the whole point of offline mail —
and treat any **B** announce a sender happens to have as an *optimisation cache* that must still be
signature-verified. Accept that a hostile relay can force the SPK-only downgrade by refusing to pop
OPKs; make that downgrade **loud** (§9) so it is observable rather than silent. This is the same
posture Signal takes: the server is trusted to *serve* prekeys but not to *forge* them, and OPK
exhaustion degrades FS visibly ([X3DH §4.7](https://signal.org/docs/specifications/x3dh/)).

---

## 7. Wire and canonical changes (exact)

### 7.1 New envelope fields (offline frames only)

`sendOffline` (`peer-channel.ts:656-679`) gains prekey-selector fields. All go **inside** the signed
canonical set so the relay cannot tamper with prekey selection or strip the FS upgrade:

| Field | Type | On | Meaning |
|---|---|---|---|
| `pk_eph` | b64 X25519 pub | offline FS frames | the sender's per-message ephemeral `EKA` public key |
| `pk_spk_id` | int | offline FS frames | which recipient `SPK` this envelope used |
| `pk_opk_id` | int \| null | offline FS frames | which recipient `OPK` was consumed; `null` = SPK-only (FS downgrade) |
| `pk_mode` | int | offline FS frames | key-agreement mode: `0` = v0.3 seal-to-identity (fields absent), `1` = X3DH (this spec), `2` = PQXDH hybrid (§13) |

A v0.3 seal-to-identity envelope carries **none** of these (`pk_mode` absent ≡ mode 0), so it
canonicalizes exactly as it does today — the presence-conditional discipline already used for
`offline`/`proto`/`room`/`ts` (`canonical.ts:28-37`, `wire-protocol-v2.md:84-91`).

### 7.2 `canonical.ts` change (PROPOSED diff)

The four fields are added **presence-conditionally**, keeping keys SORTED (the comment at
`canonical.ts:16-17` is the invariant). New keys slot in alphabetically: `pk_eph`, `pk_mode`,
`pk_opk_id`, `pk_spk_id` all sort after `payload`/`offline` and before `proto`:

```ts
// canonical.ts — PROPOSED additions (presence-conditional, strip/add-safe)
if (msg.offline !== undefined) o.offline = msg.offline
o.payload = msg.payload ?? null
if (msg.pk_eph    !== undefined) o.pk_eph    = msg.pk_eph      // NEW
if (msg.pk_mode   !== undefined) o.pk_mode   = msg.pk_mode     // NEW
if (msg.pk_opk_id !== undefined) o.pk_opk_id = msg.pk_opk_id   // NEW
if (msg.pk_spk_id !== undefined) o.pk_spk_id = msg.pk_spk_id   // NEW
if (msg.proto !== undefined) o.proto = msg.proto
// ... unchanged ...
```

Because inclusion is presence-conditional, this is **strip/add-safe** exactly as documented at
`canonical.ts:7-13`: a relay that strips `pk_opk_id` (to force an SPK-only decrypt) or flips
`pk_spk_id` changes the signed byte string, so the Ed25519 signature fails and the frame is
hard-blocked (`peer-channel.ts:1688-1691`). The relay cannot *downgrade* FS by field-stripping; it
can only *withhold prekeys upstream* (§6.1), which surfaces as a logged SPK-only send on the
*sender* side.

Update the keys-stay-SORTED comment (`canonical.ts:16-17`) and the exact-order table in
`wire-protocol-v2.md:62-99` to include the four new rows. Both are normative-adjacent and must not
drift (that is the whole reason `canonical.ts` is the single source, `canonical.ts:2-6`).

### 7.3 `PROTO` bump

Bump `PROTO` (`canonical.ts:43`) `2 → 3`. A mode-1/mode-2 offline frame is only sent to a peer known
to advertise `proto ≥ 3` (learned from its bundle publication / announce, §10.4). To a `proto 2`
peer, the sender emits a **mode-0** (today's) envelope and logs the downgrade. This keeps the
"a v2-signed frame will not verify against a v3 canonicalization" property that already guards
version skew (`wire-protocol-v2.md:527-530`) — the new fields simply do not appear on mode-0 frames,
so cross-version verification of legacy frames is unchanged.

### 7.4 New reserved control types

Add to the reserved `_`-prefixed set (router at `peer-channel.ts:1718`, table
`wire-protocol-v2.md:291-306`):

- `_prekey_announce` (peer → peers, signed): current `SPK` + batch of `OPK` publics (Option B / §6.2).
- `_prekey_request` / `_prekey_bundle` (peer ↔ relay): fetch/serve, if Option A relay endpoints are
  modelled as frames rather than the admin HTTP surface.

These remain unsendable by a local caller (the `_`-prefix guard at `peer-channel.ts:1718-1721` and
`wire-protocol-v2.md:277-279` already blocks a prompt-injected model from minting them).

---

## 8. Key agreement (buildable code)

### 8.0 A note on primitives (verified against the installed libsodium)

`libsodium-wrappers-sumo@^0.8.2` (`package.json:64`) exposes, and I verified at spec time:

- `crypto_scalarmult(sk, pk)` — raw X25519 DH, 32-byte output, agrees in both directions. **Use
  this for the DHs**, not `crypto_box_beforenm` — `beforenm` applies HSalsa20 to the point, which is
  fine for a single shared key but obscures the "concatenate raw DH outputs" structure X3DH needs.
- `crypto_auth_hmacsha256(msg, key)` / `crypto_auth_hmacsha512(msg, key)` — present.
- **`crypto_kdf_hkdf_sha256_extract` / `_expand` are NOT exposed** in 0.8.2 (only the length
  constants are). So HKDF **must be built from `crypto_auth_hmacsha256`** — do not call a non-existent
  `hkdf_*` function. The helper below is a faithful, buildable RFC 5869 HKDF-SHA-256.
- `crypto_sign_ed25519_pk_to_curve25519` / `_sk_to_curve25519` — present (already used,
  `peer-channel.ts:518`, `:2176`).

### 8.1 HKDF and the shared-secret KDF (buildable)

```ts
// PROPOSED — RFC 5869 HKDF-SHA-256 built from crypto_auth_hmacsha256 (the extract/expand
// wrappers are absent in libsodium-wrappers-sumo 0.8.2; HMAC-SHA-256 is present).
function hmac256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return sodium.crypto_auth_hmacsha256(data, key)   // 32-byte tag, key is the HMAC key
}
function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hmac256(salt, ikm)                          // PRK = HMAC(salt, IKM)
}
function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length)
  let t = new Uint8Array(0)
  let pos = 0, counter = 1
  while (pos < length) {
    const input = new Uint8Array(t.length + info.length + 1)
    input.set(t, 0); input.set(info, t.length); input[input.length - 1] = counter++
    t = hmac256(prk, input)
    const n = Math.min(t.length, length - pos)
    out.set(t.subarray(0, n), pos); pos += n
  }
  return out
}

// X3DH-style KDF: F || KM, zero salt, app info. F = 32×0xFF (X25519 domain separation,
// X3DH §2.2). KM is the ordered concatenation of the DH outputs (+ PQ SS in §13).
const F32 = new Uint8Array(32).fill(0xff)
const KDF_INFO = sodium.from_string('mycelium-offline-x3dh-v1')
function deriveOfflineKey(km: Uint8Array): Uint8Array {
  const ikm = new Uint8Array(F32.length + km.length)
  ikm.set(F32, 0); ikm.set(km, F32.length)
  const prk = hkdfExtract(new Uint8Array(32) /* zero salt */, ikm)
  return hkdfExpand(prk, KDF_INFO, sodium.crypto_secretbox_KEYBYTES)  // 32-byte secretbox key
}
```

### 8.2 The DH set

Let `IK` = the two peers' Ed25519 identities mapped to X25519 via
`crypto_sign_ed25519_{pk,sk}_to_curve25519` (i.e. the existing `idCurve` map, `peer-channel.ts:2176`).
Let `EK` = the sender's fresh per-message X25519 ephemeral. Then, mirroring X3DH §3.3 with our
identity-as-curve mapping:

```
DH1 = crypto_scalarmult( IK_sender_sec,  SPK_recipient_pub )
DH2 = crypto_scalarmult( EK_sender_sec,   IK_recipient_pub  )
DH3 = crypto_scalarmult( EK_sender_sec,   SPK_recipient_pub )
DH4 = crypto_scalarmult( EK_sender_sec,   OPK_recipient_pub )   // omitted when SPK-only
KM  = DH1 || DH2 || DH3 [|| DH4]
```

- `DH1` binds the **sender identity** (authenticates the sender to the KDF, complementing the
  envelope signature).
- `DH2` binds the **recipient identity** (only the real recipient's identity secret participates).
- `DH3` is the core FS DH against the medium-term `SPK`.
- `DH4` against a single-use `OPK` is what makes the message **forward-secret after the OPK is
  destroyed**. Its absence (`pk_opk_id: null`) is the FS-downgrade case (§9).

### 8.3 Sender: seal (PROPOSED, replaces the mode-1 path of `sealForIdentity`)

```ts
// PROPOSED — mode-1 offline sealing. Returns the ciphertext + selector fields for the envelope.
// bundle = the (signature-verified) recipient prekey bundle for (room, target).
function sealOfflineX3DH(room: string, targetSignPub64: string, bundle: VerifiedBundle, plaintext: string):
    { encrypted: string; pk_eph: string; pk_spk_id: number; pk_opk_id: number | null } | null {
  const ikRecipCurve = sodium.crypto_sign_ed25519_pk_to_curve25519(fromB64(targetSignPub64)) // IK_recip_pub
  const ikSenderCurve = idCurve.privateKey                                                    // IK_sender_sec
  const ek = sodium.crypto_box_keypair()                                                      // EK
  const spkPub = fromB64(bundle.spk.public)
  const opk = bundle.pickUnusedOpk()   // null when exhausted → SPK-only downgrade (§9)

  const dh1 = sodium.crypto_scalarmult(ikSenderCurve, spkPub)
  const dh2 = sodium.crypto_scalarmult(ek.privateKey, ikRecipCurve)
  const dh3 = sodium.crypto_scalarmult(ek.privateKey, spkPub)
  const parts = [dh1, dh2, dh3]
  if (opk) parts.push(sodium.crypto_scalarmult(ek.privateKey, fromB64(opk.public)))
  const km = concatBytes(parts)
  const key = deriveOfflineKey(km)
  // wipe DH material + ephemeral secret as soon as the key is derived
  for (const p of parts) sodium.memzero(p)
  sodium.memzero(km)

  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
  const ct = sodium.crypto_secretbox_easy(sodium.from_string(plaintext), nonce, key)
  sodium.memzero(key); sodium.memzero(ek.privateKey)
  // nonce is prepended to ciphertext so the offline envelope's own `nonce` field stays null (§7)
  const encrypted = toB64(concatBytes([nonce, ct]))
  return { encrypted, pk_eph: toB64(ek.publicKey), pk_spk_id: bundle.spk.id, pk_opk_id: opk?.id ?? null }
}
```

`AD` binding: X3DH's `AD = Encode(IKA) || Encode(IKB)` is already provided in Mycelium by the
**canonical envelope signature**, which covers `sender` and `target` (`canonical.ts:33`, `:36`) and
is verified against the TOFU pin. We therefore do **not** fold `AD` into the secretbox; the Ed25519
signature over the canonical frame *is* the associated-data check, and it is strictly stronger (it
also covers `msg_id`, `ts`, `room`, and the `pk_*` selectors). This is called out for review in §14.

### 8.4 Receiver: open (PROPOSED, mode-1 branch of `openSealed`)

```ts
// PROPOSED — runs inside processOfflineEnvelope AFTER the envelope signature is verified against
// the TOFU pin (peer-channel.ts:1688) and AFTER the ts window + msg_id dedup checks (:1692,:1700).
function openOfflineX3DH(room: string, senderSignPub64: string, msg: any): string | null {
  const spk = prekeyStore.spkById(msg.pk_spk_id)          // current or prev (grace overlap §5.1)
  if (!spk) { log(`🔴 offline: unknown SPK id ${msg.pk_spk_id} from ${msg.sender}`); return null }
  let opkSec: Uint8Array | null = null
  if (msg.pk_opk_id != null) {
    const opk = prekeyStore.takeOpk(msg.pk_opk_id)        // POP: returns & DELETES (durable) — §8.2
    if (!opk) { log(`🔴 offline: OPK ${msg.pk_opk_id} already consumed/unknown from ${msg.sender}`); return null }
    opkSec = fromB64(opk.secret)
  }
  const ikSenderCurve = sodium.crypto_sign_ed25519_pk_to_curve25519(fromB64(senderSignPub64)) // IK_sender_pub
  const ek = fromB64(msg.pk_eph)                          // EK_sender_pub
  const spkSec = fromB64(spk.secret)

  const dh1 = sodium.crypto_scalarmult(spkSec, ikSenderCurve)  // == sender's DH1 (symmetry)
  const dh2 = sodium.crypto_scalarmult(idCurve.privateKey, ek) // == sender's DH2
  const dh3 = sodium.crypto_scalarmult(spkSec, ek)             // == sender's DH3
  const parts = [dh1, dh2, dh3]
  if (opkSec) parts.push(sodium.crypto_scalarmult(opkSec, ek)) // == sender's DH4
  const key = deriveOfflineKey(concatBytes(parts))
  for (const p of parts) sodium.memzero(p)
  if (opkSec) sodium.memzero(opkSec)

  const raw = fromB64(msg.encrypted)
  const nonce = raw.subarray(0, sodium.crypto_secretbox_NONCEBYTES)
  const ct = raw.subarray(sodium.crypto_secretbox_NONCEBYTES)
  let pt: Uint8Array
  try { pt = sodium.crypto_secretbox_open_easy(ct, nonce, key) }
  catch { sodium.memzero(key); return null }               // MAC fail → nack path (§8.5)
  sodium.memzero(key)
  return sodium.to_string(pt)
}
```

**Symmetry check (must hold):** `DH(IK_send_sec, SPK_pub) == DH(SPK_sec, IK_send_pub)` and likewise
for `EK`/`OPK`, because X25519 is a symmetric DH — verified experimentally at spec time
(`crypto_scalarmult` agrees both directions). The sender computes with its secret against the
recipient's publics; the recipient computes with its secrets against the sender's publics; the
concatenated `KM` — and thus the derived key — is identical.

### 8.5 The consume-vs-decrypt ordering hazard (critical)

The receiver **pops (deletes) the OPK before it knows the ciphertext decrypts**. That is unavoidable
for FS (the OPK secret must be destroyed to gain FS), but it collides with Mycelium's
**commit-after-decrypt** invariant (`peer-channel.ts:759-763`, `wire-protocol-v2.md:381-386`): a
frame that fails to decrypt must **not** burn state, so the sender's idempotent same-`msg_id`
retransmit can still be read. If we delete the OPK and *then* the secretbox MAC fails (corruption,
or a relay-mangled `encrypted`), the OPK is gone and the honest retransmission — which reused the
same `pk_opk_id` — can never be opened. That would resurrect exactly the v0.2.x nack-can-never-
recover bug the current design fixed.

**Resolution (PROPOSED):** decouple OPK *reservation* from OPK *destruction*.

1. `takeOpk` moves the OPK to a short-lived **`opk_pending`** holding area keyed by
   `(sender, msg_id, opk_id)` instead of deleting it, then attempts decrypt.
2. On decrypt **success** → deliver, `commitReplay` (`:1711`), and only now **destroy** the pending
   OPK secret (durable delete). FS achieved; msg_id committed; retransmits dedup-drop.
3. On decrypt **failure** → `memzero` the derived key, **restore** the OPK from `opk_pending`, send
   `_nack` (`:1708`), do **not** commit. The retransmission with the same `msg_id`+`pk_opk_id`
   re-pops the restored OPK and succeeds. Commit-after-decrypt preserved.
4. `opk_pending` entries expire with the offline freshness window (`OFFLINE_MAX_AGE_MS`,
   `peer-channel.ts:47`); an expired pending OPK is destroyed (a never-arriving retransmission must
   not pin an OPK forever). This bounds the FS-exposure of a *pending* OPK to one freshness window,
   matching the existing `SEEN_EXPIRY_MS` reasoning (`peer-channel.ts:685-688`).

This is the single most important correctness point in the spec and is called out again in §12 (test
`t-opk-nack-recovers`) and §14 (checklist item C-7).

---

## 9. The fallback ladder (every downgrade explicit and logged)

Sealing degrades down a strict ladder. **Every step down from the top is logged** at the sender and
surfaced in the `myc_send` result string (mirroring the existing "no PFS" suffix,
`peer-channel.ts:1512`), so a downgrade is never silent.

| Rung | Condition | Result | FS? | Log |
|---|---|---|---|---|
| **1. X3DH + OPK** (mode 1) | recipient bundle verified, an unused OPK available | `DH1..DH4` | **Yes** — dies with the OPK | (normal, info) |
| **2. X3DH SPK-only** (mode 1, `pk_opk_id:null`) | bundle verified, OPKs exhausted | `DH1..DH3` | **Weak** — SPK compromise reopens it (X3DH §4.7) | `⚠️ FS-downgrade: <peer> OPKs exhausted, sealing to SPK only` |
| **3. Seal-to-identity** (mode 0) | peer is `proto ≤ 2`, or no verified bundle exists | today's `crypto_box_seal` to `idCurve` (`peer-channel.ts:516`) | **No** — identity compromise reopens it | `⚠️ FS-downgrade: <peer> no prekey bundle (proto <3?), sealing to identity key` |
| **4. Local queue** | relay unreachable | held in local outbox (`peer-channel.ts` outbox) | n/a | existing "queued locally" (`:1338`) |

Rung 3 is exactly today's behaviour, preserved as the compatibility floor. The ladder never *fails
closed* on a missing bundle (that would break delivery to v0.3 peers), but it **fails loud**: the
operator/model can see FS was not achieved and can choose to rotate identity (`myc_rotate_key`) or
demand the peer upgrade. A future strict mode (`MYC_REQUIRE_OFFLINE_FS=1`, PROPOSED) could refuse
rungs 2–3 for deployments that treat FS as mandatory.

`AD`/replay note: because rung-2 (SPK-only) messages are replayable at the X3DH layer
([X3DH §4.6](https://signal.org/docs/specifications/x3dh/)), they lean entirely on Mycelium's
existing `msg_id` dedup + `ts` window (§11.1). Rung-1 messages are additionally non-replayable at the
key layer (a consumed OPK cannot produce the same `SK` twice — the second attempt finds no OPK).

---

## 10. Replenishment, exhaustion, and version negotiation

### 10.1 Generation and publication cadence

- On first boot (or on identity rotation), generate the initial `SPK` + `MYC_PREKEY_OPK_TARGET`
  OPKs, persist to `MYC_PREKEY_FILE`, and publish the bundle on the next authenticated connect
  (piggy-backed on `auth`, or as a `publish_prekeys`/`_prekey_announce` immediately after
  `auth_ok`).
- Rotate `SPK` when `now - spk.created_at > MYC_PREKEY_SPK_MAX_AGE_S`; keep `spk_prev` for one grace
  window so in-flight mail to the old SPK still opens (§5.1). Destroy `spk_prev.secret` after the
  grace window — that is the SPK-level FS event.

### 10.2 Replenishment triggers (sender-serving side is the *recipient* here)

The *recipient* replenishes its own OPK pool so senders can keep using rung 1:

- On connect, if `available_opk_count < MYC_PREKEY_OPK_MIN`, mint up to `TARGET` fresh OPKs,
  persist, and publish/announce the additions.
- After a decrypt consumes an OPK (§8.5 step 2), if the pool drops below `MIN`, schedule a top-up on
  the next connect (offline peers cannot publish; they replenish when they next come online — this
  is the natural exhaustion window).

### 10.3 Exhaustion handling

When the relay/announce yields **no unused OPK** for the target, the sender takes **rung 2**
(SPK-only) and logs it. This is the designed, standards-aligned degradation
([X3DH §4.7](https://signal.org/docs/specifications/x3dh/)) — the "last-resort" role that PQXDH
formalises with a last-resort prekey ([PQXDH §2.2](https://signal.org/docs/specifications/pqxdh/)).
The SPK is effectively Mycelium's last-resort prekey: always present, reused across senders,
FS-weak but identity-independent.

**Exhaustion is a denial-of-FS lever for a hostile relay** (Option A: refuse to pop; Option B:
withhold announces). It cannot force rung 3 or plaintext — only rung 2 — and it is logged every
time, so sustained downgrades are observable. See §11.3.

### 10.4 Version negotiation

- `proto ≥ 3` in a peer's `auth`/`auth_ok`/announce signals prekey support. The sender records this
  per `(room, name)` alongside the TOFU pin.
- To a `proto 3` peer **with** a verified bundle → rung 1/2. To a `proto ≤ 2` peer, or a `proto 3`
  peer whose bundle is missing/unverifiable → **rung 3** (mode-0), logged.
- A `proto 3` **receiver** must still accept mode-0 envelopes (from a `proto 2` sender, or a
  `proto 3` sender that fell back), routing them through today's `openSealed` (`peer-channel.ts:525`).
  Mode dispatch keys on `pk_mode` (absent ⇒ 0).

---

## 11. Replay and reuse defense

### 11.1 Message replay (unchanged, still load-bearing)

X3DH warns that an SPK-only initial message is replayable ([X3DH §4.6]). Mycelium already defends
replay **above** the key layer and that defense is unchanged:

- **`msg_id` dedup**, scoped `(room, sender, msg_id)`, persisted with a WAL, retained for
  `OFFLINE_MAX_AGE_MS + 5min` so it *outlives* the freshness window (`peer-channel.ts:685-688`,
  `:736-743`, `wire-protocol-v2.md:413-418`). A replayed offline envelope is dropped as a duplicate
  and re-acked, never re-delivered (`:1700-1704`).
- **Signed `ts` window**: `|now - ts| ≤ OFFLINE_MAX_AGE_MS` (`:1692`). A replay outside the window is
  rejected as stale.

So even a rung-2 (replayable-`SK`) message cannot be *delivered* twice. Reuse of the *key* is not a
delivery problem here; it is only an FS problem, which is what rung 1 fixes.

### 11.2 One-time prekey reuse (the new defense)

The FS guarantee of rung 1 depends on an OPK being used **exactly once**. Two abuse vectors:

- **Relay re-serves a consumed OPK** (Option A) or a stale announce is replayed (Option B) so two
  senders seal to the same OPK. Defense: the **recipient** is the single authority on consumption.
  `takeOpk` (§8.5) deletes on first successful decrypt; a second envelope naming the same
  `pk_opk_id` finds it gone → `openOfflineX3DH` returns null → logged
  (`🔴 offline: OPK <id> already consumed`). The `consumed_opk_ids` tombstone ring (§5.3)
  distinguishes "already consumed" (drop, do not nack — nacking would trigger a pointless retransmit
  of an un-openable frame) from "never existed" (also drop). **Second-message decryptability is
  intentionally sacrificed to preserve the single-use invariant** — the sender of the second message
  gets a terminal `delivery_failed` after `RETRY_MAX` (`wire-protocol-v2.md:507`), which is the
  honest outcome.
- **Sender double-spends an OPK across two of its own messages** (Option B cache). Same recipient
  defense catches it: only the first to be *decrypted* wins; the recipient never opens the same OPK
  twice.

The tombstone ring is bounded (e.g. last 4096 ids); older tombstones age out. Because OPK ids are
monotonic (`opk_next_id`, §5.3) and never reused within an identity, an aged-out tombstone can never
collide with a live id, so bounding the ring does not reopen reuse.

### 11.3 Hostile-relay downgrade, made observable

A relay can withhold OPKs to force rung 2 (§10.3) but **cannot**:

- force rung 3 or plaintext (the sender only drops to rung 3 when `proto ≤ 2` or the *signed* bundle
  fails to verify — a relay-forged bundle fails the identity-signature check, §6.3);
- strip the `pk_*` selectors to trick the receiver into an SPK-only open of an OPK message (the
  selectors are inside the canonical signature, §7.2 — tampering hard-blocks);
- learn any plaintext (the KDF output never leaves memory; the relay sees only ciphertext, as today
  `relay.ts:223-235`).

Every forced downgrade is logged at the sender (§9). A monitor can alert on a sustained
`FS-downgrade: … OPKs exhausted` rate for a peer that should be replenishing — a signal that the
relay is dropping the peer's announces/pops.

### 11.4 Small-subgroup / invalid-key hardening

`crypto_scalarmult` on X25519 clamps the scalar and (in libsodium) **rejects all-zero output**,
returning an error for low-order input points — libsodium's `crypto_scalarmult` returns `-1` (throws
in the wrapper) when the result is all-zero. The implementation **MUST** treat any `crypto_scalarmult`
throw as a hard failure of that seal/open (fall back one rung on send; drop + do-not-commit on
receive), never proceed with a zeroed DH. This blocks a relay/peer that publishes a low-order prekey
public to try to force a predictable `SK`. (Signed prekeys make a *forged* low-order key impossible;
this guards a *buggy or malicious peer* signing its own bad key.) See checklist C-4.

<!-- CURSOR -->
