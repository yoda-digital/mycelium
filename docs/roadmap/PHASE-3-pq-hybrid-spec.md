# Phase 3 — Post-quantum hybrid key exchange

**Status: PROPOSED (not implemented). MUST NOT ship without human cryptographic
review.** Design doc from the v0.3.0 audit (SOTA axis).

## Problem

Every key agreement is classical X25519: live sessions via
`crypto_box_beforenm(theirEph, myEphPriv)` (`peer-channel.ts` `processPeerKeys` /
`encryptFor`), offline via `crypto_box_seal` to an identity-derived Curve25519 key
(`sealForIdentity`, `peer-channel.ts:516`). The only crypto dependency
(`libsodium-wrappers-sumo`) has no ML-KEM. A "harvest-now, decrypt-later" adversary who
records ciphertext in transit can decrypt it once a cryptographically relevant quantum
computer (CRQC) exists.

This is **insurance, not an acute exploit** for agent traffic: the harvestable corpus is
transient (the relay queue is RAM-only, ≤50 msgs / 512 KB, `RELAY_QUEUE_TTL_S` window,
gone on restart unless `RELAY_QUEUE_FILE` is set). The real exposure is any ciphertext an
attacker logs *in transit* — so prioritize the long-lived offline path.

## Standards

- **ML-KEM-768** — NIST FIPS 203 (module-lattice KEM, "Kyber").
- **Hybrid** (classical + PQ, so a break in either alone is not fatal) — the accepted
  transitional posture; cf. RFC 9370 (IKEv2 multiple key exchanges), the TLS hybrid
  drafts, and Signal **PQXDH**.
- **Library:** `@noble/post-quantum` (pure TypeScript, audited, no native addon) —
  preserves Mycelium's "three deps, no native, read it in an afternoon" ethos. libsodium
  stays for the classical half and all symmetric/auth primitives.

## Proposed design

1. **Suite negotiation.** Add a signed `suite` identifier to `challenge`/`auth`/`auth_ok`
   (and cover it in `canonical.ts` so it cannot be stripped). Peers advertise
   `{classical, hybrid}`; both pick the strongest mutually supported suite. A signed
   suite prevents a **downgrade attack** by the hostile relay.
2. **Live sessions (hybrid session key).** Alongside the X25519 ECDH, the initiator sends
   an ML-KEM-768 ciphertext encapsulated to the responder's ML-KEM public key (published
   with its ephemeral, signed by the Ed25519 identity). Session key =
   `HKDF(x25519_shared ‖ mlkem_shared ‖ transcript)`. If either half is compromised the
   key still holds.
3. **Offline envelopes (priority).** Replace bare `crypto_box_seal` with: X25519 seal
   **plus** an ML-KEM encapsulation to the recipient's published ML-KEM prekey; combine
   via HKDF. Compose with the prekey forward-secrecy spec
   ([`PHASE-3-prekey-offline-fs-spec.md`](./PHASE-3-prekey-offline-fs-spec.md)) so this
   DH *is* the PQXDH hybrid.
4. **Signatures stay classical (Ed25519) for now.** PQ signatures (ML-DSA) are
   non-urgent: forging a signature requires a *live* quantum computer at attack time, not
   later — there is no harvest-now risk. Revisit when ML-DSA is cheap and standardized in
   the toolchain.

## Wire / canonical impact

- New signed fields: `suite`, plus PQ public-key/ciphertext fields on the handshake and
  offline frames. All must be added to `canonical.ts` (presence-conditional, like the v2
  fields) so legacy peers still verify and new fields can't be stripped.
- Bundle-size cost: ML-KEM-768 public key ≈ 1184 B, ciphertext ≈ 1088 B — meaningful vs
  today's 32 B X25519 keys; measure frame sizes and the offline queue byte budget.

## Security-review checklist

- [ ] Downgrade resistance: `suite` is inside the signature and both sides enforce the
      negotiated suite (no silent fallback to classical).
- [ ] KDF domain separation and transcript binding (bind identities + suite into HKDF
      info).
- [ ] Constant-time / audited implementation (`@noble/post-quantum`), no bespoke crypto.
- [ ] ML-KEM key lifecycle (generation, publication, rotation) authenticated by Ed25519.
- [ ] Mixed-version rooms: classical-only peers still interoperate; hybrid peers upgrade
      only with each other.
- [ ] Frame-size / queue-budget impact reviewed.

## Test plan

Round-trip encrypt/decrypt under the hybrid suite; suite negotiation across
classical-only ↔ hybrid peers; a scripted **downgrade** attempt (relay strips/rewrites
`suite`) is rejected fail-closed; offline hybrid envelope survives a session-key rotation.
