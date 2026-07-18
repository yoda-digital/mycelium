# Changelog

All notable changes to `@yoda.digital/mycelium` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Post-v0.3.0 audit follow-through. A state-of-the-art / mass-adoption audit
ranked the highest-leverage gaps; this batch implements the safe, test-gated
ones (portability, durability, least-privilege, verification UX) and lands
reviewed design specs for the multi-month crypto/transport work under
[`docs/roadmap/`](./docs/roadmap/). Test count: 176 → 195 (five suites,
including a crash-recovery suite and a Node↔Bun interop suite).

### Added

- **`myc_verify` tool** — read-only display of the pinned Ed25519 fingerprint for
  any peer, or this peer's own identity. The documented out-of-band verification
  ceremony was only reachable for a *blocked* peer via `myc_trust`; it is now
  executable for a healthy peer, so the first-contact TOFU window can be closed
  proactively.
- **Node / `npx` support** — the peer bin is now built `--target node` with a
  `#!/usr/bin/env node` shebang and runs under both Node and Bun. A host without
  Bun can install the peer with `npx -y @yoda.digital/mycelium mycelium-peer`.
  New `node >= 22` engine. The relay remains Bun-only (it uses `Bun.serve`).
- **Crash-durable offline queue** (opt-in `RELAY_QUEUE_FILE`) — persists the
  offline queue (ciphertext only, atomic write) and restores it on boot, so a
  relay restart no longer drops mail whose sender may itself be gone.
- **`demo.ts` / `bun run demo`** — zero-config proof of zero-plaintext-at-relay,
  side-by-side ciphertext-on-wire vs decrypted plaintext.
- **`docs/wire-protocol-v2.md`**, **`llms.txt`**, **`server.json`** (MCP registry
  manifest), and reviewed roadmap specs in `docs/roadmap/`.
- New test suites: `test-durability.ts` (sender-death + relay-restart recovery)
  and `test-node-smoke.ts` (a Node peer interoperating with a Bun peer).

### Changed

- **`RELAY_QUEUE_TTL_S` default 300 → 3600s**, matching the peer's default offline
  window (`MYC_OFFLINE_MAX_AGE_S`). The old default silently dropped offline mail
  ~5 min in, while the sender was not told "failed" until ~65 min later.

### Security

- **BREAKING — admin/health split off the invite token.** `/admin/*` and
  `/health` are now gated by `RELAY_ADMIN_TOKEN` / `RELAY_HEALTH_TOKEN`
  respectively; when unset they are loopback-only. The long-lived invite
  `RELAY_TOKEN` is **no longer** an admin credential, so an invited peer can no
  longer read the name↔key social graph or revoke other peers. Existing
  deployments that drove `/admin/*` with `RELAY_TOKEN` must set
  `RELAY_ADMIN_TOKEN` (or call from loopback).

### Docs

- Corrected overstated claims: "full PFS" → "per-connection PFS"; offline
  seal-to-identity framed as a current design choice with a prekey upgrade path,
  not a necessity; rotation "nothing breaks" qualified to peers online or
  returning within the offline window. Documented the `npx` path and that
  `--dangerously-load-development-channels` is optional (`myc_recv` works on any
  MCP host).

## [0.3.0] - 2026-07-18

Completeness release (wire protocol v2). A full audit of v0.2.1 against the
project's own philosophy found one architectural hole (offline delivery was
impossible by construction), several designed-but-never-shipped features, and a
threat-model overstatement. This release closes all of them. Mixed-version
rooms: 0.3.0 peers verify 0.2.x frames, but 0.2.x peers cannot verify 0.3.0
frames (new signed fields) — upgrade all peers together.

### Fixed

- **ARCHITECTURAL — offline delivery actually works now.** v0.2.x relay-queued
  session frames were encrypted to ephemeral keys that rotate on reconnect, so
  100% of queued frames arrived undecryptable — the queue could only ever
  produce nack/resend theater. Messages to an offline (TOFU-known) peer are now
  sealed to the recipient's **identity-derived Curve25519 key**
  (`crypto_box_seal`), which survives reconnects. Tradeoff, documented: offline
  envelopes have **no PFS** (live-session traffic keeps it). Authenticity comes
  from the canonical Ed25519 envelope signature verified against the pinned
  sender key; replay is bounded by a **signed `ts` freshness window**
  (`MYC_OFFLINE_MAX_AGE_S`, default 1h) plus persisted msg_id dedup whose
  retention outlives the window. Session frames are marked `no_queue` so the
  relay fails them fast instead of queueing guaranteed decrypt failures; the
  sender then re-sends as an envelope automatically. First contact still
  requires both peers online (TOFU needs a pin to seal to).
- **Threat-model overstatement — name binding is now persistent.** The README
  claimed "different key claiming same name = rejected", but the relay only
  checked the LIVE room map: an offline peer's name could be squatted by anyone
  allow-listed. The allow-list (v2 format, auto-migrated) now stores a
  persistent name↔key binding per room, enforced in both directions
  (name→key and key→name), online or offline.
- **Detection without recovery — retransmission is automatic and idempotent.**
  v0.2.x told the *model* to resend (the least reliable component in the
  system). Every tracked send now lives in an outbox; nacks, relay-reported
  drops, ack timeouts, peer reappearance, and relay reconnects all trigger
  automatic retransmission **with the same msg_id** (receivers dedup and
  re-ack verified duplicates, so lost acks can't cause double delivery).
  Decrypt-failure msg_ids are no longer committed pre-decryption, so a
  same-id retransmission is accepted instead of dedup-dropped — the v0.2.x
  nack loop could never actually recover because of exactly this. The model
  hears about a send again only on confirmed delivery of a deferred message or
  terminal failure (after `RETRY_MAX` attempts). Sends while the relay is down
  queue locally and flush on reconnect.

### Added

- **`myc_recv` — host-independent inbox.** Every delivery (and system event) is
  buffered in a 500-entry inbox that `myc_recv` drains, so Mycelium works on
  MCP hosts that do not surface the experimental `notifications/claude/channel`
  capability. Previously such hosts could send but never read.
- **Broadcast is first-class:** each copy is ack-tracked and auto-retransmitted
  like a unicast; `include_offline: true` also reaches TOFU-known offline peers
  via identity envelopes (same-identity peers deduplicated across rooms).
- **Key rotation (`myc_rotate_key`).** Generates a new Ed25519 identity and
  announces `sign(newPub || name || ts, oldKey)` to every known peer — live
  sessions now, offline envelopes for the absent — who verify it against their
  *currently pinned* key and update pins with no TOFU violation. The relay
  migrates the name binding from the same continuity statement presented at
  re-auth (challenge-signed with the new key). Old-announcement replays cannot
  roll pins back (the signer must be the currently-pinned key).
- **Revocation tooling.** `POST /admin/revoke {room, name|pubkey}` (bearer:
  relay token) removes the binding, **blocklists the key** (a revoked key
  cannot re-register itself with the long-lived invite token), and disconnects
  the live peer; `{undo: true}` un-revokes. `GET /admin/allowlist` inspects
  bindings. Replaces "edit the JSON by hand".
- **Multi-room membership + discovery.** `MYC_ROOM` takes a comma list (≤8);
  one connection serves all rooms; frames carry a **signed `room`** so the
  relay cannot re-route a message across rooms; sessions, TOFU pins, replay
  windows, STS bindings, and acks are all room-scoped. `myc_rooms` lists rooms
  via the relay (`RELAY_DISCOVERY=false` to disable; non-member rooms show
  counts only).
- **Chunking.** Logical messages up to `MYC_MAX_MSG_BYTES` (default 1MB) are
  split into ≤24KB parts that inherit signatures, acks, dedup, and
  retransmission; receivers reassemble after decryption (chunk metadata rides
  inside the authenticated ciphertext). The 64KB relay frame cap no longer
  bounds message size.
- **Multi-relay fingerprint pinning.** `MYC_RELAY_FINGERPRINT` accepts a comma
  list matched as a set, so failover composes with identity pinning — v0.2.x
  docs told operators to *disable pinning* to use failover. Pinning configured
  + relay presents no identity → fail closed; token sealing failure with
  pinning configured no longer downgrades to a plaintext token.
- **Passphrase-encrypted key files.** `MYC_KEY_PASSPHRASE` /
  `RELAY_KEY_PASSPHRASE` encrypt identity keys at rest (Argon2id via
  `crypto_pwhash` + `crypto_secretbox`); plaintext files upgrade in place on
  first run; wrong passphrase is fail-closed.
- **Wire protocol version (`proto: 2`)** in challenge/auth/auth_ok and on every
  frame (signed, presence-conditional). Signature failures against a
  mismatched `proto` log an explicit upgrade hint instead of a bare bad-sig.
- **`_perm_req` is ack-tracked** (approval requests were the one message class
  still able to vanish silently); verdicts keep their acks.
- **Room-scoped TOFU (v2 store, auto-migrated)** — same-named peers in
  different rooms no longer collide into spurious violations.
- **CI on every push/PR** (`tests.yml`): blocking typecheck + all three suites.
  Publish-time typecheck is blocking too (was `continue-on-error`).
- Tests: 176 across three suites (89 unit/relay, 63 two-peer integration, 24
  controlled-relay), covering every feature above end-to-end — including the
  offline-delivery walk with a real process restart, the nack→auto-resend→
  confirm loop, rotation continuity, offline name-squat rejection, revoke/undo,
  chunk reassembly byte-identity, and passphrase fail-closed.

### Changed

- Canonical signature v2: `offline`, `proto`, `room`, `ts` join the signed
  fields with presence-conditional inclusion — stripping or adding any of them
  breaks the signature, and legacy 11-field frames still verify (see
  `canonical.ts`).
- Verified duplicates are **re-acked** (lost-ack recovery) instead of silently
  dropped; replay commits happen only after signature verification AND
  successful decryption.
- Relay `queued` status is log-only at the sender (the model was already told
  📮 at send time); relay `error` reports feed the retransmission loop and
  only surface for untracked messages.
- `myc_peers` shows per-room status, offline-reachable peers, inbox depth, and
  local-queue state; MCP server version now tracks the package version.

### Known limitations (honest edition)

- Offline envelopes trade PFS for deliverability (documented above); live
  sessions keep full PFS.
- First contact requires both peers online (sealing needs a pinned identity).
- The relay still sees metadata: names, rooms, timing, sizes, and the
  who-talks-to-whom graph. Traffic analysis is NOT mitigated — see README
  threat model.
- Revoking a key frees its name; a revoked *operator* holding the invite token
  can re-register under a fresh name/key. Rotate `RELAY_TOKEN` to fully evict
  an actor.

## [0.2.1] - 2026-07-18

Loss-signal release. A post-merge audit of 0.2.0 confirmed that several of its
hardening changes traded v0.1.x's noisy failures for **silent message loss** and
un-surfaced security failures. Every confirmed finding is fixed here, each with a
regression test in the two-peer integration suite or the controlled-relay suite.

### Fixed

- **HIGH — offline-queued messages were silently lost.** A relay-queued frame is
  encrypted to the recipient's *previous* ephemeral key (keys rotate on every
  reconnect), so it can never be decrypted on delivery — and 0.2.0 hard-dropped it
  with only a stderr log. A verified-but-undecryptable frame now (a) surfaces a
  fixed-text loss notification to the recipient's model (no attacker-controlled
  content) and (b) sends an encrypted `_nack` to the sender, whose model is told
  exactly which `msg_id` needs a resend. The relay's `queued` status is also
  surfaced to the sender with an honest warning that queued frames will not be
  decryptable after the peer reconnects.
- **HIGH — legitimately reordered frames were dropped as replays.** The strict
  monotonic `seq <= last ⇒ duplicate` check discarded any out-of-order frame
  pre-decryption. Replaced with an RFC 4303-style sliding window (64 entries) per
  (sender, session): unseen seqs inside the window are delivered even below the
  floor, exact replays and below-window stale frames are still rejected, and `seq`
  remains signature-covered so frames cannot be moved. Persisted replay state
  migrates from the 0.2.0 format conservatively.
- **HIGH — relay delivery-error reports were swallowed by the client.** 0.2.0 made
  the relay report drops honestly (`rate limited`, `backpressured`, `queue full`),
  but the peer's `_relay` handler discarded `error` frames unseen. They now surface
  to the model (sanitized + truncated), and a reported drop fails the pending
  delivery ack immediately instead of waiting out the 30s watchdog.
- **HIGH — reconnect cancelled genuine delivery warnings.** The `auth_ok` handler
  cleared all `pendingAcks` timers, so a message that raced a disconnect lost its
  only loss signal. Ack timers now survive reconnects; the 30s watchdog fires
  unless a real ack arrives.
- **HIGH — STS never verified for manually trusted peers.** `myc_trust` re-processed
  peer keys without the stored `session_id`, so the session-id-bound STS binding
  could never match and mutual verification permanently failed for exactly the
  peers the user explicitly trusted. The `session_id` is now forwarded.
- **MEDIUM — custom message types were silently rewritten to `info`.** 0.2.0's
  `safeSendType` coerced any non-allowlisted type, breaking v0.1.x workflows that
  route on `meta.type` and severing the `_perm_verdict` remote-approval loop.
  Custom application types now pass through verbatim; reserved `_*` control types
  are rejected with an explicit tool error (never silently rewritten); and
  `_perm_verdict` — the remote permission-approval mechanism — is sendable again
  (and now delivery-acked by the receiver).
- **MEDIUM — STS verification failure was log-only.** A wrong STS binding signature
  (possible MITM) left messages flowing with a `🔒` indicator. A binding-signature
  mismatch is now fail-closed: the session is torn down, the peer is blocked (also
  across re-key attempts), the model gets a `🔴 possible MITM` notification, and
  recovery requires out-of-band fingerprint verification + `myc_trust`. STS
  *timeout* remains lenient (TOFU/eph-sig-authenticated, no 🤝 flag). Malformed
  STS signatures can no longer throw in the handshake handlers.

### Changed

- The canonical 11-field signature serialization now lives in `canonical.ts` and is
  imported by `peer-channel.ts` **and** the tests — previously three inline copies
  could drift and let tests verify themselves instead of the protocol.
- `sendEncrypted` lost its vestigial `routeTarget` parameter (it was always equal to
  `target`), making the v0.1.x `target=null` broadcast fan-out bug unrepresentable.
- Shared test plumbing (MCP stdio client + `waitUntil`) extracted to
  `test-helpers.ts`, used by both process-spawning suites.

### Added

- Integration tests: custom type delivered verbatim; reserved types rejected with an
  explicit error; full TOFU-key-change → `myc_trust` → STS-re-verification walk.
- Controlled-relay tests: out-of-order delivery inside the window; exact-replay
  rejection; decrypt-failure notification + `_nack` round-trip (both sides);
  relay `error`/`queued` surfacing; STS fail-closed teardown.

## [0.2.0] - 2026-07-17

Correctness release. v0.1.x could not deliver a single message between two peers;
this release fixes that and the surrounding class of protocol bugs, and adds the
real two-peer end-to-end test coverage whose absence let the regression ship green.

### Fixed

- **CRITICAL — total delivery failure (STS handshake collision).** Both peers are
  symmetric and both initiated the STS exchange, but `stsPending` was keyed only by
  peer name, so each side's responder role clobbered its initiator ephemeral key.
  Every session then failed STS verification, which called `peerSessions.delete()`
  and tore down encryption — so `myc_send`/`myc_broadcast` returned `🔴BLOCKED` and
  no message was ever delivered. STS is redesigned: exactly one peer initiates (the
  lexicographically smaller name), the signed value is a deterministic name-ordered
  binding over **both session ephemerals + both session_ids**, and **STS never tears
  down a session** — a mismatch merely leaves it TOFU/eph-sig-authenticated but not
  mutually-verified. The channel was already authenticated by `eph_enc_pubkey_sig`
  before STS ran; STS is now a correct, live, mutual channel-confirmation on top.
- **CRITICAL — reorder buffer silently dropped messages.** The buffer assumed the
  regular-message `seq` stream started contiguously at 0, but control frames
  (`_sts`/`_ack`/`_perm`) share the same `outboundSeq` counter, so the first data
  message was buffered awaiting a seq that never arrived and then discarded by the
  200ms stale-timer without ever being delivered. Removed the buffer: a peer holds
  one relay connection at a time and the relay forwards in order, so messages are
  delivered immediately in arrival order; `msg_id` dedup + the signed `seq` remain
  the replay defense.
- **HIGH — broadcast fan-out produced decrypt-failure spam.** `myc_broadcast` routed
  each per-recipient ciphertext with `target=null`, so the relay fanned every copy to
  every peer and each peer received N−1 undecryptable copies. Broadcast is now true
  N×unicast (each copy routed to its specific recipient); exactly one decryptable copy
  per peer.
- **relay per-IP connection limit was a global cap.** `resolveIp` returned a constant
  `'direct'` for every non-proxied client, collapsing `RELAY_MAX_IP_CONNS` into a
  single global limit. It now uses the real socket address (`server.requestIP`).
- **broken published binaries (double shebang).** The build added a shebang banner on
  top of the source files' own shebang, so `build/relay.js` / `build/peer-channel.js`
  had two `#!` lines and crashed with a syntax error on run — the `mycelium-relay` /
  `mycelium-peer` bins shipped in 0.1.x did not start at all. Dropped the banner (the
  source shebang carries through) and added a `prepublishOnly` build+typecheck gate.
- **relay sole-member reconnect orphaned the peer.** A same-identity reconnect by a
  room's only member evicted the old connection, which deleted the now-empty room map,
  leaving the new peer registered in a detached map (invisible to routing/ping). The
  room map is now re-acquired after eviction.
- **unauthenticated plaintext injection bypassed the sig hard-block.** The "bad/missing
  signature = hard block" guard only ran for `e2e` frames, so a non-`e2e` frame from a
  malicious relay was delivered to the model verbatim. Non-E2E and undecryptable peer
  frames are now hard-blocked.
- **reserved control-type injection via tools.** `myc_send`/`myc_broadcast` passed the
  caller-supplied `type` straight onto the wire, letting a prompt-injected local model
  emit a reserved control frame (`_sts_*`/`_ack`/`_perm_*`) — e.g. a forged permission
  verdict. Types are now restricted to the public data set.
- **delivery acks weren't bound to the target.** `handleAck` cleared a pending ack by
  id regardless of sender; it now requires the ack to come from the message's target.
- **`msg_id` dedup was globally keyed and seq was never enforced.** Dedup is now scoped
  to the (unspoofable) sender so one peer can't burn another's `msg_id` namespace, and
  the signed `seq` is enforced monotonic per session as a real replay defense. Both are
  consulted and committed **only after signature verification**, so a malicious relay
  cannot inject a forged high-seq frame to poison the monotonic floor and silently drop
  the real sender's future messages.
- **relay lied about queued/dropped messages.** A unicast dropped under backpressure,
  or an offline message discarded by a queue cap, is now reported to the sender instead
  of silently dropped / falsely reported as `queued`.
- **constant-time credential comparison.** The shared token and health bearer are now
  compared in constant time (hash + `memcmp`), matching the documented posture.
- **typecheck now clean under `strict`.** Fixed the `Bun.serve`/`server.upgrade` data
  generic (`relay.ts`) and enabled `strict: true` (strict null checks); `bunx tsc
  --noEmit` passes with zero errors.
- Stale per-session timers (STS/ack) are cleared on reconnect; removed the unused
  `main` entry (side-effectful CLI); fixed docs (STS/first-contact claims, `stateless`
  overstatement, INSTALL.md config path, npm-excluded doc link).

### Added

- **`test-integration.ts` — real end-to-end suite.** Spawns a relay and two actual
  `peer-channel.ts` MCP processes and asserts genuine delivery: STS mutual
  verification, unicast/broadcast each deliver exactly one decrypted copy, bidirectional
  reply, a 20-message burst delivered in order with no drops, `myc_peers` status, and a
  hard-blocked plaintext-injection attempt.
- **`test-replay-poison.ts` — malicious-relay regression test.** Runs a real
  `peer-channel.ts` against a mock relay that forges a bad-signature high-seq frame, and
  asserts a subsequent legitimate low-seq message is still delivered (the seq floor is
  not poisoned). `bun run test` runs the unit, integration, and this suite.

### Changed

- Consolidated the on-wire envelope construction (`sendCtrl`) so every message type
  (data, STS, ack, permission) is built and canonically signed identically.

### Notes / known limitations

- **Offline delivery is best-effort and does not cover E2E messages.** A peer can only
  encrypt to a peer it currently shares a session with, so once a target has fully left
  the room a sender cannot produce a ciphertext for it — the relay's offline queue is
  therefore only reachable in narrow windows and cannot store-and-forward forward-secret
  traffic. Undelivered unicasts surface via the 30s ack timeout.
- **First-contact trust is TOFU.** STS confirms the agreed session against TOFU-pinned
  identities but cannot, by itself, defeat a relay that MITMs the very first contact —
  verify fingerprints out-of-band with `myc_trust` for first-contact assurance.
- Challenge-response remains opt-in via `RELAY_REQUIRE_CHALLENGE` (default off) for
  backward compatibility; enabling it is recommended for new deployments.
- The remote permission-approval loop is intentionally receive-only: `_perm_req` is
  forwarded to peers, but verdict emission depends on host support and is not fabricated.

## [0.1.1] - 2026-05-02

### Changed

- First end-to-end OIDC publish via the trusted-publisher pipeline.
  No source changes — this release only verified that the
  `.github/workflows/publish.yml` handshake works.

## [0.1.0] - 2026-05-02

Initial public release on npm. Published as **`@yoda.digital/mycelium`**.

The repository previously carried an unpublished `1.0.0` git tag from
private development; the public package starts at `0.1.0` to signal
"first release with public-API and SemVer commitment."

### Added

- Bun-runtime package on npm with two binaries:
  - `mycelium-relay` — stateless authenticated router with Ed25519 relay
    identity and challenge-response auth.
  - `mycelium-peer` — MCP server for E2E encrypted peer messaging
    (Ed25519 identity + Curve25519 PFS + NaCl `crypto_box`).
- LICENSE (MIT, owner: Yoda Digital).
- SECURITY.md with private vulnerability reporting flow.
- CONTRIBUTING.md.
- OIDC trusted-publisher CI workflow (`.github/workflows/publish.yml`)
  — no `NPM_TOKEN`, no `provenance: true` flag, npm auto-attests via
  GitHub OIDC.
- README badge linking to the
  [Yoda Digital open-source portal](https://opensource.yoda.digital/projects/mycelium/).
