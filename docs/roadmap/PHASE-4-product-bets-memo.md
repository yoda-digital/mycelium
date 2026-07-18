# Phase 4 — Optional, Demand-Gated Product Bets

**Status: PROPOSED. Nothing in this document is implemented or committed to a milestone.**
**Package:** `@yoda.digital/mycelium` v0.3.0 · **Date:** 2026-07-18 · **Author:** maintainer memo

> This is a strategy memo, not a build plan. Its single thesis: **validate the market before
> writing a line of any of these four bets.** Each bet below is gated on demand we do not yet
> have evidence for, and three of the four are gated on hard technical prerequisites that also
> do not exist yet. The honest default for all four is **No-Go until the gate is met.**

---

## 0. What Mycelium is today (the baseline these bets build on)

Everything below is grounded in the shipped v0.3.0 code so the bets don't drift into fiction.

| Property | Where it lives | Note |
|---|---|---|
| Two artifacts only | `peer-channel.ts` (MCP server / peer), `relay.ts` (hostile WebSocket router) | ~2 files of product; the rest is tests |
| Client-side crypto | `peer-channel.ts` | Ed25519 TOFU identity, per-connection Curve25519 ephemerals (live PFS), `crypto_box_seal` offline envelopes, STS mutual auth, key-rotation continuity |
| Single signed-field source | `canonical.ts` — `canonicalize()`, `PROTO = 2` | Relay cannot re-mint `msg_id`, re-route `room`, or move `seq`; all are inside the signature |
| Idempotent transport | `peer-channel.ts:759-810` (`checkReplay` / `commitReplay`), `:866-984` (outbox) | Commit-after-decrypt; retransmit reuses `msg_id`; receivers dedup + re-ack. At-least-once delivery with an idempotent receiver. |
| Relay = zero-plaintext router | `relay.ts` | Routes ciphertext; sees metadata (names, rooms, timing, sizes, the graph) — a documented tradeoff (`README.md` "Threat model") |
| License | `package.json` `"license": "MIT"` | Protocol + self-host relay + peer are all MIT |

**Two facts drive most of the go/no-go logic below and must be stated up front:**

1. **The relay is a single process with all state in RAM.** `rooms`, `offlineQueues`, and
   `ipConnections` are module-level `Map`s (`relay.ts:118-120`); the live `ws` socket handle is
   held directly on each `Peer` (`relay.ts:88-100`, field `ws`), and the counters
   (`totalConnections`, `msgRelayed`, …) are plain module variables (`relay.ts:122-127`).
   The only durable state is *local files* — the allow-list (`RELAY_ALLOW_FILE`,
   `relay.ts:57`), the relay key (`RELAY_KEY_FILE`), and an *opt-in* ciphertext queue
   (`RELAY_QUEUE_FILE`, `relay.ts:60`). There is **no shared datastore, no pub/sub, no cluster
   coordination** — a `grep` for `redis|backplane|cluster|pubsub|nats|kafka|shard` over both
   files returns nothing. A second relay process shares nothing with the first.

2. **Anti-abuse today is per-connection and per-IP, never per-identity.** The relay gates on a
   single shared `RELAY_TOKEN` (`relay.ts:40`, required at `:83-86`), a token-bucket rate limit
   per live connection (`tryConsume`, `relay.ts:204-213`, default `RATE_LIMIT = 300`/min), a
   per-IP connection cap (`MAX_IP_CONNS`, default 10, `relay.ts:52`), and a global peer cap
   (`MAX_PEERS`, default 50, `relay.ts:41`). The allow-list binds a *name* to a *pubkey* per room
   (`relay.ts:424-435`) but places **no cost on minting a new identity**: an Ed25519 keypair is
   free to generate client-side, and one shared token admits unlimited fresh identities. There is
   **no proof-of-work, no metered identity-mint, and no reputation** (`grep -i` for those terms
   returns nothing).

> The task brief referenced `relay.ts:94-96` for "state is all one process's RAM." In v0.3.0 that
> exact range sits inside the `Peer` interface (`ip`, `signPubKey`, `ephEncPubKey`); the load-bearing
> claim is the module-level state at `relay.ts:118-127`. Cited precisely above so the memo stays
> honest against the current file.

---

## 1. The demand-gating discipline (read this before any bet)

**The failure mode we are explicitly avoiding: building the hosted/standards/group/sync feature
first and hunting for a buyer second.** Every bet here is *optional*. Mycelium already does the one
thing it promises — E2EE agent-to-agent messaging you can self-host — and that promise is complete
without any of this. So the bar to start building is not "is it a good idea" (three of these are);
it is "have we seen the demand, and is the prerequisite met."

For each bet: **a Go requires a real pull signal AND (where applicable) the technical prerequisite
already in place.** A pull signal is not a hypothetical persona; it is one of:

- ≥ 3 unrelated inbound requests for the *specific* capability (not "encryption" in general);
- a paying design partner who has signed to co-develop and dogfood it;
- an internal Yoda product that is blocked on it today and would adopt within one quarter.

Absent that, the bet stays **No-Go / validate-first**, and validation means talking to buyers and
writing a throwaway spike at most — never shipping the production feature.

---

## 2. Bet 1 — Hosted zero-knowledge relay (PROPOSED · **No-Go until prerequisites + buyer**)

### Thesis
Offer a hosted relay so teams get agent-to-agent E2EE without running infrastructure. "Zero-
knowledge" here means what the code already delivers: the relay routes ciphertext and never holds
plaintext or keys. The pitch is "we run the pipe; we cannot read your traffic."

### Who this is for — and who it is emphatically NOT for
- **Sell to privacy buyers.** The value proposition is *we cannot read your content, by construction.*
- **Never sell to compliance buyers.** Regulated buyers (DLP, content inspection, archival
  supervision, lawful-intercept obligations) need to *inspect content* — and a zero-knowledge relay
  **forbids exactly that**. Selling ZK into a compliance requirement is selling a product that
  cannot do the job; it is a mis-sale, not a feature gap. If a prospect's real requirement is
  content inspection, the correct answer is "Mycelium is the wrong tool," the same posture the
  README already takes about metadata.

### The disclosure we are obligated to make
Hosting **centralizes the metadata graph**. Today a self-hoster's relay sees who talks to whom, when,
how often, and how big — and that data stays on their box. A *hosted* relay concentrates the metadata
of every tenant onto infrastructure we operate. Content stays encrypted; the *social/communication
graph* does not. This must be stated plainly in marketing and in the ToS/privacy policy, not buried.
It is the single most important honest disclosure of this bet, and it is the reason a privacy-maximalist
prospect may still (correctly) choose self-hosting.

### Hard prerequisites — NEITHER exists today
1. **Per-identity anti-abuse.** A public hosted endpoint with free identity minting and one shared
   token is a spam and resource-exhaustion magnet. Per-connection rate limiting (`relay.ts:204-213`)
   and per-IP caps (`relay.ts:52`) do not survive contact with a botnet rotating IPs and identities.
   We need one (probably a layered combination) of:
   - **Client proof-of-work on identity mint / first join** (Hashcash-style): make a fresh identity
     cost CPU, so mass-minting is expensive. Cheap to add to the challenge handshake; annoys honest
     low-power agents; tunable difficulty.
   - **Signed, rate-limited identity-mint capability**: an issuer (could be a paid API key, could be
     the hosted control plane) signs a capability that admits N identities per period. Turns "one
     shared token → infinite identities" into a metered, attributable operation.
   - **Reputation**: age/behavior-weighted trust that throttles new or misbehaving identities. Highest
     value, highest complexity, and it introduces *per-identity state the relay must persist and share*
     — which collides directly with prerequisite 2.
   None of these exist in the code. This is net-new subsystem work, not a config flag.

2. **A horizontal-scale backplane.** Per §0, the relay is one process with all routing state in RAM
   and the live `ws` handle pinned to that process (`relay.ts:88-120`). A hosted service needs ≥ 2
   nodes for availability alone, and the moment there are two, a message from a peer on node A to a
   peer on node B has no path — they share no `rooms` map. Building this means introducing an
   inter-node routing layer (session affinity or a pub/sub fan-out of ciphertext frames), moving the
   allow-list and offline queue off local files into a shared store, and solving the non-trivial
   detail that **a `ws` socket handle is not serializable across nodes** — you route the *frame* to
   the node that owns the socket, you do not move the socket. This is the largest single piece of
   engineering in this entire memo and it changes the relay's operational character completely.

### Go / No-Go criteria
- **Go only if ALL hold:** (a) ≥ 1 paying design partner or ≥ 3 qualified inbound for *hosted*
  specifically; (b) per-identity anti-abuse designed and spiked; (c) backplane designed and spiked;
  (d) legal sign-off on the metadata-centralization disclosure and a written data-processing posture.
- **No-Go (default) if:** the pull is really "we want E2EE" (→ point them at self-host, done today);
  or the buyer's requirement is content inspection (→ wrong tool, do not sell); or either prerequisite
  is still vaporware. Do **not** stand up a hosted relay on the current single-process code "just to
  test demand" — an unabuse-hardened public relay is a liability, not an MVP.

### Risks
- **Abuse before revenue** — a public endpoint invites abuse the instant it is discoverable; without
  prerequisite 1 the on-call cost dominates.
- **Availability expectations** — hosted implies an SLA; the current process has no HA story.
- **Mis-sale risk** — sales pressure to "just add an inspection mode" would silently destroy the
  zero-knowledge property. Guard this in the product definition, not in a sales conversation.
- **Metadata liability** — centralized graph metadata is subpoena-able and breach-relevant even though
  content is not. Data-minimization (short log retention, no content, aggregate-only analytics) must be
  designed in, not bolted on.

### Security review checklist (Bet 1)
- [ ] Proof-of-work / mint-capability verification is **constant-time** where it compares secrets (reuse
      `ctEq`, `relay.ts:32-37`); difficulty is server-set and cannot be downgraded by the client.
- [ ] The metadata the hosted relay retains is enumerated, minimized, and time-bounded; **no plaintext,
      no keys, no message bodies** ever touch server logs or analytics.
- [ ] Backplane transports **only ciphertext frames** between nodes; the inter-node channel is itself
      authenticated + encrypted (mutual TLS at minimum) so the backplane is not a softer MITM surface
      than the front door.
- [ ] Shared allow-list/queue store cannot let node A's compromise forge bindings for node B; the
      name↔key binding semantics (`relay.ts:424-535`) are preserved exactly across the shared store.
- [ ] Rate-limit and anti-abuse state cannot be reset by reconnecting to a different node (state is
      shared or the limiter is identity-keyed, not connection-keyed).
- [ ] Tenant isolation: one tenant's peers cannot enumerate or join another tenant's rooms; `list_rooms`
      discovery (`RELAY_DISCOVERY`, `relay.ts:62`) is tenant-scoped or off by default in hosted mode.
- [ ] Written disclosure that the hosted operator sees the full metadata graph, reviewed by legal.

---

## 3. Bet 2 — A2A Agent-Card confidential-transport face (PROPOSED · validate-first)

### Thesis
Give Mycelium an **Agent2Agent (A2A)–compatible face** so a Mycelium peer can be discovered and
addressed as an A2A agent, with Mycelium providing the *confidential transport* underneath. A2A is now
a Linux Foundation project (announced by Google April 2025, donated to the LF June 2025) and its
discovery primitive is the **Agent Card** — a JSON document advertising an agent's identity, skills,
and endpoints. The bet is to expose/consume Agent Cards and align our identity + transport story to the
emerging confidential-transport pattern, **à la AGNTCY SLIM**, which layers **MLS (RFC 9420)** for
end-to-end encryption over a metadata-routing data plane and uses cryptographic client identities.

### Where our primitives already line up
- **Identity:** our Ed25519 TOFU identity maps cleanly to a self-certifying **`did:key`** (a W3C DID
  method that encodes the public key directly in the identifier — no registry, no CA, which is exactly
  our trust model). An Agent Card could carry the peer's `did:key`, and TOFU-pinning that key gives us
  the same "verify once, trust after" property we already have (`peer-channel.ts` TOFU + `myc_trust`).
- **Transport:** SLIM's shape — a data plane that forwards on metadata while content stays E2E
  encrypted end-to-end — is *precisely* Mycelium's relay + `canonical.ts` envelope model. We are
  already an instance of the pattern the standard is formalizing; the work is speaking its vocabulary,
  not rebuilding the mechanism.

### What this bet is and is NOT
- **IS:** a compatibility/adapter face — publish + consume Agent Cards, expose a `did:key` identity,
  and (aspirationally) interoperate at the transport layer with SLIM-style peers.
- **IS NOT (yet):** adopting MLS as Mycelium's own group crypto — that is Bet 3, and it is separately
  gated. Bet 2 can ship an Agent-Card face over the *current* pairwise crypto without MLS; MLS
  alignment is the direction of travel, not a Bet-2 blocker.

### Prerequisites
- The relevant specs are moving: A2A is at v1.x under the LF; **SLIM is an early IETF Internet-Draft
  (`draft-mpsb-agntcy-slim`), not a ratified standard.** Building deep interop against a draft risks
  churn. Prerequisite: pick a *stable enough* surface (Agent Card discovery first; deeper SLIM/MLS
  transport interop only once the draft stabilizes or a design partner needs it).
- A concrete interop target: a real A2A agent or SLIM peer we must talk to, not a spec read in a vacuum.

### Go / No-Go criteria
- **Go if:** an ecosystem or customer requires Mycelium peers to be A2A-discoverable, OR we want
  Mycelium positioned as "the confidential transport for A2A/SLIM" and have design-partner demand to
  justify it. Start with the **cheapest slice**: emit + parse an Agent Card carrying a `did:key`, TOFU
  the key, done. That slice is small, MIT, and reversible.
- **No-Go if:** no interop partner exists and the specs are still churning — the risk of building
  against a moving draft outweighs the option value. Re-evaluate per spec release.

### Risks
- **Standards churn** — SLIM is a -00/-01 draft; A2A extensions are still landing (v1.0.1 added an
  extension mechanism in 2026). Design for a thin, swappable adapter, not a deep coupling.
- **Identity-model impedance** — A2A/SLIM ecosystems may assume PKI/OIDC-style identity; our TOFU +
  `did:key` model is deliberately registry-free. Interop may require a bridge (e.g., accepting a
  did:key *and* an issuer-signed card) without abandoning fail-closed TOFU.
- **Scope creep into Bet 3** — "align to MLS" can silently become "adopt MLS," which is a much larger
  commitment. Keep the boundary explicit.

### Security review checklist (Bet 2)
- [ ] An Agent Card is treated as **untrusted input**: parsing it never auto-trusts a key. A `did:key`
      from a card enters the *same* TOFU/`myc_trust` fail-closed path as any other first contact
      (`peer-channel.ts` TOFU; changed key ⇒ blocked).
- [ ] `did:key` decoding validates the multicodec/curve and rejects unexpected key types; a card
      cannot smuggle a non-Ed25519 identity that bypasses our verification.
- [ ] The adapter cannot become a signature-verification bypass: frames still verify against
      `canonicalize()` (`canonical.ts`) regardless of how the peer was discovered.
- [ ] If SLIM/MLS transport interop is attempted, it is behind a flag and does **not** weaken the
      existing pairwise guarantees for non-SLIM peers.

---

## 4. Bet 3 — MLS / TreeKEM group crypto for large, churning swarms (PROPOSED · **No-Go until O(n) rekey is the measured bottleneck**)

### Thesis
Adopt **MLS (RFC 9420)** with its **TreeKEM** continuous group key agreement to make group messaging
scale to large, high-churn agent swarms with forward secrecy and post-compromise security at
**O(log n)** rekey cost per membership change, instead of today's implicit **O(n)** pairwise model.

### The honest trigger — do NOT build this before it
Mycelium has no group crypto today; a "room" is a fan-out of **pairwise** encrypted unicasts
(`README.md`; broadcasts are fanned out client-side as unicasts, per the wire-protocol doc). Every
pairwise link has its own signed Curve25519 ephemeral (`peer-channel.ts` key exchange). For a group of
`n` peers this is inherently **O(n)** links per sender and O(n) work when membership changes. **That is
completely fine for small, stable rooms** — which is the current and near-term use case (a handful of
Claude Code instances coordinating).

MLS pays off **only** when:
1. groups are **large** (tens to hundreds+ of members), AND
2. membership **churns frequently** (agents joining/leaving constantly), so rekey cost dominates, AND
3. we have **measured** that O(n) pairwise rekey is the actual bottleneck in a real workload.

Absent all three, MLS is a large amount of subtle group-crypto complexity bought to solve a problem we
do not have. **The default is No-Go**, and the gate is a profiler, not an opinion.

### Prerequisites
- A measured workload where pairwise rekey is the demonstrated bottleneck (benchmark first).
- A vetted MLS implementation to bind to (rolling our own TreeKEM is out of scope and reckless); this
  also means a WASM/native dependency decision, since our crypto is currently libsodium-only.
- A migration story: MLS group state is stateful and epoch-based; it must coexist with, or cleanly
  replace, the pairwise path without breaking the fail-closed TOFU/STS guarantees.

### Go / No-Go criteria
- **Go only if:** (1) benchmarks show O(n) rekey is the bottleneck at real swarm sizes; AND (2) there
  is demand for large churning swarms (not hypothetical); AND (3) a mature, audited MLS library is
  available to depend on. Bet 2's SLIM/MLS alignment may create natural pull here — if we interop with
  SLIM's MLS transport, adopting MLS internally becomes coherent rather than speculative.
- **No-Go (default):** small/stable rooms, or unproven scale claims. Ship nothing; the pairwise model
  is correct for the current product.

### Risks
- **Complexity vs. payoff** — MLS is one of the more intricate protocols in modern crypto; TreeKEM
  epochs, commits, proposals, and welcome messages are a large new state machine and a large new attack
  surface. The value is real only at scale we have not reached.
- **State/dependency weight** — MLS group state and a new crypto dependency substantially increase the
  peer's footprint and the audit burden. Mycelium's current appeal is that it is ~2 small files.
- **Migration/compat** — mixed MLS + pairwise deployments, and the interaction of MLS epochs with our
  offline-envelope model (which has no PFS by design), need careful design; MLS's forward-secrecy
  guarantees must not be silently undermined by the offline path.

### Security review checklist (Bet 3)
- [ ] No hand-rolled TreeKEM/MLS — bind only to an audited implementation; treat it as the crypto core,
      not glue.
- [ ] The offline-envelope path (`sealForIdentity`, `peer-channel.ts:516-523`, **no PFS** by design)
      is reconciled with MLS's forward-secrecy claims: document exactly which guarantees hold for
      offline group messages and do not overstate PFS where sealed boxes are used.
- [ ] Group membership changes remain **fail-closed**: a peer that fails verification is removed from
      the group, mirroring today's TOFU/STS blocking (`stsFailedPeers`, `peer-channel.ts:285`).
- [ ] Epoch/commit handling is replay-safe and integrates with (or supersedes) the existing
      `msg_id`/`seq` replay defenses (`checkReplay`/`commitReplay`) without opening a gap.
- [ ] The relay still sees only ciphertext; MLS handshake/commit messages routed through the relay
      leak no group secrets to it.

---

## 5. Bet 4 — CRDT shared-state layer (Automerge / Yjs) over the idempotent transport (PROPOSED · validate-first)

### Thesis
Offer a **shared-state layer** for agents that need to converge on a common document/data structure
(shared task list, blackboard, plan) rather than just exchange messages — implemented as a
**CRDT** (Conflict-free Replicated Data Type) using **Automerge** or **Yjs**, riding on Mycelium's
existing transport.

### Why the fit is genuinely good (this is the strongest technical match in the memo)
CRDTs converge because their operations are **commutative and idempotent** — replicas apply updates in
any order, any number of times, and reach the same state. Mycelium's transport already provides exactly
the delivery property a CRDT sync layer wants:
- **At-least-once delivery with an idempotent receiver.** The outbox retransmits with the *same*
  `msg_id` (`peer-channel.ts:866-984`) and receivers **dedup + re-ack** (`checkReplay`/`commitReplay`,
  `:759-810`), so a CRDT op is delivered eventually and applying a duplicate is harmless by
  construction — the CRDT's own idempotence and the transport's dedup reinforce each other.
- **Offline convergence.** Sealed offline envelopes (`sealForIdentity`, `:516-523`) mean an agent that
  was offline still receives the ops it missed and converges on reconnect — the local-first sync story
  CRDTs are built for.
- **Signed, ordered, replay-protected frames** (`canonical.ts`, `seq` window) give the sync layer a
  trustworthy substrate; CRDT ops ride *inside* the authenticated ciphertext, so the relay sees nothing.

This bet is largely **additive and low-risk to the crypto core**: the CRDT lives *above* the transport,
carried as ordinary E2E message payloads. It does not modify `canonical.ts` or the handshake.

### Prerequisites
- A real use case where agents need *convergent shared state*, not messaging — validate this is a felt
  need, not a "wouldn't it be neat."
- Library choice (Automerge — research-backed JSON CRDT, Rust core — vs. Yjs — the performant incumbent;
  Loro is a newer Rust option). Both are MIT-compatible and both are WASM/JS.
- A framing decision: ship as a **separate optional package** (`@yoda.digital/mycelium-crdt`?) that
  depends on the peer, so the core stays ~2 files and dependency-light.

### Go / No-Go criteria
- **Go if:** a design partner or internal product needs shared convergent agent state AND is willing to
  dogfood. Start with a spike: wrap Automerge/Yjs doc updates as `myc_send` payloads over a room and
  demonstrate convergence across a churn/offline scenario — this is cheap precisely because the
  transport already does the hard delivery work.
- **No-Go if:** the need is really just messaging (already shipped) — do not add a CRDT dependency and a
  new mental model to solve a problem `myc_send` already solves.

### Risks
- **Payload size / chunking interaction** — CRDT documents can grow; large updates hit the 24 KB chunk
  boundary and the 1 MiB logical cap (wire-protocol §10). Automerge's columnar encoding and Yjs's
  compact updates help, but sync-heavy workloads could stress the transport in ways messaging does not.
  Benchmark before promising.
- **Ordering expectations** — CRDTs tolerate reorder by design, which matches our reordering-tolerant
  `seq` window; but any *causal-delivery* assumption a naive integration makes must be checked against
  what the transport actually guarantees (eventual, deduped, not strictly causal).
- **Scope** — shared-state is a product in its own right; kept as an optional layer it is contained,
  but it can grow to dominate maintenance if it becomes the headline feature. Keep it optional.

### Security review checklist (Bet 4)
- [ ] CRDT ops travel **inside** the authenticated E2E ciphertext (as `myc_send` payloads); the relay
      never sees document state, preserving the zero-plaintext property.
- [ ] Applying a CRDT op is gated on the frame passing the full verify → dedup → decrypt → commit
      pipeline (`peer-channel.ts` inbound gate + `commitReplay`); a CRDT update from an unverified or
      TOFU-violating peer is never merged.
- [ ] Merging a *duplicate* op is verified harmless — relies on CRDT idempotence **and** transport
      dedup; do not disable transport dedup on the assumption the CRDT will "handle it."
- [ ] Document-size growth cannot be used to DoS a peer past `MYC_MAX_MSG_BYTES` / chunk limits; the
      integration respects existing caps rather than raising them silently.
- [ ] No CRDT metadata (actor IDs, vector clocks) leaks a stronger identity correlation to the relay
      than the messaging layer already does.

---

## 6. Sequencing & dependencies

These bets are not independent. A rational order, each still gated on its own demand signal:

```
Bet 4 (CRDT)  ── additive, low crypto-risk, strongest technical fit ── can start first, cheaply
Bet 2 (A2A/SLIM face) ── thin adapter first (Agent Card + did:key) ── creates natural pull toward…
Bet 3 (MLS/TreeKEM) ── only after Bet 2 interop OR measured O(n) rekey pain
Bet 1 (Hosted ZK relay) ── gated on TWO net-new subsystems (anti-abuse + backplane) + a paying buyer
```

- **Cheapest / lowest-risk to validate:** Bet 4, then the Agent-Card slice of Bet 2.
- **Most expensive / highest-risk:** Bet 1 (two large net-new subsystems and an operational liability)
  and Bet 3 (deep crypto complexity that only pays at unproven scale).
- Bet 1's *reputation* anti-abuse option and Bet 1's *backplane* would each independently force the
  per-identity/shared-state work that the current single-process relay avoids — do not underestimate them.

---

## 7. Licensing stance (non-negotiable)

**The protocol, the peer, and the self-host relay stay MIT** (`package.json` `"license": "MIT"`).
Whatever commercial shape a hosted offering (Bet 1) or a shared-state package (Bet 4) takes, the
open, self-hostable core is not clawed back. A user who wants to run their own relay and peer,
read the wire protocol, and audit the crypto can always do so under MIT. Any hosted/managed value is
sold on operation and convenience, never by closing the protocol.

---

## 8. What we are explicitly NOT doing in Phase 4

- Not standing up a public hosted relay on the current single-process, single-shared-token code.
- Not selling zero-knowledge into a content-inspection/compliance requirement.
- Not adopting MLS before O(n) pairwise rekey is a *measured* bottleneck at real swarm size.
- Not adding a CRDT dependency to solve a problem `myc_send` already solves.
- Not hiding the metadata-centralization tradeoff of hosting.
- Not building any of the four before a real pull signal exists.

---

## 9. Open questions to resolve during validation

1. Is there a paying buyer for *hosted* specifically, or is the real ask self-host help (docs, ops)?
2. For anti-abuse: is proof-of-work acceptable to low-power agent operators, or does a metered
   signed-mint capability fit the buyer better?
3. Which A2A/SLIM surface is stable enough to build against, and who is the concrete interop partner?
4. At what group size and churn rate does pairwise rekey actually hurt in our workloads? (Benchmark.)
5. Automerge vs. Yjs vs. Loro for Bet 4 — decided by document shape, payload size behavior over our
   chunking, and audit/maintenance weight.

---

## References (standards & external, verified 2026-07-18)

- **MLS / TreeKEM** — *The Messaging Layer Security (MLS) Protocol*, IETF **RFC 9420** (July 2023);
  TreeKEM continuous group key agreement, O(log n) rekey.
  <https://datatracker.ietf.org/doc/html/rfc9420>
- **A2A / Agent Card** — *Linux Foundation launches the Agent2Agent Protocol Project* (announced by
  Google April 2025, donated to the LF 23 June 2025); Agent Card = JSON discovery document.
  <https://www.linuxfoundation.org/press/linux-foundation-launches-the-agent2agent-protocol-project-to-enable-secure-intelligent-communication-between-ai-agents>
  · A2A spec: <https://a2a-protocol.org/>
- **AGNTCY SLIM** — *Secure Low-Latency Interactive Messaging (SLIM)*, IETF Internet-Draft
  `draft-mpsb-agntcy-slim` (early draft; uses MLS for end-to-end encryption over a metadata-routing
  data plane). <https://datatracker.ietf.org/doc/draft-mpsb-agntcy-slim/> ·
  <https://docs.agntcy.org/messaging/slim-core/>
- **did:key** — W3C DID method encoding the public key directly in a self-certifying identifier.
  <https://w3c-ccg.github.io/did-method-key/>
- **CRDT** — *Conflict-free Replicated Data Types* (Shapiro et al., 2011); commutative + idempotent
  replicated updates. <https://crdt.tech/> · Wikipedia:
  <https://en.wikipedia.org/wiki/Conflict-free_replicated_data_type>
- **Automerge** — JSON CRDT, Rust core. <https://automerge.org/>
- **Yjs** — high-performance CRDT framework. <https://github.com/yjs/yjs>
- **Hashcash / proof-of-work** — Adam Back, anti-abuse cost function.
  <http://www.hashcash.org/>
- **libsodium sealed boxes** (`crypto_box_seal`, anonymous sender) — our offline-envelope primitive.
  <https://doc.libsodium.org/public-key_cryptography/sealed_boxes>

## Internal cross-references (authoritative code)

- Canonical signed-field set & `PROTO`: `canonical.ts`
- Peer crypto, offline envelopes, idempotent transport, STS, rotation: `peer-channel.ts`
- Relay routing, in-RAM state, anti-abuse gates, allow-list: `relay.ts`
- Wire protocol (descriptive): `docs/wire-protocol-v2.md`
- Threat model & documented tradeoffs: `README.md`, `SECURITY.md`
