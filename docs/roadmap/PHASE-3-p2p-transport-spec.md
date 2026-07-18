# Phase 3 — Direct P2P transport (the "Tailscale moment")

**Status: PROPOSED / multi-month architecture change (not implemented).** Design doc
from the v0.3.0 audit.

## Thesis

Today every deployment is an island: mint a token, run `relay.ts`, agree a URL out of
band, front it with TLS. There is no network effect, and the relay is a **data plane**
whose cost scales with total message volume and which sees the full metadata graph.

The faithful upgrade is **not** a hosted blind relay (that centralizes 100% of the
metadata the product exists to protect). It is **direct peer-to-peer** with the relay
demoted to a thin, metadata-only fallback — which *shrinks* the metadata graph and
removes the relay's economic, abuse, and scaling burden.

Model to copy: **Iroh** / Tailscale — the peer's **Ed25519 identity is its address**;
attempt a direct connection (NAT hole-punch) first; fall back to a **DERP-style relay**
that only ferries opaque packets when hole-punching fails.

## Reference landscape (research)

- **Iroh** — QUIC dialed by public key, hole-punching, DERP relay fallback. Closest fit;
  Mycelium already addresses peers by Ed25519 key.
- **libp2p** — DCUtR hole-punching, circuit-relay-v2, gossipsub, DHT discovery. Heavier,
  more moving parts.
- **QUIC / WebTransport** — the transport substrate; **assess Bun/Node QUIC maturity
  honestly** (this is the main feasibility risk — see below).
- **WebRTC data channels** — battle-tested NAT traversal, but a heavy stack and awkward
  outside browsers.

## Proposed shape

1. **Identity = address.** Reuse the existing Ed25519 identity as the dial key; no new
   naming.
2. **Rendezvous / discovery.** A coordination service (could be today's relay, reduced to
   signaling) exchanges connection candidates. It never sees plaintext and, in the
   endgame, not even message timing/sizes — only "peer A wants to reach peer B".
3. **NAT traversal.** Hole-punch first (STUN-like); on failure, relay opaque packets via
   a DERP-style fallback.
4. **E2EE unchanged.** The entire existing crypto layer (signed frames, sessions, offline
   envelopes, replay window) rides **on top** of the new transport unchanged — the
   transport swap is below the envelope. This is the key derisking property: the security
   core is transport-agnostic.

## Honest feasibility caveats

- **Bun/Node QUIC is the gating risk.** As of this writing, first-class QUIC in Bun/Node
  is immature; a WebTransport or a vetted QUIC library may be required, or WebRTC as a
  fallback. This is why it is a **multi-month** item, not a quick win.
- **Metadata is not fully solved by P2P** — a rendezvous/DERP still learns *who wants to
  reach whom*. P2P shrinks the graph (no central store-and-forward of content/timing) but
  does not deliver mixnet-grade anonymity; keep the README's honest metadata statement.
- **Losing the store-and-forward relay** changes offline delivery: offline mail needs
  either a persistent DERP queue or a rendezvous-hosted mailbox — reconcile with the
  offline-envelope + queue-durability designs.

## Phased migration

1. Keep the relay as today; add a **rendezvous** capability to it (signaling only).
2. Add an optional direct-connect path; fall back to the existing relay transport when
   hole-punching fails. Peers negotiate "direct or relayed" transparently.
3. Once direct-connect is proven, demote the relay to DERP + rendezvous as the default;
   keep full-relay mode as a supported fallback.

## Test plan

Two peers behind (emulated) NATs establish a direct session and exchange messages;
force hole-punch failure and confirm the DERP fallback delivers; confirm the E2EE layer
(signatures, replay window, offline envelopes) is byte-for-byte unchanged across both
transports.

## Non-goals (for this phase)

Mixnet / metadata privacy (separate, larger project); a hosted multi-tenant data-plane
relay (explicitly rejected as counter-thesis — see
[`PHASE-4-product-bets-memo.md`](./PHASE-4-product-bets-memo.md)).
