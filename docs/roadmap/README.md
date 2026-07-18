# Mycelium roadmap

Design specs from the post-v0.3.0 **state-of-the-art / mass-adoption audit**. The audit
separated three axes — **adoption/funnel**, **operational reliability**, and the
**crypto/SOTA frontier** — and found that mass adoption is bottlenecked by product/DX,
not cryptography.

These docs are **proposals**, not shipped features. Where crypto or transport is
involved, they carry a security-review checklist and must not reach a release without
human review.

## Already shipped (this batch — tested, on the branch)

| Gap | What shipped |
|---|---|
| #1 Bun-only blocks `npx`/Node | Node-target peer bin (`#!/usr/bin/env node`), `npx` install path, Node↔Bun interop test |
| #2 durability (relay half) | Opt-in `RELAY_QUEUE_FILE` crash-durable offline queue + `test-durability.ts` |
| #5 invite token = admin | `RELAY_ADMIN_TOKEN` / `RELAY_HEALTH_TOKEN` split, loopback default |
| #7 verification inoperable | `myc_verify` read-only fingerprint tool |
| TTL/ack mismatch | `RELAY_QUEUE_TTL_S` default 300 → 3600 |
| #3/#4/#9 positioning | Outcome-framed README fixes, `npx` + flagless `myc_recv` path, `demo`, `llms.txt`, `server.json`, wire spec |

## Proposed (specs in this directory)

| Spec | Axis | Notes |
|---|---|---|
| [PHASE-2-multirelay-fanout-spec](./PHASE-2-multirelay-fanout-spec.md) | operational | Fix the partition footgun; simultaneous fan-out with existing dedup |
| [PHASE-2-outbox-durability-spec](./PHASE-2-outbox-durability-spec.md) | operational | The **sender** half of gap #2 (relay half already shipped) |
| [PHASE-3-prekey-offline-fs-spec](./PHASE-3-prekey-offline-fs-spec.md) | SOTA | X3DH/PQXDH prekeys → forward secrecy for offline mail |
| [PHASE-3-pq-hybrid-spec](./PHASE-3-pq-hybrid-spec.md) | SOTA | X25519 + ML-KEM-768 hybrid; signed suite negotiation |
| [PHASE-3-key-transparency-spec](./PHASE-3-key-transparency-spec.md) | both | Peer-gossiped signed key history; fixes rotation catch-up + cross-relay revocation |
| [PHASE-3-p2p-transport-spec](./PHASE-3-p2p-transport-spec.md) | SOTA | Iroh-style direct P2P, relay → metadata-only DERP fallback (multi-month) |
| [PHASE-4-product-bets-memo](./PHASE-4-product-bets-memo.md) | adoption | Demand-gated bets: hosted relay, A2A face, MLS, CRDT — validate first |

## Deliberate tradeoffs to KEEP (do not "fix")

Metadata honesty over a half-built mixnet · TOFU as bootstrap (backed by detection) ·
pairwise Curve25519 at small scale (no premature MLS) · self-host first-class · the local
stdio peer that custodies the private key · no full Double Ratchet · the single-process,
no-database relay · honest drop-and-notify backpressure · zero-knowledge as a deliberate
non-feature for compliance buyers.
