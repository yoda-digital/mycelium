# Phase 2 — Multi-relay simultaneous fan-out

**Status: PROPOSED (not implemented).** Design doc from the v0.3.0 audit.

## Problem (grounded in code)

`MYC_RELAY` accepts a comma list (`peer-channel.ts:33`, `RELAY_LIST`), but the peer
holds exactly **one** connection at a time — `RELAY_LIST[relayIdx % len]`
(`peer-channel.ts:1743`) — and only advances `relayIdx` on disconnect
(`scheduleReconnect`). Offline queues are **relay-local** (`relay.ts` `offlineQueues`).

Consequences the docs currently mis-sell as "failover":

- If two peers drift onto **different** relays, they silently cannot talk.
- Offline mail queued on relay A is stranded if the recipient reconnects to relay B.
- A relay outage costs a reconnect cycle (session teardown + re-auth) instead of being
  masked.

This is a correctness/partition hazard, not just a SPOF.

## Proposed design

Hold connections to **all** relays in `RELAY_LIST` at once and fan every outbound
frame to all of them. Rely on the mechanisms that already exist:

- **Dedup on receive:** `seenMsgIds` write-ahead dedup + the RFC 4303 sliding `seq`
  window (`peer-channel.ts` replay section) already collapse duplicate deliveries and
  re-ack them. N copies of the same signed frame → exactly one delivery.
- **Acks already idempotent:** a duplicate ack for an already-cleared outbox entry is a
  no-op (`handleAck` guards on `pendingAcks`).

### Changes

- `connectRelay()` → `connectAllRelays()`: maintain `Map<url, ws>` instead of a single
  `ws`. Each socket runs the existing challenge/auth/session bring-up independently
  (each gets its own ephemeral key + `session_id`? — see Open questions).
- `wsSend()` → write to every OPEN, authenticated socket.
- Inbound handler is unchanged: dedup already makes duplicate arrivals safe.
- Keep a **sticky primary** counter for display/room-discovery replies (pick the first
  OPEN socket) to avoid duplicate `myc_rooms` answers.

### Interim (smaller, ship first)

A **sticky-primary with N-failure advance**: only advance `relayIdx` after N
consecutive failures, and document the comma list as *cold failover* (current honest
behavior) until full fan-out lands.

## Open questions / risks

- **One `session_id` across relays vs one per socket.** The STS binding and the seq
  window are keyed by `session_id`. Simplest correct model: **one ephemeral session per
  socket** (distinct `session_id`), so a peer appears as N sessions and the receiver
  dedups by `msg_id` across them. This keeps the seq window sound per session. Validate
  that STS runs per socket without churn.
- **Ordering discontinuity.** Fan-out means a message can arrive first via the faster
  relay; the reorder/seq logic must treat cross-relay arrival as normal out-of-order
  (already handled within a session, must be confirmed across sessions).
- **Metadata amplification.** Fanning out to multiple **hosted** relays multiplies the
  who-talks-to-whom exposure. Prefer a self-hosted relay set; document this.
- **Rate limits × N.** Each relay counts the peer's messages; N relays ⇒ N× traffic.

## Test plan

- Two peers pinned to a 2-relay list; kill relay A mid-conversation → delivery continues
  with **zero** message loss and no reconnect gap (contrast current behavior).
- Partition test: force peer 1 → relay A only, peer 2 → relay B only; assert fan-out lets
  them talk; assert exactly-once (no duplicate deliveries) via the existing dedup.
- Offline drain: recipient reconnects to a *different* relay than the one that queued the
  mail → still delivered (requires either fan-out on send **or** cross-relay queue sync;
  fan-out-on-send is the in-scope answer).

## Non-goals

Cross-relay backplane / shared queue (that is the horizontal-scale item, a separate
managed-tier concern). This spec keeps relays independent and dumb; the client does the
fan-out.
