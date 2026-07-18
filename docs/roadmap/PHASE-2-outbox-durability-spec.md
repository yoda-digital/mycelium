# Phase 2 — Peer outbox durability (the sender half of "exactly once")

**Status: PROPOSED (not implemented).** The *relay* half shipped
(`RELAY_QUEUE_FILE`, see CHANGELOG Unreleased + `test-durability.ts`). This is the
remaining **peer** half.

## Problem (grounded in code)

The peer outbox is an in-memory `Map` (`peer-channel.ts:893`, `outbox`). Every tracked
send lives there until acked; `trackAck`/`resendOutbox`/`flushOutbox` drive
retransmission. Nothing is persisted. So:

- A **peer restart** between send and ack evaporates the outbox → neither the
  `delivered` nor the `delivery_failed` notification (`peer-channel.ts` `handleAck` /
  `failOutbox`) ever fires. The README headline ("confirmed delivered or definitively
  failed", line ~37) is not crash-durable on the sender side.
- The replay/seen state IS already checkpointed (`saveReplay`/`loadWAL`,
  `peer-channel.ts:695-702`, `746`), so the persistence pattern exists — the outbox just
  isn't part of it.

## Proposed design (opt-in `MYC_OUTBOX_FILE`)

Persist the outbox to disk, **sealed to self** so plaintext is not written in the clear:

- On every `outbox.set` / `outbox.delete`, write `{ msgId → sealForIdentity(self,
  JSON(entry)) }` atomically (tmp + rename). `sealForIdentity` (`peer-channel.ts:516`)
  already exists; unseal with the identity key on load (`crypto_box_seal_open`,
  `peer-channel.ts:527`).
- On boot (after `loadWAL()`), load + unseal the outbox, re-insert entries, and let the
  existing `flushOutbox()` on relay connect drive retransmission (same `msg_id` ⇒
  receivers dedup, so recovery cannot double-deliver).
- Rebuild `pendingAcks` timers from the loaded entries (fresh `trackAck` per entry).

### Why sealed-to-self, not plaintext

The identity key is already on disk (optionally passphrase-encrypted). Sealing the
outbox to that key keeps the at-rest posture identical to the key file instead of adding
a new plaintext-message-at-rest surface. Default (unset) = today's in-memory behavior,
so there is no regression and no forced at-rest change.

## Risks / review points

- **Timer reconstruction:** on load, entries older than `OFFLINE_ACK_TIMEOUT_MS`
  (`peer-channel.ts:878`) should fire the timeout path immediately, not restart a full
  window.
- **Idempotency:** recovery re-sends with the original `msg_id`; confirm the receiver
  dedup (`seenMsgIds`) covers the cross-restart case (it persists via the replay WAL).
- **Write amplification:** the send hot path gains an atomic write; debounce or
  write-on-change only. Outbox is capped at `OUTBOX_MAX = 200`.
- **Fail-open on disk error:** a write failure must not break sending (log + continue),
  matching the relay `saveQueues` pattern.

## Test plan

Extend `test-durability.ts`: alice sends to an offline bob with `MYC_OUTBOX_FILE` set;
**kill and restart alice** (not the relay); on restart alice loads the outbox and, once
reconnected, retransmits; assert the eventual `delivered` (or, past the window,
`delivery_failed`) notification fires — i.e. the guarantee survives a *sender* crash.
Also assert the on-disk outbox contains no plaintext.
