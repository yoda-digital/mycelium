/**
 * Canonical message serialization — the single source of truth for the byte
 * string covered by frame signatures. peer-channel.ts signs/verifies this;
 * tests import it instead of re-implementing the field list (a drifted copy
 * would make tests pass against themselves rather than the protocol).
 *
 * v2 (proto 2) adds four fields with PRESENCE-CONDITIONAL inclusion:
 * `offline`, `proto`, `room`, `ts`. A field is covered iff it is present on
 * the message. This is strip/add-safe: removing a present field or adding an
 * absent one changes the canonical string, so the signature fails either way
 * (an attacker cannot forge the alternate form without the signing key).
 * Frames from 0.2.x peers carry none of the four and canonicalize exactly as
 * before, so verification of legacy frames is unchanged.
 */

// Keys stay SORTED: e2e, encrypted, msg_id, nonce, offline, payload, proto,
// request_id, room, sender, seq, session_id, target, ts, type.
// msg_id + seq are IN the canonical — relay can't mint new IDs for signed messages.
// room is IN the canonical — relay can't re-route a frame into another room.
// ts is IN the canonical — offline envelopes get a signed freshness bound.
export function canonicalize(msg: any): string {
  const o: Record<string, any> = {
    e2e: msg.e2e ?? null,
    encrypted: msg.encrypted ?? null,
    msg_id: msg.msg_id ?? null,     // signed — prevents relay replay with new IDs
    nonce: msg.nonce ?? null,
  }
  if (msg.offline !== undefined) o.offline = msg.offline
  o.payload = msg.payload ?? null
  if (msg.proto !== undefined) o.proto = msg.proto
  o.request_id = msg.request_id ?? null
  if (msg.room !== undefined) o.room = msg.room
  o.sender = msg.sender ?? null
  o.seq = msg.seq ?? null           // signed — prevents relay seq manipulation
  o.session_id = msg.session_id ?? null
  o.target = msg.target ?? null
  if (msg.ts !== undefined) o.ts = msg.ts
  o.type = msg.type ?? null
  return JSON.stringify(o)
}

/** Wire protocol version. Sent in challenge/auth/auth_ok and on every frame. */
export const PROTO = 2
