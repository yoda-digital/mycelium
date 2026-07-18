/**
 * Canonical message serialization — the single source of truth for the byte
 * string covered by frame signatures. peer-channel.ts signs/verifies this;
 * tests import it instead of re-implementing the field list (a drifted copy
 * would make tests pass against themselves rather than the protocol).
 */

// 11 fields, SORTED, ALL semantically meaningful fields covered.
// msg_id + seq are IN the canonical — relay can't mint new IDs for signed messages.
export function canonicalize(msg: any): string {
  return JSON.stringify({
    e2e: msg.e2e ?? null,
    encrypted: msg.encrypted ?? null,
    msg_id: msg.msg_id ?? null,     // signed — prevents relay replay with new IDs
    nonce: msg.nonce ?? null,
    payload: msg.payload ?? null,
    request_id: msg.request_id ?? null,
    sender: msg.sender ?? null,
    seq: msg.seq ?? null,           // signed — prevents relay seq manipulation
    session_id: msg.session_id ?? null,
    target: msg.target ?? null,
    type: msg.type ?? null,
  })
}
