#!/usr/bin/env bun
/**
 * Controlled-relay protocol regression tests. A real peer-channel.ts (bob) runs
 * against a mock relay we script, with a synthetic sender (alice) whose keys we hold,
 * so we can hand-craft byte-exact frames a real relay/peer could never be asked to
 * produce on demand:
 *
 *  1. Seq-poisoning (fixed v0.2.0): a forged bad-sig high-seq frame must not ratchet
 *     the replay floor and drop the real sender's future messages.
 *  2. Out-of-order tolerance (fixed v0.2.1): legitimately reordered frames inside the
 *     anti-replay window are delivered; exact replays are still dropped.
 *  3. Decrypt-failure surfacing (fixed v0.2.1): a verified-but-undecryptable frame
 *     notifies the model AND nacks the sender instead of vanishing into stderr.
 *  4. Relay error surfacing (fixed v0.2.1): relay 'error'/'queued' status frames reach
 *     the model instead of being swallowed.
 *  5. STS fail-closed (fixed v0.2.1): a wrong STS binding signature tears the session
 *     down and blocks the peer (possible MITM) instead of logging and carrying on.
 */
import { mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import sodium from 'libsodium-wrappers-sumo'
import { canonicalize } from './canonical.ts'
import { PeerProc, waitUntil } from './test-helpers.ts'

await sodium.ready
const toB64 = (x: Uint8Array) => sodium.to_base64(x, sodium.base64_variants.ORIGINAL)
const fromB64 = (s: string) => sodium.from_base64(s, sodium.base64_variants.ORIGINAL)

const PORT = 9903
const TOKEN = 'poison-' + Date.now()
const SCRATCH = mkdtempSync(join(tmpdir(), 'myc-poison-'))
let passed = 0, failed = 0
const assert = (c: boolean, n: string) => c ? (passed++, console.log(`  ✅ ${n}`)) : (failed++, console.error(`  ❌ ${n}`))

// Synthetic "alice" whose identity + ephemeral keys we (the malicious relay) hold.
const aliceSign = sodium.crypto_sign_keypair()
const aliceEph = sodium.crypto_box_keypair()
const aliceSid = 'alicesid00000000000000000000000a'
let bobEphPub: Uint8Array | null = null
let bobSock: any = null
const bobFrames: any[] = [] // every frame bob sends to the "relay" after auth

function signFrame(msg: any, sk: Uint8Array): string {
  return toB64(sodium.crypto_sign_detached(sodium.from_string(canonicalize(msg)), sk))
}

// Encrypted+signed frame from alice; `encKey` lets a test deliberately encrypt with a
// key bob does NOT share, producing a valid-sig / undecryptable frame.
function aliceFrame(text: string, seq: number, msgId: string, opts: {
  sign?: boolean; type?: string; encKey?: Uint8Array
} = {}): any {
  const shared = sodium.crypto_box_beforenm(bobEphPub!, opts.encKey ?? aliceEph.privateKey)
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES)
  const encrypted = toB64(sodium.crypto_box_easy_afternm(sodium.from_string(text), nonce, shared))
  const body: any = {
    from: 'alice', target: 'bob', type: opts.type ?? 'info', encrypted, nonce: toB64(nonce),
    e2e: true, sender: 'alice', session_id: aliceSid, payload: null, msg_id: msgId, seq,
  }
  body.sig = (opts.sign ?? true) ? signFrame(body, aliceSign.privateKey) : 'garbage-signature'
  return body
}

// Encrypt arbitrary text from alice to bob (for control frames like _nack/_sts_*).
function encTo(text: string): { encrypted: string; nonce: string } {
  const shared = sodium.crypto_box_beforenm(bobEphPub!, aliceEph.privateKey)
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES)
  return { encrypted: toB64(sodium.crypto_box_easy_afternm(sodium.from_string(text), nonce, shared)), nonce: toB64(nonce) }
}

// Mock malicious relay.
const relay = Bun.serve({
  port: PORT,
  fetch(req, server) { return server.upgrade(req) ? undefined : new Response('no', { status: 500 }) },
  websocket: {
    open(ws: any) {
      ws.send(JSON.stringify({ type: 'challenge', nonce: toB64(sodium.randombytes_buf(32)) }))
    },
    message(ws: any, raw: any) {
      const m = JSON.parse(typeof raw === 'string' ? raw : raw.toString())
      if (m.type === 'auth') {
        bobEphPub = fromB64(m.eph_enc_pubkey)
        bobSock = ws
        ws.send(JSON.stringify({
          type: 'auth_ok', from: '_relay',
          payload: { peer: 'bob', room: 'default', peers: {
            alice: {
              sign_pubkey: toB64(aliceSign.publicKey),
              eph_enc_pubkey: toB64(aliceEph.publicKey),
              eph_enc_pubkey_sig: toB64(sodium.crypto_sign_detached(aliceEph.publicKey, aliceSign.privateKey)),
              session_id: aliceSid,
            },
          } },
        }))
        return
      }
      bobFrames.push(m) // capture bob's outbound traffic (acks, nacks, STS replies…)
    },
  },
})

let bob!: PeerProc
try {
  console.log('\n🧪 P1: seq-poisoning (malicious relay forges a high-seq frame)')
  bob = new PeerProc({ name: 'bob', relayUrl: `ws://127.0.0.1:${PORT}`, token: TOKEN, scratchDir: SCRATCH })
  await bob.initialize()
  assert(await waitUntil(() => !!bobSock && !!bobEphPub, 6000), 'bob authenticated to the mock relay')
  assert(await waitUntil(() => bob.stderr.some(l => /Auth OK/.test(l)), 6000), 'bob established session with synthetic alice')
  await Bun.sleep(300)

  // 1) Malicious relay injects a FORGED (bad-sig) frame with a huge seq.
  bobSock.send(JSON.stringify(aliceFrame('POISON', Number.MAX_SAFE_INTEGER, 'forge-1', { sign: false })))
  await Bun.sleep(400)
  assert(bob.channelMsgs.every(m => m.content !== 'POISON'), 'forged bad-sig frame NOT delivered')
  assert(bob.stderr.some(l => /bad signature/.test(l)), 'forged frame rejected at signature check')

  // 2) A LEGITIMATE low-seq message from alice must still be delivered (seq not poisoned).
  bob.clear()
  bobSock.send(JSON.stringify(aliceFrame('LEGIT-AFTER-POISON', 1, 'legit-1')))
  const delivered = await waitUntil(() => bob.channelMsgs.some(m => m.content === 'LEGIT-AFTER-POISON'), 3000)
  assert(delivered, 'legitimate low-seq message delivered after the forged high-seq frame (seq floor not poisoned)')

  console.log('\n🔀 P2: out-of-order frames inside the window are delivered (not dropped as replays)')
  // v0.2.0 regression: strict `seq <= last` dropped every reordered frame pre-decryption.
  bob.clear()
  bobSock.send(JSON.stringify(aliceFrame('OOO-5', 5, 'ooo-5')))
  const replayed3 = aliceFrame('OOO-3', 3, 'ooo-3') // seq BELOW the just-advanced floor
  bobSock.send(JSON.stringify(replayed3))
  assert(await waitUntil(() => bob.channelMsgs.some(m => m.content === 'OOO-5'), 3000), 'newer frame (seq 5) delivered')
  assert(await waitUntil(() => bob.channelMsgs.some(m => m.content === 'OOO-3'), 3000), 'reordered older frame (seq 3 after 5) ALSO delivered')

  console.log('\n🔁 P3: an exact replay of a seen frame is dropped but RE-ACKED')
  // v0.3.0: a verified duplicate usually means the ack was lost — the receiver
  // must re-ack (so the sender's retransmission loop terminates) without
  // delivering twice.
  const acksBefore = bobFrames.filter(f => f.type === '_ack').length
  bobSock.send(JSON.stringify(replayed3)) // byte-identical resend
  await Bun.sleep(500)
  assert(bob.channelMsgs.filter(m => m.content === 'OOO-3').length === 1, 'replayed frame delivered exactly once')
  assert(bob.stderr.some(l => /Replay dedup: re-acked/.test(l)), 'replay logged as dedup + re-ack')
  assert(bobFrames.filter(f => f.type === '_ack').length > acksBefore, 'duplicate was re-acked (lost-ack recovery)')

  console.log('\n📭 P4: verified-but-undecryptable frame → model notified + sender nacked')
  // Valid alice signature over a ciphertext bob cannot open (stale-session simulation —
  // exactly what a relay-queued frame looks like after bob reconnects).
  bob.clear()
  const wrongKey = sodium.crypto_box_keypair()
  bobSock.send(JSON.stringify(aliceFrame('GARBLED', 6, 'garbled-1', { encKey: wrongKey.privateKey })))
  assert(await waitUntil(() => bobFrames.some(f => f.type === '_nack' && f.target === 'alice'), 3000), 'bob sent a _nack to the sender for a resend')
  assert(bob.channelMsgs.every(m => m.content !== 'GARBLED'), 'no attacker-controlled content surfaced')
  // v0.3.0: the model is NOT interrupted for a recoverable decrypt failure —
  // the nack triggers the sender's automatic retransmission. msg_id must NOT be
  // committed, or the same-id retransmission would be dedup-dropped unread.
  assert(bob.stderr.some(l => /decrypt failed.*nacking garbled-1/.test(l)), 'decrypt failure logged with the nacked msg_id')
  bobSock.send(JSON.stringify(aliceFrame('GARBLED-RETRY', 7, 'garbled-1'))) // same msg_id, decryptable
  assert(await waitUntil(() => bob.channelMsgs.some(m => m.content === 'GARBLED-RETRY'), 3000), 'same-msg_id retransmission after decrypt failure IS delivered (msg_id not burned)')

  console.log('\n📬 P4b: sender receiving a _nack retransmits AUTOMATICALLY (same msg_id)')
  // The other half of the loop: bob SENDS a tracked message, "alice" nacks it.
  // v0.3.0: instead of telling the model to resend, the outbox retransmits with
  // the SAME msg_id; the model hears nothing until confirmed delivery/terminal failure.
  bob.clear()
  await bob.callTool('myc_send', { target: 'alice', text: 'TO-BE-NACKED', type: 'info' })
  assert(await waitUntil(() => bobFrames.some(f => f.type === 'info' && f.target === 'alice' && f.msg_id), 3000), 'bob sent the tracked message')
  const sentFrame = bobFrames.filter(f => f.type === 'info' && f.target === 'alice').at(-1)
  const framesBeforeNack = bobFrames.filter(f => f.type === 'info' && f.msg_id === sentFrame.msg_id).length
  const nackEnc = encTo(`nack:${sentFrame.msg_id}`)
  bobSock.send(JSON.stringify({
    from: 'alice', target: 'bob', type: '_nack', encrypted: nackEnc.encrypted, nonce: nackEnc.nonce,
    e2e: true, sender: 'alice', session_id: aliceSid, payload: null, msg_id: 'nack-1', seq: 100,
  }))
  assert(await waitUntil(() => bobFrames.filter(f => f.type === 'info' && f.msg_id === sentFrame.msg_id).length > framesBeforeNack, 3000), 'nack triggered automatic retransmission with the SAME msg_id')
  assert(bob.stderr.some(l => new RegExp(`resent ${sentFrame.msg_id}`).test(l)), 'retransmission logged (model not interrupted)')
  // Close the loop: alice acks the retransmission → the model gets a delivery
  // confirmation (it had a deferred/retried send outstanding).
  const ackEnc = encTo(`ack:${sentFrame.msg_id}`)
  bobSock.send(JSON.stringify({
    from: 'alice', target: 'bob', type: '_ack', encrypted: ackEnc.encrypted, nonce: ackEnc.nonce,
    e2e: true, sender: 'alice', session_id: aliceSid, payload: null, msg_id: 'ack-1', seq: 101,
  }))
  assert(await waitUntil(() => bob.channelMsgs.some(m => m.meta?.type === 'delivered' && m.meta?.msg_id === sentFrame.msg_id), 3000), 'retried delivery confirmed to the model after the ack')

  console.log('\n📡 P5: relay error/queued status frames are surfaced, not swallowed')
  bob.clear()
  bobSock.send(JSON.stringify({ type: 'error', from: '_relay', payload: 'alice offline; queue full, message dropped', msg_id: 'drop-1' }))
  bobSock.send(JSON.stringify({ type: 'queued', from: '_relay', payload: 'alice offline', msg_id: 'q-1', ttl_s: 300 }))
  // 'error' for an UNTRACKED msg_id (nothing in the outbox to retry) surfaces to
  // the model; tracked ids feed the retransmission loop instead. 'queued' is
  // v0.3.0 log-only — the sender was told 📮 at send time.
  assert(await waitUntil(() => bob.channelMsgs.some(m => m.meta?.type === 'relay_error'), 3000), "relay 'error' frame surfaced to the model")
  assert(await waitUntil(() => bob.stderr.some(l => /Relay queued: alice offline/.test(l)), 3000), "relay 'queued' status logged (sender already told at send time)")

  console.log('\n🕵️ P6: wrong STS binding signature → fail-closed teardown (possible MITM)')
  // alice ('alice' < 'bob') is the STS initiator; bob responds. We complete the
  // handshake with a signature over the WRONG bytes — bob must tear down and block.
  bob.clear()
  const stsFrame = (type: string, payload: string, seq: number, msgId: string) => {
    const enc = encTo(payload)
    const body: any = {
      from: 'alice', target: 'bob', type, encrypted: enc.encrypted, nonce: enc.nonce,
      e2e: true, sender: 'alice', session_id: aliceSid, payload: null, msg_id: msgId, seq,
    }
    body.sig = signFrame(body, aliceSign.privateKey)
    return body
  }
  bobSock.send(JSON.stringify(stsFrame('_sts_init', JSON.stringify({ sts: 'init' }), 7, 'sts-i')))
  assert(await waitUntil(() => bobFrames.some(f => f.type === '_sts_reply'), 3000), 'bob (responder) replied to _sts_init')
  const wrongBindingSig = toB64(sodium.crypto_sign_detached(sodium.from_string('wrong-binding-bytes'), aliceSign.privateKey))
  bobSock.send(JSON.stringify(stsFrame('_sts_complete', JSON.stringify({ sts_sig: wrongBindingSig }), 8, 'sts-c')))
  assert(await waitUntil(() => bob.stderr.some(l => /STS VERIFICATION FAILED/.test(l)), 3000), 'bob logged STS verification failure')
  assert(await waitUntil(() => bob.channelMsgs.some(m => m.meta?.type === 'sts_failed'), 3000), 'MITM alert surfaced to the model')
  bob.clear()
  bobSock.send(JSON.stringify(aliceFrame('AFTER-STS-FAIL', 9, 'post-sts')))
  await Bun.sleep(600)
  assert(bob.channelMsgs.every(m => m.content !== 'AFTER-STS-FAIL'), 'messages from the STS-failed peer are BLOCKED (fail-closed)')
} catch (e) {
  console.error('\n💥 error:', e); failed++
} finally {
  try { bob?.kill() } catch {}
  try { relay.stop(true) } catch {}
  await Bun.sleep(120)
  try { rmSync(SCRATCH, { recursive: true, force: true }) } catch {}
  console.log(`\n${'='.repeat(50)}\nReplay-poison results: ${passed} passed, ${failed} failed\n${'='.repeat(50)}`)
  process.exit(failed > 0 ? 1 : 0)
}
