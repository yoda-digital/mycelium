#!/usr/bin/env bun
/**
 * Regression test for the seq-poisoning vulnerability (fixed in v0.2.0).
 *
 * Threat model: a MALICIOUS RELAY (which stamps `from`, so a peer cannot do this).
 * The relay injects a forged frame claiming to be from a real sender, with a garbage
 * signature and seq = MAX_SAFE_INTEGER. If replay/seq state were consumed BEFORE
 * signature verification, that one invisible (bad-sig, never-delivered) frame would
 * ratchet the monotonic seq floor and permanently drop the real sender's future
 * messages. The fix consults/commits replay state only AFTER verifySig succeeds.
 *
 * This test runs a real peer-channel.ts (bob) against a mock relay we control, with a
 * synthetic sender (alice) whose keys we hold, and asserts a legitimate low-seq message
 * is still delivered after the forged high-seq frame.
 */
import { mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import sodium from 'libsodium-wrappers-sumo'

await sodium.ready
const toB64 = (x: Uint8Array) => sodium.to_base64(x, sodium.base64_variants.ORIGINAL)
const fromB64 = (s: string) => sodium.from_base64(s, sodium.base64_variants.ORIGINAL)

const REPO = import.meta.dir
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

// Canonical signature identical to peer-channel.ts canonicalSign (11 sorted fields).
function canonicalSign(msg: any, sk: Uint8Array): string {
  const canonical = JSON.stringify({
    e2e: msg.e2e ?? null, encrypted: msg.encrypted ?? null, msg_id: msg.msg_id ?? null,
    nonce: msg.nonce ?? null, payload: msg.payload ?? null, request_id: msg.request_id ?? null,
    sender: msg.sender ?? null, seq: msg.seq ?? null, session_id: msg.session_id ?? null,
    target: msg.target ?? null, type: msg.type ?? null,
  })
  return toB64(sodium.crypto_sign_detached(sodium.from_string(canonical), sk))
}

function aliceFrame(text: string, seq: number, msgId: string, sign: boolean): any {
  const shared = sodium.crypto_box_beforenm(bobEphPub!, aliceEph.privateKey)
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES)
  const encrypted = toB64(sodium.crypto_box_easy_afternm(sodium.from_string(text), nonce, shared))
  const body: any = {
    from: 'alice', target: 'bob', type: 'info', encrypted, nonce: toB64(nonce),
    e2e: true, sender: 'alice', session_id: aliceSid, payload: null, msg_id: msgId, seq,
  }
  body.sig = sign ? canonicalSign(body, aliceSign.privateKey) : 'garbage-signature'
  return body
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
      }
      // ignore acks / everything else
    },
  },
})

// Minimal MCP stdio client for bob.
class Bob {
  proc: any; buf = ''; nextId = 1; pending = new Map<number, (v: any) => void>()
  channelMsgs: any[] = []; stderr: string[] = []
  constructor() {
    this.proc = Bun.spawn(['bun', 'run', 'peer-channel.ts'], {
      cwd: REPO,
      env: {
        ...process.env, MYC_RELAY: `ws://127.0.0.1:${PORT}`, MYC_TOKEN: TOKEN, MYC_PEER: 'bob',
        MYC_ROOM: 'default', MYC_KEY_FILE: join(SCRATCH, 'bob-keys.json'),
        MYC_TOFU_FILE: join(SCRATCH, 'bob-tofu.json'), MYC_REPLAY_FILE: join(SCRATCH, 'bob-replay.json'),
      },
      stdin: 'pipe', stdout: 'pipe', stderr: 'pipe',
    })
    this.readOut(); this.readErr()
  }
  async readOut() {
    const r = this.proc.stdout.getReader(); const d = new TextDecoder()
    while (true) { const { done, value } = await r.read(); if (done) break
      this.buf += d.decode(value, { stream: true }); let i
      while ((i = this.buf.indexOf('\n')) >= 0) {
        const line = this.buf.slice(0, i).trim(); this.buf = this.buf.slice(i + 1)
        if (!line) continue; let m: any; try { m = JSON.parse(line) } catch { continue }
        if (m.id !== undefined && this.pending.has(m.id)) { this.pending.get(m.id)!(m); this.pending.delete(m.id) }
        else if (m.method === 'notifications/claude/channel') this.channelMsgs.push(m.params)
      }
    }
  }
  async readErr() {
    const r = this.proc.stderr.getReader(); const d = new TextDecoder()
    while (true) { const { done, value } = await r.read(); if (done) break
      for (const l of d.decode(value, { stream: true }).split('\n')) if (l.trim()) this.stderr.push(l.trim()) }
  }
  send(o: any) { this.proc.stdin.write(JSON.stringify(o) + '\n'); this.proc.stdin.flush?.() }
  req(method: string, params: any): Promise<any> {
    const id = this.nextId++
    return new Promise(res => { this.pending.set(id, res); this.send({ jsonrpc: '2.0', id, method, params }) })
  }
  async init() {
    await this.req('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '1' } })
    this.send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} })
  }
  kill() { try { this.proc.kill() } catch {} }
}

async function waitUntil(fn: () => boolean, ms: number): Promise<boolean> {
  const s = Date.now(); while (Date.now() - s < ms) { if (fn()) return true; await Bun.sleep(50) } return fn()
}

let bob!: Bob
try {
  console.log('\n🧪 Seq-poisoning regression (malicious relay forges a high-seq frame)')
  bob = new Bob()
  await bob.init()
  assert(await waitUntil(() => !!bobSock && !!bobEphPub, 6000), 'bob authenticated to the mock relay')
  // Give bob time to process alice's keys and establish the session.
  assert(await waitUntil(() => bob.stderr.some(l => /Auth OK/.test(l)), 6000), 'bob established session with synthetic alice')
  await Bun.sleep(300)

  // 1) Malicious relay injects a FORGED (bad-sig) frame with a huge seq.
  bobSock.send(JSON.stringify(aliceFrame('POISON', Number.MAX_SAFE_INTEGER, 'forge-1', false)))
  await Bun.sleep(400)
  assert(bob.channelMsgs.every(m => m.content !== 'POISON'), 'forged bad-sig frame NOT delivered')
  assert(bob.stderr.some(l => /bad signature/.test(l)), 'forged frame rejected at signature check')

  // 2) A LEGITIMATE low-seq message from alice must still be delivered (seq not poisoned).
  bob.channelMsgs = []
  bobSock.send(JSON.stringify(aliceFrame('LEGIT-AFTER-POISON', 1, 'legit-1', true)))
  const delivered = await waitUntil(() => bob.channelMsgs.some(m => m.content === 'LEGIT-AFTER-POISON'), 3000)
  assert(delivered, 'legitimate low-seq message delivered after the forged high-seq frame (seq floor not poisoned)')
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
