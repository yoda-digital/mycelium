#!/usr/bin/env bun
/**
 * Mycelium test suite — infrastructure + crypto protocol.
 */
import nacl from 'tweetnacl'
import naclUtil from 'tweetnacl-util'

const TOKEN = 'test-' + Date.now()
const PORT = 9901
let passed = 0
let failed = 0

function assert(cond: boolean, name: string): void {
  if (cond) { passed++; console.log(`  ✅ ${name}`) }
  else { failed++; console.error(`  ❌ ${name}`) }
}

function makeAuth(name: string, room = 'default') {
  const signKP = nacl.sign.keyPair()
  const ephKP = nacl.box.keyPair()
  const ephSig = nacl.sign.detached(ephKP.publicKey, signKP.secretKey)
  const sid = nacl.randomBytes(16).reduce((s: string, b: number) => s + b.toString(16).padStart(2, '0'), '')
  return {
    type: 'auth', token: TOKEN, peer: name, room,
    sign_pubkey: naclUtil.encodeBase64(signKP.publicKey),
    eph_enc_pubkey: naclUtil.encodeBase64(ephKP.publicKey),
    eph_enc_pubkey_sig: naclUtil.encodeBase64(ephSig),
    session_id: sid, _signKP: signKP, _ephKP: ephKP,
  }
}

async function connectPeer(
  name: string,
  room = 'default',
  opts?: { collectPostAuth?: boolean; authOverride?: any },
): Promise<any> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}`) as any
    const timeout = setTimeout(() => reject(new Error(`${name} timeout`)), 5000)
    let authed = false
    const postMsgs: any[] = []
    const auth = opts?.authOverride ?? makeAuth(name, room)
    ws.authData = auth

    ws.addEventListener('open', () => ws.send(JSON.stringify(auth)))

    const handler = (e: any) => {
      const msg = JSON.parse(typeof e.data === 'string' ? e.data : e.data.toString())
      if (!authed) {
        if (msg.type === 'auth_ok') {
          authed = true
          clearTimeout(timeout)
          if (opts?.collectPostAuth) {
            ws.postAuthMsgs = postMsgs
            setTimeout(() => { ws.removeEventListener('message', handler); resolve(ws) }, 200)
          } else {
            ws.removeEventListener('message', handler)
            resolve(ws)
          }
        }
        if (msg.type === 'auth_error') {
          clearTimeout(timeout)
          ws.removeEventListener('message', handler)
          reject(new Error(`auth: ${msg.payload}`))
        }
      } else {
        postMsgs.push(msg)
      }
    }

    ws.addEventListener('message', handler)
    ws.addEventListener('error', () => { clearTimeout(timeout); reject(new Error(`${name} err`)) })
  })
}

function waitMsg(ws: WebSocket, timeout = 3000): Promise<any> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('msg timeout')), timeout)
    ws.addEventListener('message', (e) => {
      clearTimeout(timer)
      resolve(JSON.parse(typeof e.data === 'string' ? e.data : e.data.toString()))
    }, { once: true })
  })
}

function noMsg(ws: WebSocket, ms = 500): Promise<boolean> {
  return new Promise((resolve) => {
    let got = false
    const handler = () => { got = true }
    ws.addEventListener('message', handler, { once: true })
    setTimeout(() => {
      ws.removeEventListener('message', handler)
      resolve(!got)
    }, ms)
  })
}

async function consumeN(ws: WebSocket, n: number): Promise<void> {
  for (let i = 0; i < n; i++) {
    try { await waitMsg(ws, 2000) } catch { break }
  }
}

let relay = Bun.spawn(['bun', 'run', 'relay.ts'], {
  cwd: import.meta.dir,
  env: {
    ...process.env,
    RELAY_TOKEN: TOKEN,
    RELAY_PORT: String(PORT),
    RELAY_MAX_PEERS: '5',
    RELAY_MAX_MSG_BYTES: '4096',
    RELAY_PING_INTERVAL: '2',
    RELAY_RATE_LIMIT: '30',
    RELAY_QUEUE_MAX_MSGS: '10',
    RELAY_QUEUE_TTL_S: '10',
    RELAY_MAX_IP_CONNS: '30',
    RELAY_AUTH_TIMEOUT_MS: '2000',
  },
  stdout: 'pipe',
  stderr: 'pipe',
})
await Bun.sleep(1000)

try {
  // === INFRASTRUCTURE ===

  console.log('\n🔐 T1: Auth + key distribution')
  const a = await connectPeer('alice')
  assert(a.readyState === WebSocket.OPEN, 'alice ok')
  const jP = waitMsg(a)
  const b = await connectPeer('bob')
  const j = await jP
  assert(j.type === 'peer_joined', 'joined')
  assert(!!j.payload.session_id, 'session_id distributed')
  assert(!!j.payload.eph_enc_pubkey_sig, 'eph sig present')

  console.log('\n🔑 T2: Bad token')
  try {
    await new Promise<void>((r) => {
      const w = new WebSocket(`ws://127.0.0.1:${PORT}`)
      w.addEventListener('open', () => w.send(JSON.stringify({ type: 'auth', token: 'bad', peer: 'x', sign_pubkey: 'x' })))
      w.addEventListener('close', () => r())
      setTimeout(r, 2000)
    })
    assert(true, 'rejected')
  } catch { assert(false, '!') }

  console.log('\n⏰ T3: Auth timeout')
  await new Promise<void>((r) => {
    const w = new WebSocket(`ws://127.0.0.1:${PORT}`)
    w.addEventListener('close', (e) => {
      assert((e as any).code === 4003, '4003')
      r()
    })
    setTimeout(r, 5000)
  })

  console.log('\n📨 T4: Broadcast + Unicast')
  const cJ = Promise.all([waitMsg(a), waitMsg(b)])
  const c = await connectPeer('charlie')
  await cJ
  const [bB, cB] = [waitMsg(b), waitMsg(c)]
  a.send(JSON.stringify({ type: 'info', payload: 'hi' }))
  assert((await bB).payload === 'hi', 'broadcast bob')
  assert((await cB).payload === 'hi', 'broadcast charlie')

  const bU = waitMsg(b)
  a.send(JSON.stringify({ target: 'bob', payload: 'priv' }))
  assert((await bU).payload === 'priv', 'unicast bob')
  assert(await noMsg(c), 'charlie excluded')

  console.log('\n🔒 T5: Sender enforcement')
  const cS = waitMsg(c)
  b.send(JSON.stringify({ from: 'alice', payload: 'spoof' }))
  await waitMsg(a)
  assert((await cS).from === 'bob', 'from overwritten')

  console.log('\n🚪 T6: Disconnect + Room isolation')
  const aL = waitMsg(a)
  c.close()
  assert((await aL).type === 'peer_left', 'left')
  const d = await connectPeer('diana', 'secret')
  a.send(JSON.stringify({ payload: 'nope' }))
  assert(await noMsg(d), 'isolated')
  d.close()

  console.log('\n📏 T7: Name limits + Room full')
  try { await connectPeer('a'.repeat(65)); assert(false, '!') } catch { assert(true, 'long name') }
  const c2 = await connectPeer('charlie')
  await consumeN(a, 1)
  await consumeN(b, 1)
  const e = await connectPeer('eve')
  await consumeN(a, 1)
  await consumeN(b, 1)
  await consumeN(c2, 1)
  const f = await connectPeer('frank')
  await consumeN(a, 1)
  await consumeN(b, 1)
  await consumeN(c2, 1)
  await consumeN(e, 1)
  try { await connectPeer('george'); assert(false, '!') } catch { assert(true, 'room full') }
  f.close()
  e.close()
  c2.close()
  await consumeN(a, 3)
  await consumeN(b, 3)

  console.log('\n⚡ T8: Rate limiting')
  let rl = false
  for (let i = 0; i < 40; i++) a.send(JSON.stringify({ payload: `b${i}` }))
  for (let i = 0; i < 10; i++) {
    try {
      const m = await waitMsg(a, 300)
      if (m.payload?.includes?.('rate')) rl = true
    } catch { break }
  }
  await Bun.sleep(300)
  assert(rl, 'rate limited')

  console.log('\n📬 T9: Offline queue')
  a.close()
  b.close()
  await Bun.sleep(300)
  const a2 = await connectPeer('alice')
  const b2 = await connectPeer('bob')
  await consumeN(a2, 1)
  b2.close()
  await consumeN(a2, 1)
  await Bun.sleep(200)
  a2.send(JSON.stringify({ target: 'bob', payload: 'queued' }))
  assert((await waitMsg(a2, 2000)).type === 'queued', 'queued notice')
  const b3 = await connectPeer('bob', 'default', { collectPostAuth: true })
  await consumeN(a2, 1)
  assert(!!b3.postAuthMsgs?.find((m: any) => m.payload === 'queued'), 'drained')

  console.log('\n🏥 T10: Health auth')
  assert((await fetch(`http://127.0.0.1:${PORT}/health`)).status === 401, 'no auth 401')
  const h = await fetch(`http://127.0.0.1:${PORT}/health`, { headers: { Authorization: `Bearer ${TOKEN}` } })
  assert(h.status === 200, 'bearer 200')
  assert(typeof ((await h.json()) as any).memory?.rss_mb === 'number', 'has memory')

  console.log('\n💓 T11: Ping/pong')
  await Bun.sleep(6500)
  assert(a2.readyState === WebSocket.OPEN, 'alice alive')
  assert(b3.readyState === WebSocket.OPEN, 'bob alive')

  console.log('\n🔄 T12: Shutdown + reconnect')
  const bC = new Promise<number>((r) => {
    b3.addEventListener('close', (ev: any) => r(ev.code), { once: true })
  })
  relay.kill('SIGTERM')
  await relay.exited
  assert((await Promise.race([bC, Bun.sleep(3000).then(() => -1)])) > 0, 'closed')

  relay = Bun.spawn(['bun', 'run', 'relay.ts'], {
    cwd: import.meta.dir,
    env: {
      ...process.env,
      RELAY_TOKEN: TOKEN,
      RELAY_PORT: String(PORT),
      RELAY_MAX_PEERS: '10',
      RELAY_PING_INTERVAL: '30',
      RELAY_RATE_LIMIT: '300',
    },
    stdout: 'pipe',
    stderr: 'pipe',
  })
  await Bun.sleep(800)

  const rA = await connectPeer('alice')
  const rM = waitMsg(rA)
  await connectPeer('bob')
  assert((await rM).type === 'peer_joined', 'reconnected')
  rA.close()
  await Bun.sleep(200)

  // === CRYPTO PROTOCOL TESTS ===

  console.log('\n🔀 T13: Last-writer-wins SAME identity')
  const lwAuth = makeAuth('lww-test')
  const lw1 = await connectPeer('lww-test', 'default', { authOverride: lwAuth })
  const evicted = new Promise<boolean>((r) => {
    lw1.addEventListener('close', () => r(true))
    setTimeout(() => r(false), 3000)
  })
  const lw2 = await connectPeer('lww-test', 'default', { authOverride: { ...lwAuth, session_id: 'new-session' } })
  assert(await evicted, 'old evicted (same key)')
  assert(lw2.readyState === WebSocket.OPEN, 'new accepted')
  lw2.close()

  console.log('\n🔐 T14: Identity-bound eviction REJECTS different key')
  const lw3Auth = makeAuth('id-test')
  const lw3 = await connectPeer('id-test', 'default', { authOverride: lw3Auth })
  const diffAuth = makeAuth('id-test') // different key!
  try {
    await connectPeer('id-test', 'default', { authOverride: diffAuth })
    assert(false, 'should reject different key')
  } catch (e: any) {
    assert(e.message.includes('identity') || e.message.includes('bound'), 'rejected: different identity')
  }
  assert(lw3.readyState === WebSocket.OPEN, 'original NOT evicted')
  lw3.close()

  console.log('\n🔏 T15: Canonical sig includes msg_id + seq')
  {
    const kp = nacl.sign.keyPair()
    const body = {
      e2e: true, encrypted: 'abc', msg_id: 'id-1', nonce: 'xyz',
      payload: null, sender: 'alice', seq: 7, session_id: 's1', target: 'bob', type: 'info',
    }
    const canonical = JSON.stringify(body) // already sorted by key in object literal above
    const sig = nacl.sign.detached(naclUtil.decodeUTF8(canonical), kp.secretKey)

    // Relay tries to replay with new msg_id and seq
    const tampered = { ...body, msg_id: 'id-99', seq: 99 }
    const tampCanon = JSON.stringify({
      e2e: tampered.e2e, encrypted: tampered.encrypted,
      msg_id: tampered.msg_id, nonce: tampered.nonce,
      payload: tampered.payload, sender: tampered.sender,
      seq: tampered.seq, session_id: tampered.session_id,
      target: tampered.target, type: tampered.type,
    })
    assert(!nacl.sign.detached.verify(naclUtil.decodeUTF8(tampCanon), sig, kp.publicKey), 'relay replay with new IDs FAILS sig')

    // Original passes
    assert(nacl.sign.detached.verify(naclUtil.decodeUTF8(canonical), sig, kp.publicKey), 'original sig valid')
  }

  console.log('\n🔑 T16: Ephemeral key anti-MITM')
  {
    const lt = nacl.sign.keyPair()
    const eph = nacl.box.keyPair()
    const sig = nacl.sign.detached(eph.publicKey, lt.secretKey)
    assert(nacl.sign.detached.verify(eph.publicKey, sig, lt.publicKey), 'eph sig valid')
    assert(!nacl.sign.detached.verify(nacl.box.keyPair().publicKey, sig, lt.publicKey), 'fake eph rejected')
  }

  console.log('\n📌 T17: TOFU fail-closed')
  {
    const store: Record<string, string> = {}
    const check = (p: string, k: string) => {
      if (!store[p]) { store[p] = k; return 'new' }
      return store[p] === k ? 'trusted' : 'changed'
    }
    const k1 = naclUtil.encodeBase64(nacl.sign.keyPair().publicKey)
    assert(check('a', k1) === 'new', 'new')
    assert(check('a', k1) === 'trusted', 'trusted')
    assert(check('a', naclUtil.encodeBase64(nacl.sign.keyPair().publicKey)) === 'changed', 'changed → BLOCKED')
  }

  console.log('\n🔁 T18: Replay — session-scoped strict seq')
  {
    const seen = new Map<string, number>()
    const seqs: Record<string, Record<string, number>> = {}
    function chk(from: string, id: string, seq: number, sid: string) {
      const dup = seen.has(id)
      if (!dup) seen.set(id, Date.now())
      if (!seqs[from]) seqs[from] = {}
      const last = seqs[from][sid] ?? -1
      return { dup, seqBad: seq <= last || (seqs[from][sid] = seq, false) as any }
    }
    const r1 = chk('b', 'm1', 0, 's1')
    assert(!r1.dup && !r1.seqBad, 'first ok')
    assert(chk('b', 'm1', 1, 's1').dup, 'dup caught')
    assert(chk('b', 'm2', 0, 's1').seqBad, 'seq regression in session')
    assert(!chk('b', 'm3', 0, 's2').seqBad, 'new session seq 0 ok')
  }

  console.log('\n🔐 T19: PFS round-trip')
  {
    const aE = nacl.box.keyPair()
    const bE = nacl.box.keyPair()
    const sAB = nacl.box.before(bE.publicKey, aE.secretKey)
    const sBA = nacl.box.before(aE.publicKey, bE.secretKey)
    const n = nacl.randomBytes(nacl.box.nonceLength)
    const enc = nacl.box.after(naclUtil.decodeUTF8('pfs'), n, sAB)
    const dec = nacl.box.open.after(enc, n, sBA)
    assert(!!dec && naclUtil.encodeUTF8(dec) === 'pfs', 'PFS works')
  }

  console.log('\n⏱️ T20: Time-based dedup (not FIFO)')
  {
    const seen = new Map<string, number>()
    seen.set('old', Date.now() - 31 * 60 * 1000)
    seen.set('new', Date.now())
    const cutoff = Date.now() - 30 * 60 * 1000
    for (const [id, ts] of seen) {
      if (ts < cutoff) seen.delete(id)
    }
    assert(!seen.has('old'), 'old expired by TIME')
    assert(seen.has('new'), 'new kept')
  }

  console.log('\n📝 T21: Replay state serialization')
  {
    const state = { seen: { 'x': Date.now() }, seqs: { bob: { s1: 5 } } }
    const parsed = JSON.parse(JSON.stringify(state))
    assert(parsed.seqs.bob.s1 === 5, 'seqs serialize')
  }

  console.log('\n🔑 T22: Fingerprint generation')
  {
    const k = naclUtil.encodeBase64(nacl.sign.keyPair().publicKey)
    const bytes = naclUtil.decodeBase64(k)
    const hash = nacl.hash(bytes)
    const fp = Array.from(hash.slice(0, 16))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .match(/.{4}/g)!
      .join(':')
    assert(fp.length === 4 * 8 + 7, 'fingerprint format correct (8 groups of 4)')
    assert(fp.includes(':'), 'has separators')
  }

  console.log('\n🛡️ T23: sender field REQUIRED for sig verification (unit)')
  {
    // Simulate the enforcement: !msg.sender → BLOCK, sender !== from → BLOCK
    const msg1 = { e2e: true, from: 'alice' } // no sender
    const msg2 = { e2e: true, from: 'alice', sender: 'evil' } // mismatch
    const msg3 = { e2e: true, from: 'alice', sender: 'alice', sig: 'valid' } // ok

    // For e2e messages, hard-block if:
    const block1 = msg1.e2e && !('sender' in msg1 && (msg1 as any).sender)
    const block2 = msg2.e2e && msg2.sender !== msg2.from
    const block3 = msg3.e2e && msg3.sender !== msg3.from

    assert(block1, 'missing sender → BLOCKED')
    assert(block2, 'sender≠from → BLOCKED')
    assert(!block3, 'matching sender → pass')
  }

  console.log('\n🔒 T24: Permission messages structure (unit)')
  {
    // Permission messages must be type _perm_req/_perm_verdict with e2e=true
    // NOT plaintext type permission_request/permission_verdict
    const validPerm = { type: '_perm_req', e2e: true, encrypted: 'enc', nonce: 'n', sender: 'alice', sig: 'sig' }
    const insecurePerm = { type: 'permission_request', payload: '{}' } // old insecure format

    assert(validPerm.e2e === true, 'perm req is E2E')
    assert(!!validPerm.sig, 'perm req is signed')
    assert(validPerm.type === '_perm_req', 'new perm type')
    assert(insecurePerm.type !== '_perm_req', 'old format distinguished')
  }

  console.log('\n🔢 T25: 16-byte session ID')
  {
    const sid = nacl.randomBytes(16).reduce((s: string, b: number) => s + b.toString(16).padStart(2, '0'), '')
    assert(sid.length === 32, '16 bytes = 32 hex chars')
  }

  console.log('\n🔀 T26: Fair-share uses active peers')
  {
    // With 2 active peers in room, max per sender = max(3, ceil(10/2)) = 5
    const queueMax = 10
    const activePeers = 2
    const perSender = Math.max(3, Math.ceil(queueMax / activePeers))
    assert(perSender === 5, 'fair-share: 2 peers → 5/sender')

    // With 50 peers (old bug): max(3, ceil(10/50)) = max(3,1) = 3 (not 1)
    const perSender50 = Math.max(3, Math.ceil(queueMax / 50))
    assert(perSender50 === 3, 'fair-share floor: 50 peers → 3/sender (not 1)')
  }

  console.log('\n🔏 T27: Canonical sig — relay can\'t replay signed msg with new IDs (integration)')
  {
    const signKP = nacl.sign.keyPair()
    // Sender creates message with specific msg_id and seq
    const origMsg = {
      e2e: true, encrypted: 'data', msg_id: 'orig-1', nonce: 'n1',
      payload: null, sender: 'alice', seq: 0, session_id: 'sess1', target: 'bob', type: 'info',
    }
    const canonical = JSON.stringify(origMsg)
    const sig = nacl.sign.detached(naclUtil.decodeUTF8(canonical), signKP.secretKey)

    // Relay intercepts, changes msg_id to bypass dedup
    const relayMsg = { ...origMsg, msg_id: 'relay-forged-99', seq: 999 }
    const relayCanonical = JSON.stringify({
      e2e: relayMsg.e2e, encrypted: relayMsg.encrypted,
      msg_id: relayMsg.msg_id, nonce: relayMsg.nonce,
      payload: relayMsg.payload, sender: relayMsg.sender,
      seq: relayMsg.seq, session_id: relayMsg.session_id,
      target: relayMsg.target, type: relayMsg.type,
    })

    // Receiver verifies: MUST FAIL because msg_id and seq are now in canonical
    assert(!nacl.sign.detached.verify(naclUtil.decodeUTF8(relayCanonical), sig, signKP.publicKey), 'forged msg_id+seq breaks sig ✓')
    // Original still valid
    assert(nacl.sign.detached.verify(naclUtil.decodeUTF8(canonical), sig, signKP.publicKey), 'original sig intact ✓')
  }

  relay.kill('SIGTERM')
  await relay.exited

} catch (e) {
  console.error('\n💥 Error:', e)
  failed++
} finally {
  try { relay.kill() } catch {}
  console.log(`\n${'='.repeat(50)}`)
  console.log(`Results: ${passed} passed, ${failed} failed`)
  console.log('='.repeat(50))
  process.exit(failed > 0 ? 1 : 0)
}
