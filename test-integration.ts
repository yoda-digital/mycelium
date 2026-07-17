#!/usr/bin/env bun
/**
 * Mycelium END-TO-END integration test.
 *
 * Unlike test.ts (relay behaviour + protocol units), this spawns TWO REAL
 * peer-channel.ts MCP processes talking through a real relay, drives them over
 * MCP stdio, and asserts *actual message delivery*. This is the coverage whose
 * absence let a total delivery failure (STS handshake collision) ship green in
 * v0.1.x: both peers logged "STS VERIFICATION FAILED" and every send returned
 * 🔴BLOCKED, yet 75 unit tests passed because none ran two peers together.
 */
import { mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import sodium from 'libsodium-wrappers-sumo'

await sodium.ready
const toB64 = (x: Uint8Array) => sodium.to_base64(x, sodium.base64_variants.ORIGINAL)

const REPO = import.meta.dir
const PORT = 9902
const TOKEN = 'itest-' + Date.now()
const SCRATCH = mkdtempSync(join(tmpdir(), 'myc-itest-'))

let passed = 0
let failed = 0
function assert(cond: boolean, name: string): void {
  if (cond) { passed++; console.log(`  ✅ ${name}`) }
  else { failed++; console.error(`  ❌ ${name}`) }
}

// --- MCP stdio client over a spawned peer-channel process ---
class Peer {
  proc: any
  name: string
  private buf = ''
  private nextId = 1
  private pending = new Map<number, (v: any) => void>()
  channelMsgs: any[] = []
  stderr: string[] = []

  constructor(name: string) {
    this.name = name
    this.proc = Bun.spawn(['bun', 'run', 'peer-channel.ts'], {
      cwd: REPO,
      env: {
        ...process.env,
        MYC_RELAY: `ws://127.0.0.1:${PORT}`,
        MYC_TOKEN: TOKEN,
        MYC_PEER: name,
        MYC_ROOM: 'default',
        MYC_KEY_FILE: join(SCRATCH, `${name}-keys.json`),
        MYC_TOFU_FILE: join(SCRATCH, `${name}-tofu.json`),
        MYC_REPLAY_FILE: join(SCRATCH, `${name}-replay.json`),
      },
      stdin: 'pipe', stdout: 'pipe', stderr: 'pipe',
    })
    this.readStdout()
    this.readStderr()
  }

  private async readStdout(): Promise<void> {
    const reader = this.proc.stdout.getReader()
    const dec = new TextDecoder()
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      this.buf += dec.decode(value, { stream: true })
      let idx: number
      while ((idx = this.buf.indexOf('\n')) >= 0) {
        const line = this.buf.slice(0, idx).trim()
        this.buf = this.buf.slice(idx + 1)
        if (!line) continue
        let msg: any
        try { msg = JSON.parse(line) } catch { continue }
        if (msg.id !== undefined && this.pending.has(msg.id)) {
          this.pending.get(msg.id)!(msg)
          this.pending.delete(msg.id)
        } else if (msg.method === 'notifications/claude/channel') {
          this.channelMsgs.push(msg.params)
        }
      }
    }
  }

  private async readStderr(): Promise<void> {
    const reader = this.proc.stderr.getReader()
    const dec = new TextDecoder()
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      for (const l of dec.decode(value, { stream: true }).split('\n')) {
        if (l.trim()) this.stderr.push(l.trim())
      }
    }
  }

  private send(obj: any): void { this.proc.stdin.write(JSON.stringify(obj) + '\n'); this.proc.stdin.flush?.() }

  request(method: string, params: any): Promise<any> {
    const id = this.nextId++
    return new Promise((resolve) => {
      this.pending.set(id, resolve)
      this.send({ jsonrpc: '2.0', id, method, params })
    })
  }

  async initialize(): Promise<void> {
    await this.request('initialize', {
      protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'itest', version: '1.0.0' },
    })
    this.send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} })
  }

  callTool(name: string, args: any): Promise<any> { return this.request('tools/call', { name, arguments: args }) }
  toolText(res: any): string { return res?.result?.content?.[0]?.text ?? '' }
  stderrHas(re: RegExp): boolean { return this.stderr.some(l => re.test(l)) }
  from(peer: string): any[] { return this.channelMsgs.filter(m => m.meta?.from_peer === peer) }
  clear(): void { this.channelMsgs = [] }
  kill(): void { try { this.proc.kill() } catch {} }
}

async function waitUntil(fn: () => boolean, timeoutMs: number, stepMs = 50): Promise<boolean> {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    if (fn()) return true
    await Bun.sleep(stepMs)
  }
  return fn()
}

// A raw relay client (not a peer-channel) that authenticates via challenge-response and
// sends attacker-chosen frames — used to prove receiver-side hard-blocks.
function rawInject(name: string, room: string, frame: any): Promise<void> {
  return new Promise((resolve, reject) => {
    const signKP = sodium.crypto_sign_keypair()
    const ephKP = sodium.crypto_box_keypair()
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}`)
    const t = setTimeout(() => { try { ws.close() } catch {}; reject(new Error('rawInject timeout')) }, 5000)
    ws.addEventListener('message', (e: any) => {
      const m = JSON.parse(typeof e.data === 'string' ? e.data : e.data.toString())
      if (m.type === 'challenge') {
        const nonce = sodium.from_base64(m.nonce, sodium.base64_variants.ORIGINAL)
        const sigData = new Uint8Array([...nonce, ...sodium.from_string(name), ...sodium.from_string(room)])
        ws.send(JSON.stringify({
          type: 'auth', token: TOKEN, peer: name, room,
          sign_pubkey: toB64(signKP.publicKey),
          eph_enc_pubkey: toB64(ephKP.publicKey),
          eph_enc_pubkey_sig: toB64(sodium.crypto_sign_detached(ephKP.publicKey, signKP.privateKey)),
          session_id: 'raw-sid',
          challenge_sig: toB64(sodium.crypto_sign_detached(sigData, signKP.privateKey)),
        }))
      } else if (m.type === 'auth_ok') {
        ws.send(JSON.stringify(frame))
        setTimeout(() => { try { ws.close() } catch {}; clearTimeout(t); resolve() }, 300)
      } else if (m.type === 'auth_error') {
        clearTimeout(t); try { ws.close() } catch {}; reject(new Error('auth: ' + m.payload))
      }
    })
    ws.addEventListener('error', () => { clearTimeout(t); reject(new Error('ws err')) })
  })
}

const relay = Bun.spawn(['bun', 'run', 'relay.ts'], {
  cwd: REPO,
  env: {
    ...process.env,
    RELAY_TOKEN: TOKEN,
    RELAY_PORT: String(PORT),
    RELAY_KEY_FILE: join(SCRATCH, 'relay-keys.json'),
    RELAY_ALLOW_FILE: join(SCRATCH, 'relay-allow.json'),
  },
  stdout: 'pipe', stderr: 'pipe',
})

let alice!: Peer
let bob!: Peer
try {
  await Bun.sleep(900)

  console.log('\n🌱 IT1: two real peers authenticate + STS mutually verify')
  alice = new Peer('alice')
  await alice.initialize()
  bob = new Peer('bob')
  await bob.initialize()

  assert(await waitUntil(() => alice.stderrHas(/Auth OK/) && bob.stderrHas(/Auth OK/), 6000), 'both peers authenticated to relay')
  const stsOk = await waitUntil(() => alice.stderrHas(/STS verified/) && bob.stderrHas(/STS verified/), 6000)
  assert(stsOk, 'STS mutually verified (no false MITM, session intact)')
  assert(!alice.stderrHas(/STS VERIFICATION FAILED|STS mismatch/) && !bob.stderrHas(/STS VERIFICATION FAILED|STS mismatch/), 'no STS teardown on either side')

  console.log('\n📩 IT2: unicast delivers exactly one decrypted copy')
  bob.clear()
  const sendRes = alice.toolText(await alice.callTool('myc_send', { target: 'bob', text: 'HELLO-UNICAST', type: 'info' }))
  assert(sendRes.includes('🔒') && !sendRes.includes('BLOCKED'), `send accepted (${sendRes.trim()})`)
  await waitUntil(() => bob.from('alice').length >= 1, 3000)
  const uni = bob.from('alice')
  assert(uni.length === 1, `bob got exactly 1 unicast (got ${uni.length})`)
  assert(uni[0]?.content === 'HELLO-UNICAST', 'unicast decrypted to correct plaintext')
  assert(uni[0]?.meta?.e2e === 'encrypted', 'unicast delivered E2E-encrypted')

  console.log('\n📢 IT3: broadcast delivers exactly one decryptable copy (no fan-out spam)')
  bob.clear()
  await alice.callTool('myc_broadcast', { text: 'HELLO-BCAST', type: 'info' })
  await waitUntil(() => bob.from('alice').length >= 1, 3000)
  await Bun.sleep(400) // allow any erroneous extra copies to arrive
  const bc = bob.from('alice')
  assert(bc.length === 1, `bob got exactly 1 broadcast copy (got ${bc.length})`)
  assert(bc.every(m => !String(m.content).includes('Decrypt failed')), 'zero decrypt-failure copies from broadcast')
  assert(bc[0]?.content === 'HELLO-BCAST', 'broadcast decrypted to correct plaintext')

  console.log('\n🔁 IT4: bidirectional — reply path works')
  alice.clear()
  await bob.callTool('myc_send', { target: 'alice', text: 'REPLY-OK', type: 'response' })
  await waitUntil(() => alice.from('bob').length >= 1, 3000)
  const rep = alice.from('bob')
  assert(rep.length === 1 && rep[0]?.content === 'REPLY-OK', 'alice received bob\'s reply, decrypted')

  console.log('\n🚦 IT5: burst ordering — 20 rapid messages, none dropped, in order')
  // Regression guard for the removed reorder buffer, which silently dropped
  // messages whose seq did not start contiguously from 0.
  bob.clear()
  const N = 20
  for (let i = 0; i < N; i++) await alice.callTool('myc_send', { target: 'bob', text: `burst-${i}`, type: 'info' })
  const got = await waitUntil(() => bob.from('alice').length >= N, 6000)
  const burst = bob.from('alice').map(m => m.content)
  assert(got && burst.length === N, `all ${N} burst messages delivered (got ${burst.length})`)
  const inOrder = burst.every((c, i) => c === `burst-${i}`)
  assert(inOrder, 'burst messages delivered in order with no gaps/drops')

  console.log('\n🤝 IT6: myc_peers reflects encrypted + STS-verified status')
  const peersTxt = alice.toolText(await alice.callTool('myc_peers', {}))
  assert(/bob/.test(peersTxt) && !/BLOCKED/.test(peersTxt), 'peers list shows bob, not blocked')
  assert(/🤝/.test(peersTxt), 'peers list shows STS handshake (🤝)')

  console.log('\n🧹 IT7: no duplicate deliveries observed across the burst')
  const uniqueContents = new Set(bob.from('alice').map(m => m.content))
  assert(uniqueContents.size === bob.from('alice').length, 'no duplicate deliveries observed')

  console.log('\n🛡️ IT8: unauthenticated plaintext injection is hard-blocked')
  // A raw authenticated relay client sends a NON-e2e frame to bob. bob must refuse to
  // surface it (v0.1.x delivered non-e2e frames verbatim, bypassing all sig checks).
  bob.clear()
  await rawInject('mallory', 'default', { target: 'bob', type: 'info', payload: 'INJECTED-PLAINTEXT' })
  await Bun.sleep(700)
  const injected = bob.channelMsgs.filter(m => String(m.content).includes('INJECTED-PLAINTEXT'))
  assert(injected.length === 0, 'plaintext injection not delivered to the model')
  assert(bob.stderrHas(/non-E2E peer message/), 'receiver logged the block')

} catch (e) {
  console.error('\n💥 Integration error:', e)
  failed++
} finally {
  try { alice?.kill() } catch {}
  try { bob?.kill() } catch {}
  try { relay.kill() } catch {}
  await Bun.sleep(150)
  try { rmSync(SCRATCH, { recursive: true, force: true }) } catch {}
  console.log(`\n${'='.repeat(50)}`)
  console.log(`Integration results: ${passed} passed, ${failed} failed`)
  console.log('='.repeat(50))
  process.exit(failed > 0 ? 1 : 0)
}
