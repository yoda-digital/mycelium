#!/usr/bin/env bun
/**
 * Mycelium DURABILITY test — crash-recovery of the offline queue.
 *
 * The headline guarantee ("a deferred send: confirmed delivered or definitively
 * failed") is only real if it survives a restart. This spawns a real relay with
 * RELAY_QUEUE_FILE set, queues an offline message, then KILLS THE SENDER (so its
 * outbox cannot retransmit) and RESTARTS THE RELAY — leaving the persisted queue
 * as the *only* path by which the message can still reach the recipient. That is
 * the "ephemeral agent" scenario from the audit: sender gone, relay bounced.
 *
 * Without RELAY_QUEUE_FILE this message would be lost. With it, it is delivered.
 */
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { PeerProc, waitUntil } from './test-helpers.ts'

const REPO = import.meta.dir
const PORT = 9903
const TOKEN = 'dur-' + Date.now()
const RELAY_URL = `ws://127.0.0.1:${PORT}`
const SCRATCH = mkdtempSync(join(tmpdir(), 'myc-dur-'))
const QUEUE_FILE = join(SCRATCH, 'relay-queue.json')

let passed = 0
let failed = 0
function assert(cond: boolean, name: string): void {
  if (cond) { passed++; console.log(`  ✅ ${name}`) }
  else { failed++; console.error(`  ❌ ${name}`) }
}

const relayEnv = {
  ...process.env,
  RELAY_TOKEN: TOKEN,
  RELAY_PORT: String(PORT),
  RELAY_KEY_FILE: join(SCRATCH, 'relay-keys.json'),
  RELAY_ALLOW_FILE: join(SCRATCH, 'relay-allow.json'),
  RELAY_QUEUE_FILE: QUEUE_FILE,
}
function spawnRelay(): any {
  return Bun.spawn(['bun', 'run', 'relay.ts'], { cwd: REPO, env: relayEnv, stdout: 'pipe', stderr: 'pipe' })
}
function spawnPeer(name: string): PeerProc {
  return new PeerProc({ name, relayUrl: RELAY_URL, token: TOKEN, scratchDir: SCRATCH })
}

let relay = spawnRelay()
let alice: PeerProc | undefined
let bob: PeerProc | undefined
try {
  await Bun.sleep(900)

  console.log('\n🌱 D1: alice + bob meet (alice pins bob so she can seal offline mail to him)')
  alice = spawnPeer('alice')
  await alice.initialize()
  bob = spawnPeer('bob')
  await bob.initialize()
  assert(await waitUntil(() => !!alice!.stderrHas(/Auth OK/) && !!bob!.stderrHas(/Auth OK/), 6000), 'both peers authenticated')
  assert(await waitUntil(() => !!alice!.stderrHas(/STS verified/), 6000), 'alice established + pinned bob')

  console.log('\n📴 D2: bob goes offline, alice sends an offline (identity-sealed) message')
  bob.kill()
  await Bun.sleep(1200) // let the relay observe bob leave so alice picks the offline path
  const sendTxt = alice.toolText(await alice.callTool('myc_send', { target: 'bob', text: 'DURABLE-PAYLOAD' }))
  assert(/queued for offline delivery/.test(sendTxt), `alice queued an offline envelope (${sendTxt.trim()})`)
  await Bun.sleep(500)

  console.log('\n💾 D3: the offline queue is persisted to disk (ciphertext only)')
  assert(existsSync(QUEUE_FILE), 'RELAY_QUEUE_FILE was written')
  const persisted = existsSync(QUEUE_FILE) ? readFileSync(QUEUE_FILE, 'utf8') : ''
  assert(/"queues"/.test(persisted) && persisted.length > 40, 'queue file holds the queued envelope')
  assert(!/DURABLE-PAYLOAD/.test(persisted), 'plaintext is NOT present on disk (only ciphertext is persisted)')

  console.log('\n☠️  D4: the SENDER is killed (its outbox can no longer retransmit)')
  alice.kill()
  await Bun.sleep(500)

  console.log('\n🔁 D5: the relay CRASHES and restarts — only the persisted queue remains')
  relay.kill()
  await relay.exited
  await Bun.sleep(400)
  relay = spawnRelay()
  await Bun.sleep(1200)
  // The restored count is visible on /health (loopback-authorized, no token needed).
  const health: any = await (await fetch(`http://127.0.0.1:${PORT}/health`)).json()
  assert((health?.offline_queues ?? 0) >= 1, `relay restored the queue from disk on boot (offline_queues=${health?.offline_queues})`)

  console.log('\n📬 D6: bob returns and receives the message that outlived both the sender AND the relay restart')
  bob = spawnPeer('bob') // same identity (same key/tofu files) → re-pins, accepts the sealed envelope
  await bob.initialize()
  const got = await waitUntil(() => {
    const inbox = bob!.channelMsgs.map(m => m.content).join('\n')
    return inbox.includes('DURABLE-PAYLOAD')
  }, 8000)
  const recv = bob.toolText(await bob.callTool('myc_recv', { peek: true }))
  assert(got || /DURABLE-PAYLOAD/.test(recv), 'bob received DURABLE-PAYLOAD after sender-death + relay-restart')
} finally {
  try { alice?.kill() } catch {}
  try { bob?.kill() } catch {}
  try { relay.kill() } catch {}
  await Bun.sleep(200)
  try { rmSync(SCRATCH, { recursive: true, force: true }) } catch {}
}

console.log(`\n${'='.repeat(50)}\nDurability results: ${passed} passed, ${failed} failed\n${'='.repeat(50)}`)
process.exit(failed > 0 ? 1 : 0)
