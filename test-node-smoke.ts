#!/usr/bin/env bun
/**
 * Mycelium NODE portability test.
 *
 * The peer makes zero Bun.* calls, so it should run under Node too — the
 * portability that unblocks `npx` and non-Bun MCP hosts (audit gap #1). This
 * builds the node-target peer bundle, runs it under REAL `node`, and has it
 * exchange messages BOTH WAYS with a Bun peer through a Bun relay. If libsodium
 * WASM, the global WebSocket, or MCP stdio did not work under Node, this fails.
 */
import { mkdtempSync, rmSync, existsSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { PeerProc, waitUntil } from './test-helpers.ts'

const REPO = import.meta.dir
const PORT = 9904
const TOKEN = 'node-' + Date.now()
const RELAY_URL = `ws://127.0.0.1:${PORT}`
const SCRATCH = mkdtempSync(join(tmpdir(), 'myc-node-'))

let passed = 0
let failed = 0
function assert(cond: boolean, name: string): void {
  if (cond) { passed++; console.log(`  ✅ ${name}`) }
  else { failed++; console.error(`  ❌ ${name}`) }
}

console.log('\n🔧 N0: build the node-target peer bundle')
const build = Bun.spawnSync(['bun', 'build', 'peer-channel.ts', '--target', 'node', '--outfile', 'build/peer-channel.node.mjs'], { cwd: REPO })
if (build.exitCode !== 0) { console.error('build:node failed'); process.exit(1) }
const NODE_PEER = join(REPO, 'build/peer-channel.node.mjs')
assert(existsSync(NODE_PEER), 'node-target peer bundle built')

const relay = Bun.spawn(['bun', 'run', 'relay.ts'], {
  cwd: REPO,
  env: { ...process.env, RELAY_TOKEN: TOKEN, RELAY_PORT: String(PORT), RELAY_KEY_FILE: join(SCRATCH, 'rk.json'), RELAY_ALLOW_FILE: join(SCRATCH, 'ra.json') },
  stdout: 'pipe', stderr: 'pipe',
})

let nodePeer: PeerProc | undefined
let bunPeer: PeerProc | undefined
try {
  await Bun.sleep(900)

  console.log('\n🟢 N1: alice runs under NODE, bob under BUN — both authenticate + STS-verify')
  nodePeer = new PeerProc({ name: 'alice', relayUrl: RELAY_URL, token: TOKEN, scratchDir: SCRATCH, cmd: ['node', NODE_PEER] })
  await nodePeer.initialize()
  bunPeer = new PeerProc({ name: 'bob', relayUrl: RELAY_URL, token: TOKEN, scratchDir: SCRATCH })
  await bunPeer.initialize()
  assert(await waitUntil(() => !!nodePeer!.stderrHas(/Auth OK/), 8000), 'the NODE-built peer authenticated to the relay')
  assert(await waitUntil(() => !!nodePeer!.stderrHas(/STS verified/) && !!bunPeer!.stderrHas(/STS verified/), 8000), 'node<->bun STS mutual verification (crypto works under Node)')

  console.log('\n📨 N2: message delivery works in BOTH directions across runtimes')
  await nodePeer.callTool('myc_send', { target: 'bob', text: 'FROM-NODE' })
  assert(await waitUntil(() => bunPeer!.channelMsgs.some(m => m.content === 'FROM-NODE'), 6000), 'bun peer received + decrypted a message from the NODE peer')
  await bunPeer.callTool('myc_send', { target: 'alice', text: 'FROM-BUN' })
  assert(await waitUntil(() => nodePeer!.channelMsgs.some(m => m.content === 'FROM-BUN'), 6000), 'NODE peer received + decrypted a reply from the bun peer')
} finally {
  try { nodePeer?.kill() } catch {}
  try { bunPeer?.kill() } catch {}
  try { relay.kill() } catch {}
  await Bun.sleep(200)
  try { rmSync(SCRATCH, { recursive: true, force: true }) } catch {}
}

console.log(`\n${'='.repeat(50)}\nNode-interop results: ${passed} passed, ${failed} failed\n${'='.repeat(50)}`)
process.exit(failed > 0 ? 1 : 0)
