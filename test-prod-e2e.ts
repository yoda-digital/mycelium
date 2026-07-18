#!/usr/bin/env bun
/**
 * Mycelium E2E against a REMOTE relay (e.g. the wss:// staging/prod relay).
 *
 * Spawns two branch peers pointed at a live relay and exchanges messages both
 * ways, over real TLS. Reads config from env — NO secrets in this file:
 *   MYC_RELAY               (default wss://myc.yoda.digital)
 *   MYC_TOKEN               (required)
 *   MYC_RELAY_FINGERPRINT   (optional; pin the relay identity)
 *   MYC_ROOM                (default e2e-probe)
 *
 * Probe peers register ephemeral names on the relay's allow-list; revoke them
 * afterwards if you care (they are named probe-a-<pid> / probe-b-<pid>).
 */
import { mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { PeerProc, waitUntil } from './test-helpers.ts'

const RELAY = process.env.MYC_RELAY ?? 'wss://myc.yoda.digital'
const TOKEN = process.env.MYC_TOKEN
const FP = process.env.MYC_RELAY_FINGERPRINT
const ROOM = process.env.MYC_ROOM ?? 'e2e-probe'
if (!TOKEN) { console.error('MYC_TOKEN required in env'); process.exit(2) }

const SCRATCH = mkdtempSync(join(tmpdir(), 'myc-prod-'))
const SFX = String(process.pid)
const A = `probe-a-${SFX}`
const B = `probe-b-${SFX}`

let passed = 0
let failed = 0
function assert(c: boolean, n: string): void {
  if (c) { passed++; console.log(`  ✅ ${n}`) } else { failed++; console.error(`  ❌ ${n}`) }
}
function mk(name: string): PeerProc {
  return new PeerProc({ name, relayUrl: RELAY, token: TOKEN as string, scratchDir: SCRATCH, room: ROOM, extraEnv: FP ? { MYC_RELAY_FINGERPRINT: FP } : undefined })
}

let a: PeerProc | undefined
let b: PeerProc | undefined
try {
  console.log(`\n🌐 Prod E2E → ${RELAY}  (room ${ROOM}, peers ${A} / ${B})`)
  a = mk(A); await a.initialize()
  b = mk(B); await b.initialize()

  const authed = await waitUntil(() => !!a!.stderrHas(/Auth OK/) && !!b!.stderrHas(/Auth OK/), 20000)
  assert(authed, 'both probe peers authenticated to the remote relay')
  if (!authed) {
    console.error('   a.stderr tail:', a.stderr.slice(-6).join(' | '))
    if (a.stderrHas(/waiting for challenge/i) && !a.stderrHas(/challenge verified|Relay identity/i)) {
      console.error('   → the relay never sent a v2 challenge frame — it is PRE-v0.3.0. Upgrade the relay first.')
    }
    throw new Error('auth failed against the remote relay (see diagnostics above)')
  }

  assert(await waitUntil(() => !!a!.stderrHas(/STS verified/) && !!b!.stderrHas(/STS verified/), 15000), 'STS mutual verification over the remote relay')

  await a.callTool('myc_send', { target: B, text: 'PROD-E2E-AB' })
  assert(await waitUntil(() => b!.channelMsgs.some(m => m.content === 'PROD-E2E-AB'), 12000), `${B} received ${A}'s message through the remote relay`)

  await b.callTool('myc_send', { target: A, text: 'PROD-E2E-BA' })
  assert(await waitUntil(() => a!.channelMsgs.some(m => m.content === 'PROD-E2E-BA'), 12000), `${A} received ${B}'s reply through the remote relay`)
} catch (e: any) {
  console.error('   ✖', e?.message ?? e)
} finally {
  try { a?.kill() } catch {}
  try { b?.kill() } catch {}
  await Bun.sleep(200)
  try { rmSync(SCRATCH, { recursive: true, force: true }) } catch {}
}

console.log(`\n${'='.repeat(50)}\nProd E2E: ${passed} passed, ${failed} failed\n${'='.repeat(50)}`)
process.exit(failed > 0 ? 1 : 0)
