#!/usr/bin/env bun
/**
 * Mycelium ZERO-PLAINTEXT DEMO — `bun run demo.ts`
 * ===================================================================
 *
 * A standalone, zero-config proof that the relay never sees plaintext.
 *
 * It stands up a COMPLETE, throwaway Mycelium network on localhost:
 *
 *     alice ──▶ [ WS tap ] ──▶ relay ──▶ [ WS tap ] ──▶ bob
 *                  ▲
 *                  └── logs every frame exactly as the relay receives it
 *
 * The tap is a transparent WebSocket proxy the two peers dial instead of
 * dialing the relay directly. It forwards frames byte-for-byte in both
 * directions and records the peer→relay leg — which is *literally* what a
 * malicious relay operator or a network eavesdropper would observe. (A passive
 * observer peer cannot be used here: unicast frames are routed only to their
 * target, so nothing but the tap can see alice's message to bob.)
 *
 * Everything else mirrors test-integration.ts EXACTLY:
 *   • the relay is spawned with RELAY_TOKEN / RELAY_PORT / RELAY_KEY_FILE /
 *     RELAY_ALLOW_FILE under a fresh temp dir;
 *   • the peers are spawned via the same PeerProc helper the integration test
 *     uses (MYC_RELAY / MYC_TOKEN / MYC_PEER / MYC_ROOM / MYC_KEY_FILE /
 *     MYC_TOFU_FILE / MYC_REPLAY_FILE — one key file per peer);
 *   • tool calls are issued over MCP stdio via PeerProc.callTool().
 *
 * The demo then:
 *   (1) forks the relay on an EPHEMERAL port with a RANDOM token + temp state;
 *   (2) starts peers "alice" and "bob" (separate identities);
 *   (3) has alice `myc_send` a human sentence to bob;
 *   (4) prints, side by side, the CIPHERTEXT on the wire (opaque) vs. the
 *       PLAINTEXT bob's `myc_recv` returns — and asserts the plaintext appears
 *       in NONE of the frames the relay saw;
 *   (5) tears down every process/file and exits 0 on success, non-zero on any
 *       failure, guarded by a hard overall timeout.
 *
 * Dependency-free: it uses only what the repo already ships (Bun + the repo's
 * own test-helpers). No network, no config, no arguments.
 */

import { mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { PeerProc, waitUntil } from './test-helpers.ts'

// ---------------------------------------------------------------------------
// Tunables (all local, all fast).
// ---------------------------------------------------------------------------
const HUMAN_MESSAGE = 'Meet me at the old bridge at midnight. Bring the documents. — A'
const AUTH_TIMEOUT_MS = 8_000     // both peers authenticate + STS mutually verify
const DELIVER_TIMEOUT_MS = 6_000  // bob receives + decrypts the message
const RELAY_READY_MS = 6_000      // relay binds its port and answers /health
const OVERALL_TIMEOUT_MS = 30_000 // hard watchdog for the whole run

// A random room-invite token, exactly like test-integration.ts's `TOKEN`.
const TOKEN = 'demo-' + crypto.randomUUID()
// One temp dir holds ALL state (relay keys/allow-list + each peer's key/tofu/
// replay files). Removed on exit.
const SCRATCH = mkdtempSync(join(tmpdir(), 'myc-demo-'))

// ---------------------------------------------------------------------------
// Module-scope handles so the single cleanup() can reach everything.
// ---------------------------------------------------------------------------
let relay: any            // Bun.spawn'd relay.ts process
let proxy: any            // in-process Bun.serve WebSocket tap
let alice: PeerProc | undefined
let bob: PeerProc | undefined

// Every frame the peers sent toward the relay, captured on the wire. This is
// the relay's-eye view: opaque, signed, E2E-encrypted envelopes.
const wireLog: any[] = []

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

/** Ask the OS for a free localhost port by binding :0, then releasing it. */
function freePort(): number {
  const s = Bun.serve({ port: 0, fetch: () => new Response('ok') })
  const p = s.port! // a bound TCP server always reports its port
  s.stop(true)
  return p
}

/** Poll the relay's authenticated /health endpoint until it answers or times out. */
async function waitForRelay(port: number, timeoutMs: number): Promise<boolean> {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/health`, {
        headers: { Authorization: `Bearer ${TOKEN}` },
      })
      if (r.ok) return true
    } catch {
      // relay not listening yet
    }
    await Bun.sleep(100)
  }
  return false
}

/** Elide a long base64 blob so the terminal stays readable, noting its true size. */
function elide(s: string, head = 44, tail = 10): string {
  if (s.length <= head + tail + 3) return s
  return `${s.slice(0, head)}…${s.slice(-tail)}`
}

/** Render two blocks in aligned columns — a genuine side-by-side comparison. */
function sideBySide(lTitle: string, left: string, rTitle: string, right: string, colW = 42): string {
  const wrap = (s: string): string[] => {
    const out: string[] = []
    for (const para of s.split('\n')) {
      if (para === '') { out.push(''); continue }
      for (let i = 0; i < para.length; i += colW) out.push(para.slice(i, i + colW))
    }
    return out
  }
  const L = wrap(left)
  const R = wrap(right)
  const pad = (s: string) => s + ' '.repeat(Math.max(0, colW - s.length))
  const lines: string[] = [
    `${pad(lTitle)} │ ${rTitle}`,
    `${'─'.repeat(colW)}─┼─${'─'.repeat(colW)}`,
  ]
  for (let i = 0; i < Math.max(L.length, R.length); i++) {
    lines.push(`${pad(L[i] ?? '')} │ ${R[i] ?? ''}`)
  }
  return lines.join('\n')
}

// Assertion tally — the demo fails (non-zero exit) if any check fails.
let failures = 0
function check(cond: boolean, label: string): void {
  if (cond) {
    console.log(`  ✅ ${label}`)
  } else {
    failures++
    console.error(`  ❌ ${label}`)
  }
}

// ---------------------------------------------------------------------------
// The transparent WebSocket tap (peers dial this; it forwards to the relay).
// ---------------------------------------------------------------------------

interface TapData {
  upstream: WebSocket | null // this peer connection's paired socket to the real relay
  queue: string[]            // frames buffered until the upstream socket opens
}

function startTap(relayUrl: string): { url: string } {
  proxy = Bun.serve<TapData>({
    port: 0, // ephemeral
    fetch(req, server) {
      const ok = server.upgrade(req, { data: { upstream: null, queue: [] } satisfies TapData })
      return ok ? undefined : new Response('upgrade failed', { status: 500 })
    },
    websocket: {
      perMessageDeflate: false,
      maxPayloadLength: 16 * 1024 * 1024,
      // A peer connected → open its dedicated pipe to the real relay.
      open(ws) {
        const d = ws.data
        let up: WebSocket
        try {
          up = new WebSocket(relayUrl)
        } catch {
          try { ws.close() } catch {}
          return
        }
        d.upstream = up
        up.addEventListener('open', () => {
          for (const m of d.queue) { try { up.send(m) } catch {} }
          d.queue = []
        })
        // relay → peer (downstream): forward verbatim.
        up.addEventListener('message', (e: any) => {
          const s = typeof e.data === 'string' ? e.data : e.data.toString()
          try { ws.send(s) } catch {}
        })
        up.addEventListener('close', () => { try { ws.close() } catch {} })
        up.addEventListener('error', () => { try { ws.close() } catch {} })
      },
      // peer → relay (upstream): THIS is the wire. Record it, then forward verbatim.
      message(ws, raw) {
        const d = ws.data
        const s = typeof raw === 'string' ? raw : raw.toString()
        try { wireLog.push(JSON.parse(s)) } catch { /* non-JSON is never sent by peers */ }
        const up = d.upstream
        if (up && up.readyState === WebSocket.OPEN) {
          try { up.send(s) } catch {}
        } else {
          d.queue.push(s)
        }
      },
      close(ws) {
        try { ws.data.upstream?.close() } catch {}
      },
    },
  })
  return { url: `ws://127.0.0.1:${proxy.port}` }
}

// ---------------------------------------------------------------------------
// Teardown — idempotent; safe to call from the finally block.
// ---------------------------------------------------------------------------
function cleanup(): void {
  try { alice?.kill() } catch {}
  try { bob?.kill() } catch {}
  try { proxy?.stop(true) } catch {}
  try { relay?.kill() } catch {}
  try { rmSync(SCRATCH, { recursive: true, force: true }) } catch {}
}

// ---------------------------------------------------------------------------
// The demo proper. Throws on any hard failure; per-check failures accumulate.
// ---------------------------------------------------------------------------
async function run(): Promise<void> {
  const REPO = import.meta.dir
  const RELAY_PORT = freePort()
  const RELAY_URL = `ws://127.0.0.1:${RELAY_PORT}`

  console.log('🌱 Mycelium zero-plaintext demo\n')
  console.log(`   temp dir : ${SCRATCH}`)
  console.log(`   relay    : ${RELAY_URL} (random token)`)

  // (1) Fork the relay — same env contract as test-integration.ts.
  relay = Bun.spawn(['bun', 'run', 'relay.ts'], {
    cwd: REPO,
    env: {
      ...process.env,
      RELAY_TOKEN: TOKEN,
      RELAY_PORT: String(RELAY_PORT),
      RELAY_KEY_FILE: join(SCRATCH, 'relay-keys.json'),
      RELAY_ALLOW_FILE: join(SCRATCH, 'relay-allow.json'),
    },
    stdout: 'pipe', stderr: 'pipe',
  })
  if (!(await waitForRelay(RELAY_PORT, RELAY_READY_MS))) {
    throw new Error('relay did not become ready')
  }

  // Stand up the tap in front of the relay; the peers will dial IT.
  const tap = startTap(RELAY_URL)
  console.log(`   wire tap : ${tap.url} (peers dial this; forwards to the relay)\n`)

  // (2) Start alice and bob — separate MYC_KEY_FILE each (distinct identities),
  // both pointed at the tap. PeerProc is the exact spawner the integration test
  // uses; it wires MYC_RELAY/MYC_TOKEN/MYC_PEER/MYC_ROOM and the per-peer
  // key/tofu/replay files under SCRATCH.
  const spawnPeer = (name: string) =>
    new PeerProc({ name, relayUrl: tap.url, token: TOKEN, scratchDir: SCRATCH })

  console.log('🔑 Bringing up two peers through the tap...')
  alice = spawnPeer('alice')
  await alice.initialize()
  bob = spawnPeer('bob')
  await bob.initialize()

  const authed = await waitUntil(
    () => alice!.stderrHas(/Auth OK/) && bob!.stderrHas(/Auth OK/),
    AUTH_TIMEOUT_MS,
  )
  check(authed, 'both peers authenticated to the relay')
  const sts = await waitUntil(
    () => alice!.stderrHas(/STS verified/) && bob!.stderrHas(/STS verified/),
    AUTH_TIMEOUT_MS,
  )
  check(sts, 'STS mutual authentication verified (live PFS session established)')
  if (!authed || !sts) throw new Error('peers failed to establish a session')

  // Drain any startup chatter from bob's inbox (peer_joined events, etc.) so the
  // post-send myc_recv shows only alice's message.
  await bob.callTool('myc_recv', { max: 500 })
  bob.clear()
  const wireMark = wireLog.length // ignore all frames captured before the send

  // (3) alice sends a human message to bob.
  console.log(`\n📩 alice → bob (myc_send): ${JSON.stringify(HUMAN_MESSAGE)}`)
  const sendRes = alice.toolText(await alice.callTool('myc_send', {
    target: 'bob', text: HUMAN_MESSAGE, type: 'info',
  }))
  console.log(`   send result: ${sendRes.trim()}`)
  check(sendRes.includes('🔒') && !sendRes.includes('BLOCKED'), 'send accepted over an encrypted session')

  // Wait until bob actually receives + decrypts the message.
  const delivered = await waitUntil(
    () => bob!.from('alice').some(m => m.content === HUMAN_MESSAGE),
    DELIVER_TIMEOUT_MS,
  )
  check(delivered, 'bob received and decrypted the message')
  if (!delivered) throw new Error('message never reached bob')

  // (4) Pull the exact frame the relay routed for this message, off the wire.
  const wireFrame = wireLog.slice(wireMark).find(f =>
    f && f.target === 'bob' && f.sender === 'alice' &&
    f.e2e === true && typeof f.encrypted === 'string' &&
    typeof f.type === 'string' && !f.type.startsWith('_'),
  )
  if (!wireFrame) throw new Error('could not locate the message frame on the wire')

  // What bob's host-independent inbox returns after decryption.
  const recvText = bob.toolText(await bob.callTool('myc_recv', {})).trim()

  // ---- The proof, side by side ------------------------------------------------
  const wireView = [
    `type      : ${wireFrame.type}`,
    `from→to   : ${wireFrame.sender} → ${wireFrame.target}  (room ${wireFrame.room})`,
    `e2e       : ${wireFrame.e2e}`,
    `nonce     : ${elide(String(wireFrame.nonce))}`,
    `ciphertext: ${elide(String(wireFrame.encrypted))}`,
    `           (${String(wireFrame.encrypted).length} base64 chars — opaque NaCl box)`,
    `sig       : ${elide(String(wireFrame.sig))}`,
  ].join('\n')

  console.log('\n🔎 Same message, two vantage points:\n')
  console.log(sideBySide(
    'CIPHERTEXT ON THE WIRE (relay sees)', wireView,
    "PLAINTEXT bob's myc_recv RETURNS", recvText,
  ))

  // ---- Assertions that make this a proof, not a picture -----------------------
  console.log('\n🔬 Verifying zero-plaintext-at-relay:')
  check(recvText.includes(HUMAN_MESSAGE), 'bob decrypted the exact plaintext')

  // The plaintext must appear in NONE of the frames that transited the relay.
  const leaked = wireLog.filter(f => JSON.stringify(f).includes(HUMAN_MESSAGE))
  check(leaked.length === 0, `plaintext absent from all ${wireLog.length} relayed frame(s)`)

  // A distinctive word from the message must also be absent (belt and braces).
  const leakedWord = wireLog.filter(f => JSON.stringify(f).toLowerCase().includes('midnight'))
  check(leakedWord.length === 0, "no distinctive plaintext token ('midnight') on the wire")

  // The frame really was E2E-encrypted (opaque ciphertext, not a plaintext payload).
  check(
    wireFrame.payload == null && typeof wireFrame.encrypted === 'string' && wireFrame.encrypted.length > 0,
    'the routed frame carried ciphertext, never a plaintext payload',
  )
}

// ---------------------------------------------------------------------------
// Entry point: race the run against a hard timeout, always clean up, set code.
// ---------------------------------------------------------------------------
let watchdog: ReturnType<typeof setTimeout> | undefined
const timeout = new Promise<never>((_, reject) => {
  watchdog = setTimeout(
    () => reject(new Error(`demo timed out after ${OVERALL_TIMEOUT_MS}ms`)),
    OVERALL_TIMEOUT_MS,
  )
})

let exitCode = 0
try {
  await Promise.race([run(), timeout])
  if (failures > 0) throw new Error(`${failures} check(s) failed`)
  console.log('\n' + '='.repeat(64))
  console.log('✅ SUCCESS — the relay only ever saw opaque ciphertext.')
  console.log('='.repeat(64))
} catch (e) {
  exitCode = 1
  console.error('\n' + '='.repeat(64))
  console.error(`💥 FAILURE — ${e instanceof Error ? e.message : e}`)
  console.error('='.repeat(64))
} finally {
  if (watchdog) clearTimeout(watchdog)
  cleanup()
  // Give killed child processes a beat to release the temp dir before exit.
  await Bun.sleep(150)
  process.exit(exitCode)
}
