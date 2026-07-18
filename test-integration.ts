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
import { PeerProc, waitUntil } from './test-helpers.ts'

await sodium.ready
const toB64 = (x: Uint8Array) => sodium.to_base64(x, sodium.base64_variants.ORIGINAL)

const REPO = import.meta.dir
const PORT = 9902
const TOKEN = 'itest-' + Date.now()
const RELAY_URL = `ws://127.0.0.1:${PORT}`
const SCRATCH = mkdtempSync(join(tmpdir(), 'myc-itest-'))

let passed = 0
let failed = 0
function assert(cond: boolean, name: string): void {
  if (cond) { passed++; console.log(`  ✅ ${name}`) }
  else { failed++; console.error(`  ❌ ${name}`) }
}

function spawnPeer(name: string, filePrefix?: string): PeerProc {
  return new PeerProc({ name, relayUrl: RELAY_URL, token: TOKEN, scratchDir: SCRATCH, filePrefix })
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

let alice!: PeerProc
let bob!: PeerProc
let bob2: PeerProc | undefined
try {
  await Bun.sleep(900)

  console.log('\n🌱 IT1: two real peers authenticate + STS mutually verify')
  alice = spawnPeer('alice')
  await alice.initialize()
  bob = spawnPeer('bob')
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

  console.log('\n🏷️ IT9: custom message type is delivered verbatim (not coerced to info)')
  // v0.2.0 regression: safeSendType silently rewrote custom types to 'info', breaking
  // every v0.1.x workflow that routes on meta.type.
  bob.clear()
  const ctRes = alice.toolText(await alice.callTool('myc_send', { target: 'bob', text: 'CUSTOM-TYPE', type: 'task_result' }))
  assert(ctRes.includes('🔒'), `custom-type send accepted (${ctRes.trim()})`)
  await waitUntil(() => bob.from('alice').some(m => m.content === 'CUSTOM-TYPE'), 3000)
  const ctMsg = bob.from('alice').find(m => m.content === 'CUSTOM-TYPE')
  assert(ctMsg?.meta?.type === 'task_result', `custom type preserved on delivery (got ${ctMsg?.meta?.type})`)

  console.log('\n🚫 IT10: reserved control types are rejected with an explicit error')
  const resAck = alice.toolText(await alice.callTool('myc_send', { target: 'bob', text: 'x', type: '_ack' }))
  assert(resAck.includes('❌ Invalid message type'), 'sending type _ack returns an explicit error (not silent coercion)')
  const resSts = alice.toolText(await alice.callTool('myc_send', { target: 'bob', text: 'x', type: '_sts_init' }))
  assert(resSts.includes('❌ Invalid message type'), 'sending type _sts_init returns an explicit error')

  console.log('\n🔑 IT11: TOFU key change → myc_trust → STS re-verifies (session_id forwarded)')
  // v0.2.0 regression: myc_trust dropped the session_id, so STS could never verify for
  // a manually trusted peer. This restarts "bob" with a NEW identity, walks the trust
  // flow, and requires full mutual STS verification + working delivery afterwards.
  bob.kill()
  await Bun.sleep(600) // let the relay reap bob and alice process peer_left
  const stsBefore = alice.stderr.filter(l => /STS verified: bob/.test(l)).length
  alice.clear()
  // The relay's persistent name binding would (correctly) reject a fresh key for
  // "bob" — the operator recovery path is an admin revoke, which frees the name
  // and blocklists the lost key. This is the real "peer lost its keys" flow.
  const revokeRes = await fetch(`http://127.0.0.1:${PORT}/admin/revoke`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ room: 'default', name: 'bob' }),
  })
  const revokeJson: any = await revokeRes.json()
  assert(revokeRes.status === 200 && revokeJson.revoked === true, 'admin revoke frees the name binding')
  bob2 = spawnPeer('bob', 'bob2') // same name, fresh keys → TOFU 'changed' at alice
  await bob2.initialize()
  assert(await waitUntil(() => alice.stderrHas(/TOFU VIOLATION: bob/), 6000), 'alice detects the key change (TOFU violation)')
  const blockedTxt = alice.toolText(await alice.callTool('myc_send', { target: 'bob', text: 'nope' }))
  assert(blockedTxt.includes('BLOCKED'), 'sends to the changed-key peer are blocked before trust')
  const fpTxt = alice.toolText(await alice.callTool('myc_trust', { peer_name: 'bob' }))
  assert(fpTxt.includes('fingerprint'), 'myc_trust shows the fingerprint first')
  const trustTxt = alice.toolText(await alice.callTool('myc_trust', { peer_name: 'bob', confirm: true }))
  assert(trustTxt.includes('✅'), `myc_trust confirm succeeds (${trustTxt.trim()})`)
  const stsAgain = await waitUntil(() => alice.stderr.filter(l => /STS verified: bob/.test(l)).length > stsBefore, 6000)
  assert(stsAgain, 'STS mutually verifies AFTER myc_trust (session_id was forwarded)')
  const peersTrusted = alice.toolText(await alice.callTool('myc_peers', {}))
  assert(/bob.*🤝/.test(peersTrusted), `myc_peers shows 🤝 for the trusted peer (${peersTrusted.trim()})`)
  bob2.clear()
  await alice.callTool('myc_send', { target: 'bob', text: 'POST-TRUST', type: 'info' })
  assert(await waitUntil(() => bob2!.from('alice').some(m => m.content === 'POST-TRUST'), 3000), 'delivery works after trust')

  console.log('\n📮 IT12: OFFLINE delivery — send to a dead peer, it receives on return')
  // The v0.2.x architectural hole: relay-queued session frames were undecryptable
  // by construction (keys rotate on reconnect). v0.3.0 seals offline messages to
  // the recipient's IDENTITY key, so store-and-forward actually works.
  bob2.kill()
  assert(await waitUntil(() => alice.stderrHas(/Disconnected|peer_left/) || !alice.from('bob').length || true, 500) && await waitUntil(() => (alice.channelMsgs.some(m => m.meta?.type === 'peer_left' && m.meta?.peer === 'bob')), 6000), 'alice saw bob leave')
  alice.clear()
  const offRes = alice.toolText(await alice.callTool('myc_send', { target: 'bob', text: 'WHILE-YOU-WERE-OUT', type: 'info' }))
  assert(offRes.includes('📮'), `send to offline peer becomes an identity envelope (${offRes.trim()})`)
  await Bun.sleep(400)
  const bob3 = spawnPeer('bob', 'bob2') // SAME identity as the trusted bob2
  bob2 = bob3
  await bob3.initialize()
  assert(await waitUntil(() => bob3.from('alice').some(m => m.content === 'WHILE-YOU-WERE-OUT'), 6000), 'offline message DELIVERED after the peer returns (queue drained, envelope opened)')
  const offMsg = bob3.from('alice').find(m => m.content === 'WHILE-YOU-WERE-OUT')
  assert(offMsg?.meta?.offline === true, 'delivery is flagged as an offline envelope (no PFS disclosure)')
  assert(await waitUntil(() => alice.channelMsgs.some(m => m.meta?.type === 'delivered'), 6000), 'sender gets an explicit delivery confirmation for the deferred message')

  console.log('\n📥 IT13: myc_recv — host-independent inbox drain')
  const recvTxt = bob3.toolText(await bob3.callTool('myc_recv', {}))
  assert(recvTxt.includes('WHILE-YOU-WERE-OUT'), 'myc_recv returns the delivered message')
  const recvTxt2 = bob3.toolText(await bob3.callTool('myc_recv', {}))
  assert(recvTxt2.includes('No pending messages'), 'second myc_recv call finds a drained inbox')

  console.log('\n🧩 IT14: chunking — a 120KB message crosses the 64KB relay frame cap intact')
  bob3.clear()
  const bigText = 'CHUNK-START|' + 'x'.repeat(120_000) + '|CHUNK-END'
  const bigRes = alice.toolText(await alice.callTool('myc_send', { target: 'bob', text: bigText, type: 'info' }))
  assert(bigRes.includes('chunks'), `send reports chunking (${bigRes.trim()})`)
  assert(await waitUntil(() => bob3.from('alice').some(m => typeof m.content === 'string' && m.content.length === bigText.length), 10_000), 'reassembled message delivered')
  const bigMsg = bob3.from('alice').find(m => m.content?.length === bigText.length)
  assert(bigMsg?.content === bigText, 'chunked content is byte-identical after reassembly')
  assert((bigMsg?.meta?.chunked ?? 0) >= 5, `delivery metadata reports the chunk count (${bigMsg?.meta?.chunked})`)

  console.log('\n🔑 IT15: key rotation — continuity-signed, no TOFU violation, relay binding migrates')
  const allowBefore: any = await (await fetch(`http://127.0.0.1:${PORT}/admin/allowlist`, { headers: { Authorization: `Bearer ${TOKEN}` } })).json()
  const aliceKeyBefore = allowBefore.bindings?.default?.alice
  assert(typeof aliceKeyBefore === 'string', 'admin allowlist endpoint exposes the current binding')
  bob3.clear()
  const rotRes = alice.toolText(await alice.callTool('myc_rotate_key', { confirm: true }))
  assert(rotRes.includes('✅ Identity rotated'), `rotation succeeds (${rotRes.split('\n')[0]})`)
  assert(await waitUntil(() => bob3.channelMsgs.some(m => m.meta?.type === 'key_rotated' && m.meta?.peer === 'alice'), 6000), 'peer verified the continuity signature and updated its pin')
  assert(await waitUntil(() => alice.stderr.filter(l => /Auth OK/.test(l)).length >= 2, 8000), 'alice re-authenticated under the NEW key (binding migrated, no token needed)')
  assert(!bob3.stderrHas(/TOFU VIOLATION: alice/), 'NO TOFU violation at the peer — rotation is seamless')
  const allowAfter: any = await (await fetch(`http://127.0.0.1:${PORT}/admin/allowlist`, { headers: { Authorization: `Bearer ${TOKEN}` } })).json()
  assert(allowAfter.bindings?.default?.alice && allowAfter.bindings.default.alice !== aliceKeyBefore, 'relay name binding migrated to the new key')
  bob3.clear()
  await waitUntil(() => alice.stderrHas(/STS verified: bob/), 6000)
  await alice.callTool('myc_send', { target: 'bob', text: 'POST-ROTATE', type: 'info' })
  assert(await waitUntil(() => bob3.from('alice').some(m => m.content === 'POST-ROTATE'), 6000), 'delivery works after rotation')

  console.log('\n🚷 IT16: revoked key is refused even WITH the invite token')
  // IT11's admin revoke blocklisted original-bob's key; the old identity must not
  // be able to re-register itself using the (long-lived) room token.
  const oldBob = spawnPeer('bob', 'bob') // the ORIGINAL bob keys from IT1
  assert(await waitUntil(() => oldBob.stderrHas(/key revoked/), 6000), 'relay rejects the revoked key at auth')
  assert(!oldBob.stderrHas(/Auth OK/), 'revoked peer never authenticates')
  oldBob.kill()

  console.log('\n🏘️ IT17: multi-room membership + per-room isolation + discovery')
  const carol = spawnPeer('carol')
  ;(carol as any) // carol: default only — spawn multi-room dana + ops-only erin
  await carol.initialize()
  const dana = new (await import('./test-helpers.ts')).PeerProc({ name: 'dana', relayUrl: RELAY_URL, token: TOKEN, scratchDir: SCRATCH, room: 'default,ops' })
  await dana.initialize()
  const erin = new (await import('./test-helpers.ts')).PeerProc({ name: 'erin', relayUrl: RELAY_URL, token: TOKEN, scratchDir: SCRATCH, room: 'ops' })
  await erin.initialize()
  assert(await waitUntil(() => dana.stderrHas(/Auth OK/) && erin.stderrHas(/Auth OK/), 6000), 'multi-room + ops-only peers authenticated')
  erin.clear(); carol.clear()
  await waitUntil(() => dana.stderrHas(/STS verified: erin@ops/), 6000)
  const danaSend = dana.toolText(await dana.callTool('myc_send', { target: 'erin', text: 'OPS-ONLY', type: 'info' }))
  assert(danaSend.includes('🔒') || danaSend.includes('🆕'), `dana→erin send accepted (${danaSend.trim()})`)
  assert(await waitUntil(() => erin.from('dana').some(m => m.content === 'OPS-ONLY'), 6000), 'ops-room unicast delivered')
  const opsMsg = erin.from('dana').find(m => m.content === 'OPS-ONLY')
  assert(opsMsg?.meta?.room === 'ops', `delivery is tagged with its room (${opsMsg?.meta?.room})`)
  await Bun.sleep(500)
  assert(!carol.from('dana').some(m => m.content === 'OPS-ONLY'), 'default-room peer did NOT receive the ops message (room isolation)')
  const roomsTxt = dana.toolText(await dana.callTool('myc_rooms', {}))
  assert(/default: \d+ peer/.test(roomsTxt) && /ops: \d+ peer/.test(roomsTxt), `discovery lists both rooms (${roomsTxt.replace(/\n/g, ' | ')})`)
  carol.kill(); dana.kill(); erin.kill()

  console.log('\n📌 IT18: multi-relay fingerprint pinning (set match) + wrong-pin refusal')
  const relayKeysFile = JSON.parse(require('fs').readFileSync(join(SCRATCH, 'relay-keys.json'), 'utf8'))
  const relayPub = sodium.from_base64(relayKeysFile.public, sodium.base64_variants.ORIGINAL)
  const realFp = Array.from(sodium.crypto_hash(relayPub).slice(0, 16))
    .map((b: number) => b.toString(16).padStart(2, '0')).join('').match(/.{4}/g)!.join(':')
  const pinned = new (await import('./test-helpers.ts')).PeerProc({
    name: 'pinned-peer', relayUrl: RELAY_URL, token: TOKEN, scratchDir: SCRATCH,
    extraEnv: { MYC_RELAY_FINGERPRINT: `dead:beef:0000:0000:0000:0000:0000:0000,${realFp}` },
  })
  assert(await waitUntil(() => pinned.stderrHas(/Relay identity verified/) && pinned.stderrHas(/Auth OK/), 6000), 'fingerprint LIST pins the relay (failover keeps identity pinning)')
  pinned.kill()
  const misPinned = new (await import('./test-helpers.ts')).PeerProc({
    name: 'mispinned-peer', relayUrl: RELAY_URL, token: TOKEN, scratchDir: SCRATCH,
    extraEnv: { MYC_RELAY_FINGERPRINT: 'dead:beef:0000:0000:0000:0000:0000:0000' },
  })
  assert(await waitUntil(() => misPinned.stderrHas(/RELAY IDENTITY MISMATCH/), 6000), 'wrong pin refuses to send credentials')
  assert(!misPinned.stderrHas(/Auth OK/), 'mis-pinned peer never authenticates')
  misPinned.kill()

  console.log('\n🔐 IT19: passphrase-encrypted identity key file')
  const pp = new (await import('./test-helpers.ts')).PeerProc({
    name: 'vault-peer', relayUrl: RELAY_URL, token: TOKEN, scratchDir: SCRATCH,
    extraEnv: { MYC_KEY_PASSPHRASE: 'hunter2' },
  })
  assert(await waitUntil(() => pp.stderrHas(/Auth OK/), 6000), 'peer with passphrase-encrypted keys authenticates')
  const fpLine = pp.stderr.find(l => /Fingerprint:/.test(l)) ?? ''
  pp.kill()
  await Bun.sleep(300)
  const keyFileRaw = JSON.parse(require('fs').readFileSync(join(SCRATCH, 'vault-peer-keys.json'), 'utf8'))
  assert(typeof keyFileRaw.cipher === 'string' && !keyFileRaw.sign_secret, 'key file on disk is encrypted (no plaintext secret)')
  const pp2 = new (await import('./test-helpers.ts')).PeerProc({
    name: 'vault-peer', relayUrl: RELAY_URL, token: TOKEN, scratchDir: SCRATCH,
    extraEnv: { MYC_KEY_PASSPHRASE: 'hunter2' },
  })
  assert(await waitUntil(() => pp2.stderr.some(l => /Fingerprint:/.test(l) && l === fpLine), 6000), 'same passphrase restores the SAME identity')
  pp2.kill()
  const pp3 = new (await import('./test-helpers.ts')).PeerProc({
    name: 'vault-peer', relayUrl: RELAY_URL, token: TOKEN, scratchDir: SCRATCH,
    extraEnv: { MYC_KEY_PASSPHRASE: 'wrong-pass' },
  })
  assert(await waitUntil(() => pp3.stderrHas(/wrong passphrase/), 6000), 'wrong passphrase is refused (fail-closed)')
  pp3.kill()

} catch (e) {
  console.error('\n💥 Integration error:', e)
  failed++
} finally {
  try { alice?.kill() } catch {}
  try { bob?.kill() } catch {}
  try { bob2?.kill() } catch {}
  try { relay.kill() } catch {}
  await Bun.sleep(150)
  try { rmSync(SCRATCH, { recursive: true, force: true }) } catch {}
  console.log(`\n${'='.repeat(50)}`)
  console.log(`Integration results: ${passed} passed, ${failed} failed`)
  console.log('='.repeat(50))
  process.exit(failed > 0 ? 1 : 0)
}
