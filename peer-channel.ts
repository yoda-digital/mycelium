#!/usr/bin/env bun
/**
 * Mycelium Peer Channel — MCP server for E2E encrypted peer messaging.
 *
 * Ed25519 identity + Curve25519 ephemeral (PFS) + NaCl authenticated encryption.
 * TOFU fail-closed. Canonical signatures over msg_id+seq. Write-ahead replay log.
 * Permission messages go through the same E2E envelope. Bad/missing sig = hard block.
 *
 * Env: MYC_RELAY, MYC_TOKEN, MYC_PEER, MYC_ROOM, MYC_KEY_FILE, MYC_TOFU_FILE, MYC_REPLAY_FILE
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import sodium from 'libsodium-wrappers-sumo'
import { existsSync, readFileSync, writeFileSync, mkdirSync, appendFileSync } from 'fs'

const toB64 = (x: Uint8Array) => sodium.to_base64(x, sodium.base64_variants.ORIGINAL)
const fromB64 = (x: string) => sodium.from_base64(x, sodium.base64_variants.ORIGINAL)
import { dirname, resolve } from 'path'
import { homedir } from 'os'

const RELAY_LIST = (process.env.MYC_RELAY ?? '').split(',').map(s => s.trim()).filter(Boolean)
let relayIdx = 0
const TOKEN = process.env.MYC_TOKEN
const PEER = process.env.MYC_PEER
const ROOM = process.env.MYC_ROOM ?? 'default'
const KEY_FILE = process.env.MYC_KEY_FILE ?? resolve(homedir(), '.mycelium-keys.json')
const TOFU_FILE = process.env.MYC_TOFU_FILE ?? resolve(homedir(), '.mycelium-known-peers.json')
const REPLAY_FILE = process.env.MYC_REPLAY_FILE ?? resolve(homedir(), '.mycelium-replay-state.json')
const RELAY_FINGERPRINT = process.env.MYC_RELAY_FINGERPRINT

if (!RELAY_LIST.length || !TOKEN || !PEER) {
  console.error('Required: MYC_RELAY, MYC_TOKEN, MYC_PEER')
  process.exit(1)
}

function log(msg: string): void {
  console.error(`[myc/${PEER}] ${msg}`)
}

function safeWrite(path: string, data: string): void {
  try {
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, data, { mode: 0o600 })
  } catch (e) {
    log(`Write failed ${path}: ${e}`)
  }
}

// ===========================================================================
// LONG-TERM KEYS (Ed25519 — identity)
// ===========================================================================

let ltKeys: { signPublicKey: Uint8Array; signPrivateKey: Uint8Array }

function loadOrGenLTKeys(): { signPublicKey: Uint8Array; signPrivateKey: Uint8Array } {
  try {
    if (existsSync(KEY_FILE)) {
      const s = JSON.parse(readFileSync(KEY_FILE, 'utf8'))
      return {
        signPublicKey: fromB64(s.sign_public),
        signPrivateKey: fromB64(s.sign_secret),
      }
    }
  } catch {}

  const kp = sodium.crypto_sign_keypair()
  safeWrite(KEY_FILE, JSON.stringify({
    sign_public: toB64(kp.publicKey),
    sign_secret: toB64(kp.privateKey),
  }, null, 2))
  log(`Generated Ed25519 identity → ${KEY_FILE}`)
  return { signPublicKey: kp.publicKey, signPrivateKey: kp.privateKey }
}

// ===========================================================================
// EPHEMERAL KEYS (Curve25519 — PFS, per session)
// ===========================================================================

let ephKeys: { encPublicKey: Uint8Array; encPrivateKey: Uint8Array; pubKeySig: string }

function genEphKeys(): { encPublicKey: Uint8Array; encPrivateKey: Uint8Array; pubKeySig: string } {
  const kp = sodium.crypto_box_keypair()
  return {
    encPublicKey: kp.publicKey,
    encPrivateKey: kp.privateKey,
    pubKeySig: toB64(sodium.crypto_sign_detached(kp.publicKey, ltKeys.signPrivateKey)),
  }
}

// ===========================================================================
// TOFU — FAIL-CLOSED
// ===========================================================================

interface TofuEntry {
  sign_pubkey: string
  first_seen: string
  last_seen: string
}

let tofuStore: Record<string, TofuEntry> = {}

function loadTofu(): void {
  try {
    if (existsSync(TOFU_FILE)) tofuStore = JSON.parse(readFileSync(TOFU_FILE, 'utf8'))
  } catch {}
}

function saveTofu(): void {
  safeWrite(TOFU_FILE, JSON.stringify(tofuStore, null, 2))
}

function tofuCheck(peer: string, key64: string): 'trusted' | 'new' | 'changed' {
  const now = new Date().toISOString()
  const entry = tofuStore[peer]

  if (!entry) {
    tofuStore[peer] = { sign_pubkey: key64, first_seen: now, last_seen: now }
    saveTofu()
    return 'new'
  }
  if (entry.sign_pubkey === key64) {
    entry.last_seen = now
    saveTofu()
    return 'trusted'
  }
  return 'changed'
}

function tofuOverride(peer: string, key64: string): void {
  const now = new Date().toISOString()
  tofuStore[peer] = { sign_pubkey: key64, first_seen: now, last_seen: now }
  saveTofu()
}

// Fingerprint for out-of-band verification
function fingerprint(key64: string): string {
  const bytes = fromB64(key64)
  const hash = sodium.crypto_hash(bytes) // SHA-512
  // Take first 16 bytes, format as 4-char groups
  return Array.from(hash.slice(0, 16))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .match(/.{4}/g)!
    .join(':')
}

// ===========================================================================
// PEER SESSIONS
// ===========================================================================

interface PeerSession {
  signPubKey: Uint8Array
  ephEncPubKey: Uint8Array
  sharedKey: Uint8Array
  tofuStatus: 'trusted' | 'new'
  sessionId: string
}

const peerSessions = new Map<string, PeerSession>()
const pendingTrustKeys = new Map<string, {
  sign_pubkey: string
  eph_enc_pubkey: string
  eph_enc_pubkey_sig: string
}>()

function processPeerKeys(
  peerName: string,
  signPubKey64: string,
  ephEncPubKey64: string,
  ephSig64: string,
  remoteSessionId?: string,
): PeerSession | null {
  if (!signPubKey64 || !ephEncPubKey64 || !ephSig64) return null
  try {
    const signPubKey = fromB64(signPubKey64)
    const ephEncPubKey = fromB64(ephEncPubKey64)

    if (!sodium.crypto_sign_verify_detached(fromB64(ephSig64), ephEncPubKey, signPubKey)) {
      log(`⚠️ SECURITY: Bad eph key sig for ${peerName}`)
      return null
    }

    const tofu = tofuCheck(peerName, signPubKey64)
    if (tofu === 'changed') {
      log(`🔴 TOFU VIOLATION: ${peerName} key changed! BLOCKED.`)
      return null // FAIL-CLOSED
    }

    const sharedKey = sodium.crypto_box_beforenm(ephEncPubKey, ephKeys.encPrivateKey)
    const session: PeerSession = {
      signPubKey, ephEncPubKey, sharedKey,
      tofuStatus: tofu,
      sessionId: remoteSessionId ?? '',
    }
    peerSessions.set(peerName, session)
    return session
  } catch (e) {
    log(`Bad keys for ${peerName}: ${e}`)
    return null
  }
}

// ===========================================================================
// ENCRYPTION
// ===========================================================================

function encryptFor(peer: string, plaintext: string): { encrypted: string; nonce: string } | null {
  const s = peerSessions.get(peer)
  if (!s) return null
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES)
  const encrypted = toB64(sodium.crypto_box_easy_afternm(sodium.from_string(plaintext), nonce, s.sharedKey))
  return { encrypted, nonce: toB64(nonce) }
}

function decryptFrom(peer: string, enc64: string, nonce64: string): string | null {
  const s = peerSessions.get(peer)
  if (!s) return null
  try {
    const decrypted = sodium.crypto_box_open_easy_afternm(
      fromB64(enc64),
      fromB64(nonce64),
      s.sharedKey,
    )
    return sodium.to_string(decrypted)
  } catch {
    return null
  }
}

// ===========================================================================
// CANONICAL SIGNATURE — includes msg_id + seq
// ===========================================================================

function canonicalSign(msg: any): string {
  // 11 fields, SORTED, ALL semantically meaningful fields covered.
  // msg_id + seq are IN the canonical — relay can't mint new IDs for signed messages.
  const canonical = JSON.stringify({
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
  return toB64(sodium.crypto_sign_detached(sodium.from_string(canonical), ltKeys.signPrivateKey))
}

function verifySig(peerName: string, msg: any, sig64: string): boolean {
  const s = peerSessions.get(peerName)
  if (!s) return false
  try {
    const canonical = JSON.stringify({
      e2e: msg.e2e ?? null,
      encrypted: msg.encrypted ?? null,
      msg_id: msg.msg_id ?? null,
      nonce: msg.nonce ?? null,
      payload: msg.payload ?? null,
      request_id: msg.request_id ?? null,
      sender: msg.sender ?? null,
      seq: msg.seq ?? null,
      session_id: msg.session_id ?? null,
      target: msg.target ?? null,
      type: msg.type ?? null,
    })
    return sodium.crypto_sign_verify_detached(
      fromB64(sig64),
      sodium.from_string(canonical),
      s.signPubKey,
    )
  } catch {
    return false
  }
}

// ===========================================================================
// REPLAY PROTECTION — persisted, write-ahead, session-scoped
// ===========================================================================

const SEEN_EXPIRY_MS = 30 * 60 * 1000
const SEEN_MAX = 10_000
let seenMsgIds = new Map<string, number>()
let peerSeqs: Record<string, Record<string, number>> = {}

function loadReplay(): void {
  try {
    if (existsSync(REPLAY_FILE)) {
      const s = JSON.parse(readFileSync(REPLAY_FILE, 'utf8'))
      if (s.seen) seenMsgIds = new Map(Object.entries(s.seen).map(([k, v]) => [k, v as number]))
      if (s.seqs) peerSeqs = s.seqs
    }
  } catch {}
}

function saveReplay(): void {
  const obj: Record<string, number> = {}
  for (const [k, v] of seenMsgIds) obj[k] = v
  safeWrite(REPLAY_FILE, JSON.stringify({ seen: obj, seqs: peerSeqs }))
}

// Write-ahead — persist msg_id BEFORE processing
function writeAheadMsgId(msgId: string): void {
  seenMsgIds.set(msgId, Date.now())
  // Append to replay file immediately (crash-safe)
  try { appendFileSync(REPLAY_FILE + '.wal', msgId + '\n') } catch {}
}

function loadWAL(): void {
  const walPath = REPLAY_FILE + '.wal'
  try {
    if (existsSync(walPath)) {
      const lines = readFileSync(walPath, 'utf8').trim().split('\n')
      for (const id of lines) {
        if (id) seenMsgIds.set(id, Date.now())
      }
      writeFileSync(walPath, '') // clear after merge
    }
  } catch {}
}

function checkReplay(
  from: string,
  msgId: string | undefined,
  seq: number | undefined,
  sid: string | undefined,
): { duplicate: boolean } {
  let duplicate = false

  if (msgId) {
    if (seenMsgIds.has(msgId)) duplicate = true
    else writeAheadMsgId(msgId)
  }

  // Track max seq for persistence (ordering handled by reorder buffer)
  if (typeof seq === 'number' && sid) {
    if (!peerSeqs[from]) peerSeqs[from] = {}
    const last = peerSeqs[from][sid] ?? -1
    if (seq > last) peerSeqs[from][sid] = seq
  }

  return { duplicate }
}

const replayTimer = setInterval(() => {
  const cutoff = Date.now() - SEEN_EXPIRY_MS
  for (const [id, ts] of seenMsgIds) {
    if (ts < cutoff) seenMsgIds.delete(id)
  }
  while (seenMsgIds.size > SEEN_MAX) {
    const first = seenMsgIds.keys().next().value
    if (first) seenMsgIds.delete(first)
  }
  saveReplay()
  // Clear WAL after full save
  try { writeFileSync(REPLAY_FILE + '.wal', '') } catch {}
}, 10_000)

// ===========================================================================
// REORDER BUFFER — fixes out-of-order seq being dropped as replay
// ===========================================================================

interface BufferedMsg {
  seq: number
  msg: any
  receivedAt: number
}

const reorderBuffers = new Map<string, BufferedMsg[]>()
const expectedSeqs = new Map<string, number>()

function reorderKey(peer: string, sid: string): string {
  return `${peer}\0${sid}`
}

function bufferInsert(peer: string, sid: string, seq: number, msg: any): void {
  const key = reorderKey(peer, sid)
  let buf = reorderBuffers.get(key)
  if (!buf) { buf = []; reorderBuffers.set(key, buf) }
  buf.push({ seq, msg, receivedAt: Date.now() })
  buf.sort((a, b) => a.seq - b.seq)
}

async function bufferFlush(peer: string, sid: string, processFn: (msg: any) => Promise<void>): Promise<void> {
  const key = reorderKey(peer, sid)
  const buf = reorderBuffers.get(key)
  if (!buf || !buf.length) return

  let expected = expectedSeqs.get(key) ?? 0

  while (buf.length && buf[0].seq === expected) {
    const item = buf.shift()!
    expected++
    await processFn(item.msg)
  }

  while (buf.length > 5) {
    const item = buf.shift()!
    expected = item.seq + 1
    await processFn(item.msg)
  }

  expectedSeqs.set(key, expected)
  if (!buf.length) reorderBuffers.delete(key)
}

function bufferForceFlushPeer(peer: string): void {
  for (const [key] of reorderBuffers) {
    if (key.startsWith(peer + '\0')) {
      reorderBuffers.delete(key)
      expectedSeqs.delete(key)
    }
  }
}

const reorderTimer = setInterval(() => {
  const cutoff = Date.now() - 200
  for (const [key, buf] of reorderBuffers) {
    const stale = buf.filter(m => m.receivedAt < cutoff)
    if (stale.length) {
      const remaining = buf.filter(m => m.receivedAt >= cutoff)
      if (remaining.length) reorderBuffers.set(key, remaining)
      else reorderBuffers.delete(key)
    }
  }
}, 100)

// ===========================================================================
// E2E DELIVERY ACKS
// ===========================================================================

const ACK_TIMEOUT_MS = 30_000
const pendingAcks = new Map<string, { target: string; timer: ReturnType<typeof setTimeout> }>()

function trackAck(msgId: string, target: string): void {
  const timer = setTimeout(async () => {
    pendingAcks.delete(msgId)
    await safeNotify({
      method: 'notifications/claude/channel',
      params: {
        content: `⚠️ Message ${msgId} to ${target}: delivery NOT confirmed (30s). Relay may have dropped it.`,
        meta: { type: 'ack_timeout', target, msg_id: msgId },
      },
    })
  }, ACK_TIMEOUT_MS)
  pendingAcks.set(msgId, { target, timer })
}

function handleAck(ackMsgId: string): void {
  const p = pendingAcks.get(ackMsgId)
  if (p) {
    clearTimeout(p.timer)
    pendingAcks.delete(ackMsgId)
  }
}

function sendAck(fromPeer: string, ackMsgId: string): void {
  const enc = encryptFor(fromPeer, `ack:${ackMsgId}`)
  if (!enc) return

  const msgId = makeMsgId()
  const ack: any = {
    target: fromPeer, type: '_ack',
    encrypted: enc.encrypted, nonce: enc.nonce,
    e2e: true, sender: PEER, session_id: sessionId,
    payload: null, msg_id: msgId, seq: outboundSeq++,
  }
  ack.sig = canonicalSign(ack)
  wsSend(ack)
}

// ===========================================================================
// STATE
// ===========================================================================

let connectedPeers: string[] = []
let ws: WebSocket | null = null
let mcpReady = false
let authenticated = false
let outboundSeq = 0
// 16-byte session ID (128-bit, birthday-safe to ~2^64)
let sessionId = ''

let reconnectAttempt = 0
let reconnectTimer: ReturnType<typeof setTimeout> | null = null

function getBackoffMs(): number {
  return Math.floor(Math.random() * Math.min(60_000, 1000 * Math.pow(2, reconnectAttempt)))
}

let lastServerActivity = 0
let heartbeatTimer: ReturnType<typeof setInterval> | null = null

function startHB(): void {
  lastServerActivity = Date.now()
  if (heartbeatTimer) clearInterval(heartbeatTimer)
  heartbeatTimer = setInterval(() => {
    if (Date.now() - lastServerActivity > 45_000) {
      log('HB timeout')
      if (ws) try { ws.close(4100, 'heartbeat') } catch {}
    }
  }, 10_000)
}

function stopHB(): void {
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer)
    heartbeatTimer = null
  }
}

let msgIdSeq = 0

function makeMsgId(): string {
  return `${PEER}-${Date.now().toString(36)}-${(msgIdSeq++).toString(36)}`
}

function generateSessionId(): string {
  return sodium.randombytes_buf(16).reduce((s: string, b: number) => s + b.toString(16).padStart(2, '0'), '')
}

// ===========================================================================
// MCP SERVER
// ===========================================================================

const mcp = new Server(
  { name: `myc-${PEER}`, version: '1.0.0' },
  {
    capabilities: { experimental: { 'claude/channel': {}, 'claude/channel/permission': {} }, tools: {} },
    instructions: [
      `Mycelium peer "${PEER}" in room "${ROOM}".`,
      'All messages E2E encrypted (PFS). Signatures bind msg_id+seq (relay can\'t replay).',
      'TOFU-pinned identities — 🔴BLOCKED = fail-closed, use myc_trust after verification.',
      'Bad/missing signatures on encrypted messages = HARD BLOCKED (not delivered).',
      'Permission messages are encrypted too — relay can\'t forge approvals.',
      'Tools: myc_send, myc_broadcast, myc_peers, myc_trust',
    ].join('\n'),
  },
)

mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'myc_send',
      description: 'E2E encrypted unicast (PFS, signed, ack-tracked)',
      inputSchema: {
        type: 'object',
        properties: {
          target: { type: 'string', description: `Peer. Known: ${connectedPeers.join(', ') || '(none)'}` },
          text: { type: 'string' },
          type: { type: 'string', enum: ['request', 'response', 'info'] },
          request_id: { type: 'string', description: 'Correlate request/response pairs' },
        },
        required: ['target', 'text'],
      },
    },
    {
      name: 'myc_broadcast',
      description: 'E2E encrypted to ALL peers (N×unicast)',
      inputSchema: {
        type: 'object',
        properties: {
          text: { type: 'string' },
          type: { type: 'string', enum: ['request', 'info', 'announcement'] },
        },
        required: ['text'],
      },
    },
    {
      name: 'myc_peers',
      description: 'List peers with TOFU + encryption status',
      inputSchema: { type: 'object', properties: {} },
    },
    // Shows fingerprint for out-of-band verification
    {
      name: 'myc_trust',
      description: 'Override TOFU block — shows fingerprint for out-of-band verification',
      inputSchema: {
        type: 'object',
        properties: {
          peer_name: { type: 'string' },
          confirm: { type: 'boolean', description: 'Must be true after verifying fingerprint' },
        },
        required: ['peer_name'],
      },
    },
  ],
}))

mcp.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params as { name: string; arguments: Record<string, any> }

  if (name !== 'myc_trust' && name !== 'myc_peers' && (!ws || ws.readyState !== WebSocket.OPEN || !authenticated)) {
    return { content: [{ type: 'text', text: `⚠️ Not connected (attempt ${reconnectAttempt})` }] }
  }

  switch (name) {
    case 'myc_send':
      return { content: [{ type: 'text', text: sendEncrypted(args.target, args.text, args.type ?? 'info', args.target, args.request_id) }] }

    case 'myc_broadcast': {
      if (!connectedPeers.length) return { content: [{ type: 'text', text: 'No peers' }] }
      const results = connectedPeers.map(p => sendEncrypted(p, args.text, args.type ?? 'info', null, undefined))
      return { content: [{ type: 'text', text: `Broadcast (${connectedPeers.length}): ${results.join('; ')}` }] }
    }

    case 'myc_peers': {
      const lines = connectedPeers.map(p => {
        const s = peerSessions.get(p)
        if (!s) return `${p} 🔴 BLOCKED (TOFU violation or no keys)`
        return `${p} ${s.tofuStatus === 'new' ? '🆕' : '🔒'}`
      })
      const blocked = [...pendingTrustKeys.keys()].filter(p => !peerSessions.has(p))
      if (blocked.length) {
        lines.push(`\n🔴 BLOCKED: ${blocked.join(', ')} — use myc_trust after fingerprint verification`)
      }
      return { content: [{ type: 'text', text: lines.length ? lines.join('\n') : 'No peers' }] }
    }

    case 'myc_trust': {
      const pk = pendingTrustKeys.get(args.peer_name)
      if (!pk) return { content: [{ type: 'text', text: `No pending key for ${args.peer_name}` }] }

      // Always show fingerprint first
      const fp = fingerprint(pk.sign_pubkey)
      if (!args.confirm) {
        return { content: [{ type: 'text', text: `🔑 ${args.peer_name} fingerprint:\n\n  ${fp}\n\nVerify this matches the peer's fingerprint (run myc_peers on that instance).\nThen call myc_trust with confirm=true.` }] }
      }
      tofuOverride(args.peer_name, pk.sign_pubkey)
      const session = processPeerKeys(args.peer_name, pk.sign_pubkey, pk.eph_enc_pubkey, pk.eph_enc_pubkey_sig)
      pendingTrustKeys.delete(args.peer_name)
      return { content: [{ type: 'text', text: session ? `✅ ${args.peer_name} trusted (${fp})` : `❌ Key verification failed` }] }
    }

    default:
      throw new Error(`Unknown: ${name}`)
  }
})

function sendEncrypted(target: string, text: string, msgType: string, routeTarget: string | null, requestId?: string): string {
  const s = peerSessions.get(target)
  if (!s) return `${target} 🔴BLOCKED`

  const enc = encryptFor(target, text)
  if (!enc) return `${target} ⚠️encrypt-failed`

  const msgId = makeMsgId()
  const seq = outboundSeq++
  const body: any = {
    target: routeTarget, type: msgType,
    encrypted: enc.encrypted, nonce: enc.nonce,
    e2e: true, sender: PEER, session_id: sessionId,
    payload: null, msg_id: msgId, seq,
  }
  if (requestId) body.request_id = requestId
  body.sig = canonicalSign(body)
  wsSend(body)
  if (routeTarget) trackAck(msgId, target)
  return `${target} 🔒${s.tofuStatus === 'new' ? '🆕' : ''}`
}

// Permission messages through E2E envelope
const PermReqSchema = z.object({
  method: z.literal('notifications/claude/channel/permission_request'),
  params: z.object({
    request_id: z.string(),
    tool_name: z.string(),
    description: z.string(),
    input_preview: z.string(),
  }),
})

mcp.setNotificationHandler(PermReqSchema, async ({ params }) => {
  const payload = JSON.stringify(params)
  for (const peer of connectedPeers) {
    const enc = encryptFor(peer, payload)
    if (!enc) continue
    const msgId = makeMsgId()
    const seq = outboundSeq++
    const body: any = {
      target: peer, type: '_perm_req',
      encrypted: enc.encrypted, nonce: enc.nonce,
      e2e: true, sender: PEER, session_id: sessionId,
      payload: null, msg_id: msgId, seq,
    }
    body.sig = canonicalSign(body)
    wsSend(body)
  }
})

// ===========================================================================
// PROCESS REGULAR MESSAGE (extracted for reorder buffer)
// ===========================================================================

async function processRegularMessage(msg: any): Promise<void> {
  // Hard block on bad/missing signature for E2E messages
  if (msg.e2e) {
    // sender field REQUIRED (no more !msg.sender bypass)
    if (!msg.sender) { log(`🔴 BLOCKED: missing sender field from ${msg.from}`); return }
    if (msg.sender !== msg.from) { log(`🔴 BLOCKED: sender/from mismatch: ${msg.sender} vs ${msg.from}`); return }
    if (!msg.sig) { log(`🔴 BLOCKED: unsigned e2e message from ${msg.from}`); return }
    if (!verifySig(msg.from, msg, msg.sig)) { log(`🔴 BLOCKED: bad signature from ${msg.from}`); return }
  }

  // Decrypt
  let content: string
  if (msg.e2e && msg.encrypted && msg.nonce) {
    const dec = decryptFrom(msg.from, msg.encrypted, msg.nonce)
    content = dec ?? `[⚠️ Decrypt failed from ${msg.from}]`
  } else {
    content = typeof msg.payload === 'string' ? msg.payload : JSON.stringify(msg.payload)
  }

  const session = peerSessions.get(msg.from)
  const tofu = session ? (session.tofuStatus === 'new' ? '🆕' : '🔒') : '🔴'
  const sig = msg.e2e ? '✅' : (msg.sig ? '✅' : '❌unsigned')

  if (msg.msg_id && msg.from && msg.type !== '_ack') sendAck(msg.from, msg.msg_id)

  await safeNotify({
    method: 'notifications/claude/channel',
    params: {
      content,
      meta: {
        from_peer: msg.from, type: msg.type ?? 'info', room: ROOM,
        msg_id: msg.msg_id ?? '', e2e: msg.e2e ? 'encrypted' : 'plaintext', sig, tofu,
        ...(msg.request_id ? { request_id: msg.request_id } : {}),
      },
    },
  })
}

// ===========================================================================
// WEBSOCKET
// ===========================================================================

function connectRelay(): void {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer)
    reconnectTimer = null
  }

  ephKeys = genEphKeys()
  // 16-byte session ID (128-bit)
  sessionId = generateSessionId()
  outboundSeq = 0
  const url = RELAY_LIST[relayIdx % RELAY_LIST.length]
  log(`Session: ${sessionId.slice(0, 8)}... → relay ${relayIdx % RELAY_LIST.length + 1}/${RELAY_LIST.length}`)

  try {
    ws = new WebSocket(url)
  } catch (e) {
    log(`WS fail: ${e}`)
    scheduleReconnect()
    return
  }

  ws.addEventListener('open', () => {
    log('Connected, awaiting challenge...')
  })

  ws.addEventListener('message', async (event) => {
    lastServerActivity = Date.now()
    let msg: any
    try {
      msg = JSON.parse(typeof event.data === 'string' ? event.data : event.data.toString())
    } catch {
      return
    }

    if (msg.type === 'challenge') {
      // L6: Verify relay identity if fingerprint configured
      if (RELAY_FINGERPRINT && msg.relay_pubkey) {
        try {
          const rpk = fromB64(msg.relay_pubkey)
          const fp = fingerprint(msg.relay_pubkey)
          if (fp !== RELAY_FINGERPRINT) {
            log(`RELAY IDENTITY MISMATCH: expected ${RELAY_FINGERPRINT}, got ${fp}`)
            ws!.close(4099, 'relay identity mismatch')
            return
          }
          if (msg.relay_sig && msg.timestamp) {
            const nonce = fromB64(msg.nonce)
            const sigData = new Uint8Array([...nonce, ...sodium.from_string(msg.timestamp)])
            if (!sodium.crypto_sign_verify_detached(fromB64(msg.relay_sig), sigData, rpk)) {
              log(`RELAY SIG INVALID`)
              ws!.close(4099, 'relay sig invalid')
              return
            }
          }
          log(`Relay identity verified: ${fp}`)
        } catch (e) {
          log(`Relay identity check error: ${e}`)
          ws!.close(4099, 'relay identity error')
          return
        }
      }

      // L1: Sign challenge
      const nonce = fromB64(msg.nonce)
      const sigData = new Uint8Array([
        ...nonce,
        ...sodium.from_string(PEER!),
        ...sodium.from_string(ROOM),
      ])
      const challengeSig = toB64(sodium.crypto_sign_detached(sigData, ltKeys.signPrivateKey))

      // Build auth message
      const authMsg: any = {
        type: 'auth', peer: PEER, room: ROOM,
        sign_pubkey: toB64(ltKeys.signPublicKey),
        eph_enc_pubkey: toB64(ephKeys.encPublicKey),
        eph_enc_pubkey_sig: ephKeys.pubKeySig,
        session_id: sessionId,
        challenge_sig: challengeSig,
      }

      // L6: Seal token if relay pubkey available
      if (msg.relay_pubkey) {
        try {
          const relayCurvePk = sodium.crypto_sign_ed25519_pk_to_curve25519(fromB64(msg.relay_pubkey))
          authMsg.sealed_token = toB64(sodium.crypto_box_seal(sodium.from_string(TOKEN!), relayCurvePk))
        } catch {
          authMsg.token = TOKEN
        }
      } else {
        authMsg.token = TOKEN
      }

      ws!.send(JSON.stringify(authMsg))
      return
    }

    if (msg.type === 'auth_ok') {
      authenticated = true
      reconnectAttempt = 0
      peerSessions.clear()
      pendingTrustKeys.clear()

      if (msg.payload?.peers) {
        for (const [n, info] of Object.entries(msg.payload.peers) as [string, any][]) {
          if (n !== PEER) {
            const s = processPeerKeys(n, info.sign_pubkey, info.eph_enc_pubkey, info.eph_enc_pubkey_sig, info.session_id)
            if (!s && info.sign_pubkey) pendingTrustKeys.set(n, info)
          }
        }
      }
      connectedPeers = Object.keys(msg.payload?.peers ?? {}).filter(p => p !== PEER)
      startHB()
      log(`Auth OK (${connectedPeers.length} peers)`)
      return
    }

    if (msg.type === 'auth_error') {
      log(`Auth fail: ${msg.payload}`)
      authenticated = false
      return
    }

    if (msg.type === 'evicted') {
      log(`Evicted: ${msg.payload}`)
      return
    }

    if (!mcpReady || !authenticated) return

    // --- Relay control ---
    if (msg.from === '_relay') {
      if (msg.type === 'peer_joined') {
        const p = msg.payload
        if (p?.sign_pubkey && p?.eph_enc_pubkey && p?.eph_enc_pubkey_sig) {
          const session = processPeerKeys(p.peer, p.sign_pubkey, p.eph_enc_pubkey, p.eph_enc_pubkey_sig, p.session_id)
          if (!session) {
            pendingTrustKeys.set(p.peer, p)
            await safeNotify({
              method: 'notifications/claude/channel',
              params: {
                content: `🔴 TOFU VIOLATION: ${p.peer} — BLOCKED. Verify fingerprint and use myc_trust.`,
                meta: { type: 'tofu_violation', peer: p.peer },
              },
            })
          }
          updatePeerList(msg.payload.peers)
          const label = session
            ? (session.tofuStatus === 'new' ? '🆕' : '🔒')
            : '🔴BLOCKED'
          await safeNotify({
            method: 'notifications/claude/channel',
            params: {
              content: `➕ ${p.peer} ${label} — peers: ${connectedPeers.join(', ') || '(none)'}`,
              meta: { type: 'peer_joined', peer: p.peer },
            },
          })
        }
        return
      }

      if (msg.type === 'peer_left') {
        peerSessions.delete(msg.payload?.peer)
        pendingTrustKeys.delete(msg.payload?.peer)
        updatePeerList(msg.payload?.peers)
        await safeNotify({
          method: 'notifications/claude/channel',
          params: {
            content: `➖ ${msg.payload?.peer}`,
            meta: { type: 'peer_left', peer: msg.payload?.peer },
          },
        })
        return
      }

      if (msg.type === 'relay_shutdown') {
        log('Relay shutdown')
        reconnectAttempt = 0
        return
      }

      if (msg.type === 'queued') return
      return
    }

    // --- Acks (lightweight, no sig enforcement needed — authenticated encryption provides auth) ---
    if (msg.type === '_ack') {
      if (msg.e2e && msg.encrypted && msg.nonce) {
        const dec = decryptFrom(msg.from, msg.encrypted, msg.nonce)
        if (dec?.startsWith('ack:')) handleAck(dec.slice(4))
      }
      return
    }

    // --- Encrypted permission messages ---
    if (msg.type === '_perm_req') {
      if (!msg.e2e || !msg.encrypted || !msg.nonce) return // drop non-E2E perm messages
      // Hard block on bad sig
      if (!msg.sig || !msg.sender || msg.sender !== msg.from || !verifySig(msg.from, msg, msg.sig)) {
        log(`🔴 BLOCKED: bad sig on _perm_req from ${msg.from}`)
        return
      }
      const dec = decryptFrom(msg.from, msg.encrypted, msg.nonce)
      if (!dec) return
      try {
        const params = JSON.parse(dec)
        await safeNotify({
          method: 'notifications/claude/channel',
          params: {
            content: `⚠️ ${msg.from} needs approval: ${params.tool_name}: ${params.description}`,
            meta: { type: 'permission_request', from_peer: msg.from, request_id: params.request_id },
          },
        })
      } catch {}
      return
    }

    if (msg.type === '_perm_verdict') {
      if (!msg.e2e || !msg.encrypted || !msg.nonce) return
      if (!msg.sig || !msg.sender || msg.sender !== msg.from || !verifySig(msg.from, msg, msg.sig)) {
        log(`🔴 BLOCKED: bad sig on _perm_verdict from ${msg.from}`)
        return
      }
      const dec = decryptFrom(msg.from, msg.encrypted, msg.nonce)
      if (!dec) return
      try {
        const v = JSON.parse(dec)
        await safeNotify({
          method: 'notifications/claude/channel/permission' as any,
          params: { request_id: v.request_id, behavior: v.behavior },
        })
      } catch {}
      return
    }

    // --- REGULAR PEER MESSAGE ---
    const { duplicate } = checkReplay(msg.from, msg.msg_id, msg.seq, msg.session_id)
    if (duplicate) { log(`Replay BLOCKED: dup ${msg.msg_id}`); return }

    if (typeof msg.seq === 'number' && msg.session_id) {
      bufferInsert(msg.from, msg.session_id, msg.seq, msg)
      await bufferFlush(msg.from, msg.session_id, processRegularMessage)
    } else {
      await processRegularMessage(msg)
    }
  })

  ws.addEventListener('close', (e) => {
    log(`Disconnected (${(e as any).reason || (e as any).code})`)
    connectedPeers = []
    authenticated = false
    ws = null
    stopHB()
    scheduleReconnect()
  })

  ws.addEventListener('error', () => {})
}

function updatePeerList(peersMap: any): void {
  if (!peersMap || typeof peersMap !== 'object') return
  connectedPeers = Object.keys(peersMap).filter(p => p !== PEER)
  for (const [n, info] of Object.entries(peersMap) as [string, any][]) {
    if (n !== PEER && !peerSessions.has(n) && info.sign_pubkey && info.eph_enc_pubkey && info.eph_enc_pubkey_sig) {
      const s = processPeerKeys(n, info.sign_pubkey, info.eph_enc_pubkey, info.eph_enc_pubkey_sig, info.session_id)
      if (!s && info.sign_pubkey) pendingTrustKeys.set(n, info)
    }
  }
}

function scheduleReconnect(): void {
  if (reconnectTimer) return
  relayIdx++
  const delay = getBackoffMs()
  reconnectAttempt++
  log(`Reconnect ${(delay / 1000).toFixed(1)}s (attempt ${reconnectAttempt})`)
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null
    connectRelay()
  }, delay)
}

function wsSend(msg: any): void {
  if (ws?.readyState === WebSocket.OPEN && authenticated) {
    try { ws.send(JSON.stringify(msg)) } catch (e) { log(`Send fail: ${e}`) }
  }
}

async function safeNotify(n: any): Promise<void> {
  try { await mcp.notification(n) } catch (e) { log(`MCP fail: ${e}`) }
}

// ===========================================================================
// BOOT
// ===========================================================================

;(async () => {
  await sodium.ready

  ltKeys = loadOrGenLTKeys()
  ephKeys = genEphKeys()
  loadTofu()
  loadReplay()
  loadWAL()

  log(`Identity: ${toB64(ltKeys.signPublicKey).slice(0, 16)}...`)
  log(`Fingerprint: ${fingerprint(toB64(ltKeys.signPublicKey))}`)
  log(`TOFU: ${Object.keys(tofuStore).length} known | Replay: ${seenMsgIds.size} seen`)

  await mcp.connect(new StdioServerTransport())
  mcpReady = true
  connectRelay()

  function cleanup(): void {
    saveReplay()
    clearInterval(replayTimer)
    clearInterval(reorderTimer)
    if (reconnectTimer) clearTimeout(reconnectTimer)
    stopHB()
    for (const [, p] of pendingAcks) clearTimeout(p.timer)
    if (ws) try { ws.close(1000) } catch {}
    process.exit(0)
  }

  process.on('SIGTERM', cleanup)
  process.on('SIGINT', cleanup)
})()
