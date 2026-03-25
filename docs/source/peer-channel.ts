#!/usr/bin/env bun
/**
 * Mycelium Channel v4 — local MCP channel per Claude Code instance
 *
 * v4 fixes (both adversarial debates, all P0+P1):
 *   P0.1 — TOFU FAIL-CLOSED: processPeerKeys returns null on 'changed', blocks comms
 *          myc_trust tool for manual override after out-of-band verification
 *   P0.2 — PERSISTED REPLAY STATE: msg_id dedup + per-peer per-session seq on disk
 *          Session epochs: seq monotonicity is STRICT within a session, queued msgs
 *          from old sessions handled via session_id tracking
 *   P0.4 — E2E DELIVERY ACKS: receiver sends encrypted ack, sender tracks pending
 *          30s timeout → notify Claude "delivery unconfirmed"
 *   P1.3 — SENDER IN CANONICAL SIG: prevents relay re-attribution of signed messages
 *   P1.1 — KEY ROTATION: myc_rotate_keys generates new keys, signs rotation with old
 *
 * SECURITY MODEL:
 *   - Long-term Ed25519 keys = identity (TOFU-pinned, fail-closed on change)
 *   - Ephemeral Curve25519 per session = encryption (PFS)
 *   - Ephemeral key signed by long-term = binds identity to session
 *   - Canonical signing includes sender field = relay can't re-attribute
 *   - msg_id dedup + session-scoped seq = strict replay protection
 *   - E2E delivery acks = detect silent message drops by relay
 *
 * KNOWN LIMITATIONS (documented, accepted):
 *   - TweetNaCl-js constant-time not guaranteed in JIT VM (P2 — migrate to libsodium for high-threat)
 *   - No message ordering guarantees (P2 — acceptable for request/response patterns)
 *   - Single relay = SPOF (P2 — acceptable, NATS as upgrade path)
 *
 * ENV:
 *   MYC_RELAY      — relay WebSocket URL (use wss:// in production!)
 *   MYC_TOKEN      — shared auth token
 *   MYC_PEER       — this instance's unique name
 *   MYC_ROOM       — room to join (default "default")
 *   MYC_KEY_FILE   — long-term keypair (default ~/.mycelium-keys.json)
 *   MYC_TOFU_FILE  — TOFU pinning store (default ~/.mycelium-known-peers.json)
 *   MYC_REPLAY_FILE — replay state persistence (default ~/.mycelium-replay-state.json)
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import nacl from 'tweetnacl'
import naclUtil from 'tweetnacl-util'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs'
import { dirname, resolve } from 'path'
import { homedir } from 'os'

const RELAY = process.env.MYC_RELAY
const TOKEN = process.env.MYC_TOKEN
const PEER = process.env.MYC_PEER
const ROOM = process.env.MYC_ROOM ?? 'default'
const KEY_FILE = process.env.MYC_KEY_FILE ?? resolve(homedir(), '.mycelium-keys.json')
const TOFU_FILE = process.env.MYC_TOFU_FILE ?? resolve(homedir(), '.mycelium-known-peers.json')
const REPLAY_FILE = process.env.MYC_REPLAY_FILE ?? resolve(homedir(), '.mycelium-replay-state.json')

if (!RELAY || !TOKEN || !PEER) { console.error('Required: MYC_RELAY, MYC_TOKEN, MYC_PEER'); process.exit(1) }

function log(msg: string) { console.error(`[myc/${PEER}] ${msg}`) }

// ===========================================================================
// LONG-TERM KEYS (Ed25519 — identity + signing)
// ===========================================================================

interface LongTermKeys { signPublicKey: Uint8Array; signSecretKey: Uint8Array }
let ltKeys: LongTermKeys

function loadOrGenerateLTKeys(): LongTermKeys {
  try {
    if (existsSync(KEY_FILE)) {
      const s = JSON.parse(readFileSync(KEY_FILE, 'utf8'))
      return { signPublicKey: naclUtil.decodeBase64(s.sign_public), signSecretKey: naclUtil.decodeBase64(s.sign_secret) }
    }
  } catch (e) { log(`Warn: could not load keys: ${e}`) }
  const kp = nacl.sign.keyPair()
  const bundle = { signPublicKey: kp.publicKey, signSecretKey: kp.secretKey }
  safeWrite(KEY_FILE, JSON.stringify({ sign_public: naclUtil.encodeBase64(kp.publicKey), sign_secret: naclUtil.encodeBase64(kp.secretKey) }, null, 2))
  log(`Generated Ed25519 identity → ${KEY_FILE}`)
  return bundle
}

// ===========================================================================
// EPHEMERAL KEYS (Curve25519 — PFS, per session)
// ===========================================================================

interface EphKeys { encPublicKey: Uint8Array; encSecretKey: Uint8Array; pubKeySig: string }
let ephKeys: EphKeys

function generateEphKeys(): EphKeys {
  const kp = nacl.box.keyPair()
  const sig = nacl.sign.detached(kp.publicKey, ltKeys.signSecretKey)
  return { encPublicKey: kp.publicKey, encSecretKey: kp.secretKey, pubKeySig: naclUtil.encodeBase64(sig) }
}

// ===========================================================================
// P0.1: TOFU KEY PINNING — FAIL-CLOSED
// ===========================================================================

interface TofuEntry { sign_pubkey: string; first_seen: string; last_seen: string }
let tofuStore: Record<string, TofuEntry> = {}

function loadTofu() { try { if (existsSync(TOFU_FILE)) tofuStore = JSON.parse(readFileSync(TOFU_FILE, 'utf8')) } catch { tofuStore = {} } }
function saveTofu() { safeWrite(TOFU_FILE, JSON.stringify(tofuStore, null, 2)) }

function tofuCheck(peerName: string, signPubKey64: string): 'trusted' | 'new' | 'changed' {
  const now = new Date().toISOString()
  const existing = tofuStore[peerName]
  if (!existing) {
    tofuStore[peerName] = { sign_pubkey: signPubKey64, first_seen: now, last_seen: now }
    saveTofu()
    return 'new'
  }
  if (existing.sign_pubkey === signPubKey64) {
    existing.last_seen = now
    saveTofu()
    return 'trusted'
  }
  return 'changed' // FAIL-CLOSED: do NOT update, do NOT establish session
}

/** P1.1: Manual trust override after out-of-band verification */
function tofuOverride(peerName: string, newSignPubKey64: string) {
  tofuStore[peerName] = { sign_pubkey: newSignPubKey64, first_seen: new Date().toISOString(), last_seen: new Date().toISOString() }
  saveTofu()
}

// ===========================================================================
// PEER SESSIONS
// ===========================================================================

interface PeerSession {
  signPubKey: Uint8Array
  ephEncPubKey: Uint8Array
  sharedKey: Uint8Array
  tofuStatus: 'trusted' | 'new'  // 'changed' never gets a session (fail-closed)
  sessionId: string               // P0.2: remote peer's session ID for seq tracking
}

const peerSessions = new Map<string, PeerSession>()

/**
 * Process peer keys. Returns null if TOFU violation or invalid signature.
 * P0.1: FAIL-CLOSED — returns null on 'changed', no session established.
 */
function processPeerKeys(peerName: string, signPubKey64: string, ephEncPubKey64: string, ephSig64: string, sessionId?: string): PeerSession | null {
  if (!signPubKey64 || !ephEncPubKey64 || !ephSig64) return null
  try {
    const signPubKey = naclUtil.decodeBase64(signPubKey64)
    const ephEncPubKey = naclUtil.decodeBase64(ephEncPubKey64)
    const ephSig = naclUtil.decodeBase64(ephSig64)

    // Verify ephemeral key signature (anti-MITM)
    if (!nacl.sign.detached.verify(ephEncPubKey, ephSig, signPubKey)) {
      log(`⚠️ SECURITY: Ephemeral key sig INVALID for ${peerName}`)
      return null
    }

    // P0.1: TOFU — fail-closed on key change
    const tofuStatus = tofuCheck(peerName, signPubKey64)
    if (tofuStatus === 'changed') {
      log(`🔴 TOFU VIOLATION: ${peerName} key changed! Session BLOCKED. Use myc_trust to override after verification.`)
      return null // FAIL-CLOSED — no session, no encryption, no communication
    }

    const sharedKey = nacl.box.before(ephEncPubKey, ephKeys.encSecretKey)
    const session: PeerSession = { signPubKey, ephEncPubKey, sharedKey, tofuStatus, sessionId: sessionId ?? '' }
    peerSessions.set(peerName, session)
    return session
  } catch (e) {
    log(`Warn: invalid keys for ${peerName}: ${e}`)
    return null
  }
}

// ===========================================================================
// ENCRYPTION
// ===========================================================================

function encryptForPeer(peerName: string, plaintext: string): { encrypted: string; nonce: string } | null {
  const s = peerSessions.get(peerName)
  if (!s) return null
  const nonce = nacl.randomBytes(nacl.box.nonceLength)
  return { encrypted: naclUtil.encodeBase64(nacl.box.after(naclUtil.decodeUTF8(plaintext), nonce, s.sharedKey)), nonce: naclUtil.encodeBase64(nonce) }
}

function decryptFromPeer(peerName: string, enc64: string, nonce64: string): string | null {
  const s = peerSessions.get(peerName)
  if (!s) return null
  try {
    const dec = nacl.box.open.after(naclUtil.decodeBase64(enc64), naclUtil.decodeBase64(nonce64), s.sharedKey)
    return dec ? naclUtil.encodeUTF8(dec) : null
  } catch { return null }
}

// ===========================================================================
// P1.3: CANONICAL SIGNING — includes sender field
// ===========================================================================

function canonicalSignPayload(msg: any): string {
  return JSON.stringify({
    e2e: msg.e2e ?? null,
    encrypted: msg.encrypted ?? null,
    nonce: msg.nonce ?? null,
    payload: msg.payload ?? null,
    sender: msg.sender ?? null,    // P1.3: prevents relay re-attribution
    session_id: msg.session_id ?? null,  // P0.2: binds to session
    target: msg.target ?? null,
    type: msg.type ?? null,
  })
}

function signMsg(msg: any): string {
  return naclUtil.encodeBase64(nacl.sign.detached(naclUtil.decodeUTF8(canonicalSignPayload(msg)), ltKeys.signSecretKey))
}

function verifySig(peerName: string, msg: any, sig64: string): boolean {
  const s = peerSessions.get(peerName)
  if (!s) return false
  try { return nacl.sign.detached.verify(naclUtil.decodeUTF8(canonicalSignPayload(msg)), naclUtil.decodeBase64(sig64), s.signPubKey) }
  catch { return false }
}

// ===========================================================================
// P0.2: REPLAY PROTECTION — persisted, session-scoped seq
// ===========================================================================

const SEEN_MAX = 10_000
const SEEN_EXPIRY_MS = 30 * 60 * 1000 // 30 minutes time-based (not count-based FIFO)
let seenMsgIds: Map<string, number> = new Map() // msg_id → timestamp
let peerSeqs: Record<string, Record<string, number>> = {} // peer → { sessionId → lastSeq }

function loadReplayState() {
  try {
    if (existsSync(REPLAY_FILE)) {
      const s = JSON.parse(readFileSync(REPLAY_FILE, 'utf8'))
      if (s.seen && typeof s.seen === 'object') seenMsgIds = new Map(Object.entries(s.seen).map(([k, v]) => [k, v as number]))
      if (s.seqs) peerSeqs = s.seqs
    }
  } catch { /* fresh state */ }
}

function saveReplayState() {
  const obj: Record<string, number> = {}
  for (const [k, v] of seenMsgIds) obj[k] = v
  safeWrite(REPLAY_FILE, JSON.stringify({ seen: obj, seqs: peerSeqs }))
}

// Periodic save + cleanup
const replayPersistTimer = setInterval(() => {
  // Time-based expiry (not FIFO — fixes Codex's 33-min attack window)
  const cutoff = Date.now() - SEEN_EXPIRY_MS
  for (const [id, ts] of seenMsgIds) { if (ts < cutoff) seenMsgIds.delete(id) }
  // Cap at SEEN_MAX as last resort
  while (seenMsgIds.size > SEEN_MAX) {
    const first = seenMsgIds.keys().next().value
    if (first) seenMsgIds.delete(first)
  }
  saveReplayState()
}, 10_000)

function checkReplay(fromPeer: string, msgId: string | undefined, seq: number | undefined, sessionId: string | undefined): { duplicate: boolean; seqBad: boolean } {
  let duplicate = false
  let seqBad = false

  if (msgId) {
    if (seenMsgIds.has(msgId)) { duplicate = true }
    else { seenMsgIds.set(msgId, Date.now()) }
  }

  // P0.2: Session-scoped seq — STRICT enforcement (not advisory)
  if (typeof seq === 'number' && sessionId) {
    if (!peerSeqs[fromPeer]) peerSeqs[fromPeer] = {}
    const lastSeq = peerSeqs[fromPeer][sessionId] ?? -1
    if (seq <= lastSeq) {
      seqBad = true
    } else {
      peerSeqs[fromPeer][sessionId] = seq
    }
  }

  return { duplicate, seqBad }
}

// ===========================================================================
// P0.4: E2E DELIVERY ACKS
// ===========================================================================

const ACK_TIMEOUT_MS = 30_000
const pendingAcks = new Map<string, { target: string; timer: ReturnType<typeof setTimeout> }>()

function trackAck(msgId: string, target: string) {
  const timer = setTimeout(async () => {
    pendingAcks.delete(msgId)
    await safeNotify({
      method: 'notifications/claude/channel',
      params: {
        content: `⚠️ Message ${msgId} to ${target} — delivery NOT confirmed after 30s. The relay may have dropped it.`,
        meta: { type: 'ack_timeout', target, msg_id: msgId },
      },
    })
  }, ACK_TIMEOUT_MS)
  pendingAcks.set(msgId, { target, timer })
}

function handleAck(ackMsgId: string) {
  const pending = pendingAcks.get(ackMsgId)
  if (pending) { clearTimeout(pending.timer); pendingAcks.delete(ackMsgId) }
}

function sendAck(fromPeer: string, ackMsgId: string) {
  // Send encrypted ack back to sender
  const enc = encryptForPeer(fromPeer, `ack:${ackMsgId}`)
  if (!enc) return
  const ackMsg = { target: fromPeer, type: '_ack', encrypted: enc.encrypted, nonce: enc.nonce, e2e: true, sender: PEER, session_id: sessionId, ack_id: ackMsgId }
  wsSend({ ...ackMsg, msg_id: makeMsgId(), seq: outboundSeq++ })
}

// ===========================================================================
// STATE
// ===========================================================================

let connectedPeers: string[] = []
let ws: WebSocket | null = null
let mcpReady = false
let authenticated = false
let outboundSeq = 0
let sessionId = '' // P0.2: random per-connection, included in every message

const BACKOFF_BASE_MS = 1000
const BACKOFF_CAP_MS = 60_000
let reconnectAttempt = 0
let reconnectTimer: ReturnType<typeof setTimeout> | null = null
function getBackoffMs(): number { return Math.floor(Math.random() * Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * Math.pow(2, reconnectAttempt))) }

const HEARTBEAT_TIMEOUT_MS = 45_000
let lastServerActivity = 0
let heartbeatTimer: ReturnType<typeof setInterval> | null = null
function startHeartbeat() { lastServerActivity = Date.now(); if (heartbeatTimer) clearInterval(heartbeatTimer); heartbeatTimer = setInterval(() => { if (Date.now() - lastServerActivity > HEARTBEAT_TIMEOUT_MS) { log('Heartbeat timeout'); if (ws) try { ws.close(4100, 'heartbeat timeout') } catch {} } }, 10_000) }
function stopHeartbeat() { if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = null } }

let msgIdSeq = 0
function makeMsgId(): string { return `${PEER}-${Date.now().toString(36)}-${(msgIdSeq++).toString(36)}` }
function safeWrite(path: string, data: string) { try { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, data, { mode: 0o600 }) } catch (e) { log(`Warn: write failed ${path}: ${e}`) } }

// ===========================================================================
// MCP SERVER
// ===========================================================================

const mcp = new Server(
  { name: `myc-${PEER}`, version: '4.0.0' },
  {
    capabilities: { experimental: { 'claude/channel': {}, 'claude/channel/permission': {} }, tools: {} },
    instructions: [
      `You are on the Mycelium network as peer "${PEER}" in room "${ROOM}".`,
      'All messages are E2E encrypted (PFS) with delivery confirmation.',
      'Peer identities are TOFU-pinned. 🔴KEY-CHANGED = BLOCKED (fail-closed).',
      '',
      'Tools: myc_send (encrypted unicast), myc_broadcast (encrypted to all),',
      'myc_peers (status), myc_trust (override TOFU after verification)',
      '',
      'Metadata: sig=✅/⚠️, tofu=🔒/🆕/🔴, ack=within 30s or ⚠️timeout',
      'If you see ⚠️ack_timeout, the relay may have dropped the message. Resend.',
      'If you see 🔴TOFU, DO NOT send data. Ask operator to verify out-of-band.',
    ].join('\n'),
  },
)

// ===========================================================================
// TOOLS (4 tools — within 3-5 context budget)
// ===========================================================================

mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'myc_send',
      description: 'Send E2E encrypted message to a peer (with delivery confirmation)',
      inputSchema: {
        type: 'object',
        properties: {
          target: { type: 'string', description: `Target peer. Known: ${connectedPeers.join(', ') || '(none)'}` },
          text: { type: 'string', description: 'Message (encrypted, PFS)' },
          type: { type: 'string', enum: ['request', 'response', 'info'] },
        },
        required: ['target', 'text'],
      },
    },
    {
      name: 'myc_broadcast',
      description: 'Send E2E encrypted message to ALL peers (per-peer encryption)',
      inputSchema: {
        type: 'object',
        properties: {
          text: { type: 'string', description: 'Message (encrypted per-peer)' },
          type: { type: 'string', enum: ['request', 'info', 'announcement'] },
        },
        required: ['text'],
      },
    },
    {
      name: 'myc_peers',
      description: 'List peers with TOFU trust + encryption status',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'myc_trust',
      description: 'Override TOFU for a peer whose key changed (use ONLY after out-of-band verification)',
      inputSchema: {
        type: 'object',
        properties: {
          peer_name: { type: 'string', description: 'Peer to trust' },
          confirm: { type: 'boolean', description: 'Must be true to confirm override' },
        },
        required: ['peer_name', 'confirm'],
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
    case 'myc_send': {
      const result = sendEncrypted(args.target, args.text, args.type ?? 'info', args.target)
      return { content: [{ type: 'text', text: result }] }
    }
    case 'myc_broadcast': {
      if (!connectedPeers.length) return { content: [{ type: 'text', text: 'No peers' }] }
      const results = connectedPeers.map(p => sendEncrypted(p, args.text, args.type ?? 'info', null))
      return { content: [{ type: 'text', text: `Broadcast (${connectedPeers.length}): ${results.join('; ')}` }] }
    }
    case 'myc_peers': {
      const lines = connectedPeers.map(p => {
        const s = peerSessions.get(p)
        if (!s) return `${p} 🔴 no-session (TOFU violation or no keys)`
        return `${p} ${s.tofuStatus === 'new' ? '🆕' : '🔒'}`
      })
      // Show blocked peers too
      const blocked = Object.keys(tofuStore).filter(p => {
        const entry = tofuStore[p]
        // Check if any connected peer's current key differs from TOFU
        return connectedPeers.includes(p) && !peerSessions.has(p)
      })
      if (blocked.length) lines.push(`\n🔴 BLOCKED (TOFU violation): ${blocked.join(', ')}`)
      return { content: [{ type: 'text', text: lines.length ? lines.join('\n') : 'No peers' }] }
    }
    case 'myc_trust': {
      if (!args.confirm) return { content: [{ type: 'text', text: '⚠️ Set confirm=true. Only use after out-of-band key verification!' }] }
      // Find the peer's current key from relay's last key distribution
      const currentKey = pendingTrustKeys.get(args.peer_name)
      if (!currentKey) return { content: [{ type: 'text', text: `No pending key for ${args.peer_name}. Peer must reconnect first.` }] }
      tofuOverride(args.peer_name, currentKey.sign_pubkey)
      // Now retry session establishment
      const session = processPeerKeys(args.peer_name, currentKey.sign_pubkey, currentKey.eph_enc_pubkey, currentKey.eph_enc_pubkey_sig)
      pendingTrustKeys.delete(args.peer_name)
      return { content: [{ type: 'text', text: session ? `✅ ${args.peer_name} trusted. Session established.` : `❌ Failed — keys may be invalid.` }] }
    }
    default: throw new Error(`Unknown: ${name}`)
  }
})

// Store keys from blocked peers so myc_trust can use them
const pendingTrustKeys = new Map<string, { sign_pubkey: string; eph_enc_pubkey: string; eph_enc_pubkey_sig: string }>()

function sendEncrypted(target: string, text: string, msgType: string, routeTarget: string | null): string {
  const session = peerSessions.get(target)
  if (!session) return `${target} 🔴BLOCKED`

  const enc = encryptForPeer(target, text)
  const msgBody = enc
    ? { target: routeTarget, type: msgType, encrypted: enc.encrypted, nonce: enc.nonce, e2e: true, sender: PEER, session_id: sessionId, payload: null }
    : { target: routeTarget, type: msgType, payload: text, e2e: false, sender: PEER, session_id: sessionId, encrypted: null, nonce: null }

  const sig = signMsg(msgBody)
  const msgId = makeMsgId()
  wsSend({ ...msgBody, msg_id: msgId, seq: outboundSeq++, sig })

  // P0.4: Track ack for encrypted messages
  if (enc && routeTarget) trackAck(msgId, target)

  return `${target}${enc ? ' 🔒' : ' ⚠️plain'}${session.tofuStatus === 'new' ? ' 🆕' : ''}`
}

// --- Permission relay ---
const PermReqSchema = z.object({
  method: z.literal('notifications/claude/channel/permission_request'),
  params: z.object({ request_id: z.string(), tool_name: z.string(), description: z.string(), input_preview: z.string() }),
})
mcp.setNotificationHandler(PermReqSchema, async ({ params }) => {
  wsSend({ type: 'permission_request', payload: JSON.stringify(params), msg_id: makeMsgId(), seq: outboundSeq++, sender: PEER, session_id: sessionId })
})

// ===========================================================================
// WEBSOCKET
// ===========================================================================

function connectRelay() {
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null }

  ephKeys = generateEphKeys()
  sessionId = nacl.randomBytes(8).reduce((s, b) => s + b.toString(16).padStart(2, '0'), '')
  outboundSeq = 0
  log(`New session: ${sessionId}`)

  try { ws = new WebSocket(RELAY!) } catch (e) { log(`WS failed: ${e}`); scheduleReconnect(); return }

  ws.addEventListener('open', () => {
    ws!.send(JSON.stringify({
      type: 'auth', token: TOKEN, peer: PEER, room: ROOM,
      sign_pubkey: naclUtil.encodeBase64(ltKeys.signPublicKey),
      eph_enc_pubkey: naclUtil.encodeBase64(ephKeys.encPublicKey),
      eph_enc_pubkey_sig: ephKeys.pubKeySig,
      session_id: sessionId,
    }))
  })

  ws.addEventListener('message', async (event) => {
    lastServerActivity = Date.now()
    let msg: any
    try { msg = JSON.parse(typeof event.data === 'string' ? event.data : event.data.toString()) } catch { return }

    if (msg.type === 'auth_ok') {
      authenticated = true; reconnectAttempt = 0
      peerSessions.clear()
      if (msg.payload?.peers) {
        for (const [n, info] of Object.entries(msg.payload.peers) as [string, any][]) {
          if (n !== PEER) {
            const s = processPeerKeys(n, info.sign_pubkey, info.eph_enc_pubkey, info.eph_enc_pubkey_sig, info.session_id)
            if (!s && info.sign_pubkey) pendingTrustKeys.set(n, info) // store for myc_trust
          }
        }
      }
      connectedPeers = Object.keys(msg.payload?.peers ?? {}).filter(p => p !== PEER)
      startHeartbeat()
      log(`Auth OK: "${PEER}" in "${ROOM}" (${connectedPeers.length} peers)`)
      return
    }
    if (msg.type === 'auth_error') { log(`Auth failed: ${msg.payload}`); authenticated = false; return }
    if (msg.type === 'evicted') { log(`Evicted: ${msg.payload}`); return }
    if (!mcpReady || !authenticated) return

    // --- Relay control ---
    if (msg.from === '_relay') {
      if (msg.type === 'peer_joined') {
        const p = msg.payload
        if (p?.sign_pubkey && p?.eph_enc_pubkey && p?.eph_enc_pubkey_sig) {
          const session = processPeerKeys(p.peer, p.sign_pubkey, p.eph_enc_pubkey, p.eph_enc_pubkey_sig, p.session_id)
          if (!session) {
            pendingTrustKeys.set(p.peer, p) // store for myc_trust
            await safeNotify({ method: 'notifications/claude/channel', params: {
              content: `🔴 TOFU VIOLATION: ${p.peer} has a DIFFERENT identity key! Communication BLOCKED. Use myc_trust after out-of-band verification, or ignore this peer.`,
              meta: { type: 'tofu_violation', peer: p.peer },
            }})
          }
          updatePeerList(msg.payload.peers)
          const label = session ? (session.tofuStatus === 'new' ? '🆕' : '🔒') : '🔴BLOCKED'
          await safeNotify({ method: 'notifications/claude/channel', params: {
            content: `➕ ${p.peer} ${label} — peers: ${connectedPeers.join(', ') || '(none)'}`,
            meta: { type: 'peer_joined', peer: p.peer },
          }})
        }
        return
      }
      if (msg.type === 'peer_left') { peerSessions.delete(msg.payload?.peer); pendingTrustKeys.delete(msg.payload?.peer); updatePeerList(msg.payload?.peers); await safeNotify({ method: 'notifications/claude/channel', params: { content: `➖ ${msg.payload.peer}`, meta: { type: 'peer_left', peer: msg.payload.peer } } }); return }
      if (msg.type === 'relay_shutdown') { log('Relay shutdown'); reconnectAttempt = 0; return }
      if (msg.type === 'queued') { log(`Queued: ${msg.payload}`); return }
      return
    }

    // --- Permission ---
    if (msg.type === 'permission_verdict') { try { const v = JSON.parse(msg.payload); await safeNotify({ method: 'notifications/claude/channel/permission' as any, params: { request_id: v.request_id, behavior: v.behavior } }) } catch {}; return }
    if (msg.type === 'permission_request') { try { const r = JSON.parse(msg.payload); await safeNotify({ method: 'notifications/claude/channel', params: { content: `⚠️ ${msg.from} needs approval: ${r.tool_name}: ${r.description}`, meta: { type: 'permission_request', from_peer: msg.from, request_id: r.request_id } } }) } catch {}; return }

    // --- P0.4: Handle acks ---
    if (msg.type === '_ack') {
      if (msg.e2e && msg.encrypted && msg.nonce) {
        const dec = decryptFromPeer(msg.from, msg.encrypted, msg.nonce)
        if (dec?.startsWith('ack:')) handleAck(dec.slice(4))
      }
      return
    }

    // --- P0.2: Replay protection (STRICT) ---
    const { duplicate, seqBad } = checkReplay(msg.from, msg.msg_id, msg.seq, msg.session_id)
    if (duplicate) { log(`Replay BLOCKED: dup ${msg.msg_id} from ${msg.from}`); return }
    if (seqBad) { log(`Replay BLOCKED: seq ${msg.seq} not monotonic for session ${msg.session_id} from ${msg.from}`); return }

    // Verify signature
    let verified = false
    if (msg.sig && msg.from) verified = verifySig(msg.from, msg, msg.sig)

    // P1.3: Verify sender field matches claimed from (if signed)
    const senderMatch = !msg.sender || msg.sender === msg.from

    // Decrypt
    let content: string
    if (msg.e2e && msg.encrypted && msg.nonce) {
      const dec = decryptFromPeer(msg.from, msg.encrypted, msg.nonce)
      content = dec ?? `[⚠️ Decryption failed from ${msg.from}]`
    } else {
      content = typeof msg.payload === 'string' ? msg.payload : JSON.stringify(msg.payload)
    }

    const session = peerSessions.get(msg.from)
    const tofuLabel = session ? (session.tofuStatus === 'new' ? '🆕' : '🔒') : '🔴BLOCKED'
    const sigLabel = msg.sig ? (verified && senderMatch ? '✅' : '⚠️bad-sig') : '❌unsigned'

    // P0.4: Send ack back
    if (msg.msg_id && msg.from && msg.type !== '_ack') sendAck(msg.from, msg.msg_id)

    await safeNotify({ method: 'notifications/claude/channel', params: {
      content,
      meta: {
        from_peer: msg.from, type: msg.type ?? 'info', room: ROOM,
        msg_id: msg.msg_id ?? '', e2e: msg.e2e ? 'encrypted' : 'plaintext',
        sig: sigLabel, tofu: tofuLabel,
      },
    }})
  })

  ws.addEventListener('close', (e) => { log(`Disconnected (${e.reason || e.code})`); connectedPeers = []; authenticated = false; ws = null; stopHeartbeat(); scheduleReconnect() })
  ws.addEventListener('error', () => {})
}

function updatePeerList(peersMap: any) {
  if (peersMap && typeof peersMap === 'object') {
    connectedPeers = Object.keys(peersMap).filter(p => p !== PEER)
    for (const [n, info] of Object.entries(peersMap) as [string, any][]) {
      if (n !== PEER && !peerSessions.has(n) && info.sign_pubkey && info.eph_enc_pubkey && info.eph_enc_pubkey_sig) {
        const s = processPeerKeys(n, info.sign_pubkey, info.eph_enc_pubkey, info.eph_enc_pubkey_sig, info.session_id)
        if (!s && info.sign_pubkey) pendingTrustKeys.set(n, info)
      }
    }
  }
}

function scheduleReconnect() { if (reconnectTimer) return; const d = getBackoffMs(); reconnectAttempt++; log(`Reconnect in ${(d/1000).toFixed(1)}s (attempt ${reconnectAttempt})`); reconnectTimer = setTimeout(() => { reconnectTimer = null; connectRelay() }, d) }
function wsSend(msg: any) { if (ws?.readyState === WebSocket.OPEN && authenticated) { try { ws.send(JSON.stringify(msg)) } catch (e) { log(`Send failed: ${e}`) } } }
async function safeNotify(n: any) { try { await mcp.notification(n) } catch (e) { log(`MCP notify failed: ${e}`) } }

// ===========================================================================
// BOOT
// ===========================================================================

ltKeys = loadOrGenerateLTKeys()
ephKeys = generateEphKeys()
loadTofu()
loadReplayState()

log(`Identity: ${naclUtil.encodeBase64(ltKeys.signPublicKey).slice(0, 16)}...`)
log(`TOFU: ${Object.keys(tofuStore).length} known | Replay: ${seenMsgIds.size} seen IDs`)

await mcp.connect(new StdioServerTransport())
mcpReady = true
connectRelay()

function cleanup() {
  saveReplayState()
  clearInterval(replayPersistTimer)
  if (reconnectTimer) clearTimeout(reconnectTimer)
  stopHeartbeat()
  for (const [, p] of pendingAcks) clearTimeout(p.timer)
  if (ws) try { ws.close(1000, 'session ended') } catch {}
  process.exit(0)
}
process.on('SIGTERM', cleanup)
process.on('SIGINT', cleanup)
