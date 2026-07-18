#!/usr/bin/env bun
/**
 * Mycelium Relay
 *
 * Challenge-response authenticated router with Ed25519 relay identity.
 * Persistent name↔key binding per room (allow-list v2). Peers verify relay
 * identity and sign the challenge. New peers need a token; known peers don't.
 * Token can be sealed (encrypted to relay's public key).
 *
 * Auth flow:
 *   1. Client connects ws(s)://host:port
 *   2. Relay sends { type:"challenge", nonce, relay_pubkey, relay_sig, timestamp, proto }
 *   3. Client signs challenge + sends auth with challenge_sig (+ token or sealed_token
 *      for new peers, + rooms[] for multi-room, + rotation continuity after a key rotation)
 *   4. Relay validates → { type:"auth_ok", peers:{...} } with all peer keys + session_ids
 *   5. Identity-bound: a name is PERSISTENTLY bound to its key (allow-list v2), so an
 *      offline peer's name cannot be squatted. Same key = evict old (reconnect),
 *      different key = reject — whether the original holder is connected or not.
 */

import sodium from 'libsodium-wrappers-sumo'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs'
import { dirname, resolve } from 'path'
import { homedir } from 'os'
import { PROTO } from './canonical.ts'

const toB64 = (x: Uint8Array) => sodium.to_base64(x, sodium.base64_variants.ORIGINAL)
const fromB64 = (x: string) => sodium.from_base64(x, sodium.base64_variants.ORIGINAL)

// Constant-time, length-independent secret comparison (both sides hashed, then memcmp).
// Prevents byte-by-byte timing discrimination on the shared token / bearer credential.
function ctEq(a: string | null | undefined, b: string): boolean {
  if (a == null) return false
  const ha = sodium.crypto_hash(sodium.from_string(a))
  const hb = sodium.crypto_hash(sodium.from_string(b))
  return sodium.memcmp(ha, hb)
}

const PORT = Number(process.env.RELAY_PORT ?? 9900)
const TOKEN = process.env.RELAY_TOKEN
const MAX_PEERS = Number(process.env.RELAY_MAX_PEERS ?? 50)
const MAX_MSG_BYTES = Number(process.env.RELAY_MAX_MSG_BYTES ?? 65_536)
const PING_INTERVAL_S = Number(process.env.RELAY_PING_INTERVAL ?? 30)
const RATE_LIMIT = Number(process.env.RELAY_RATE_LIMIT ?? 300)
const QUEUE_MAX_MSGS = Number(process.env.RELAY_QUEUE_MAX_MSGS ?? 50)
const QUEUE_MAX_BYTES = Number(process.env.RELAY_QUEUE_MAX_BYTES ?? 524_288)
// Default raised 300→3600 to match the peer's default MYC_OFFLINE_MAX_AGE_S (3600).
// If the relay drops queued mail before the sender's offline-ack window closes, the
// sender is told "FAILED" long after the message silently expired. Keep this >= the
// peers' MYC_OFFLINE_MAX_AGE_S.
const QUEUE_TTL_S = Number(process.env.RELAY_QUEUE_TTL_S ?? 3600)
const MAX_IP_CONNS = Number(process.env.RELAY_MAX_IP_CONNS ?? 10)
const AUTH_TIMEOUT_MS = Number(process.env.RELAY_AUTH_TIMEOUT_MS ?? 5000)
const REQUIRE_TLS = process.env.RELAY_REQUIRE_TLS === 'true'
const TRUSTED_PROXY = process.env.RELAY_TRUSTED_PROXY === 'true'
const RELAY_KEY_FILE = process.env.RELAY_KEY_FILE ?? resolve(homedir(), '.mycelium-relay-keys.json')
const RELAY_ALLOW_FILE = process.env.RELAY_ALLOW_FILE ?? resolve(homedir(), '.mycelium-relay-allow.json')
const REQUIRE_CHALLENGE = process.env.RELAY_REQUIRE_CHALLENGE === 'true'
const DISCOVERY = process.env.RELAY_DISCOVERY !== 'false'
const KEY_PASSPHRASE = process.env.RELAY_KEY_PASSPHRASE
const MAX_ROOMS_PER_CONN = 8
// Admin/health are split off the invite TOKEN so an invited peer can no longer read
// the social graph or revoke others. If RELAY_ADMIN_TOKEN is unset, admin is loopback-
// only (local operator); the long-lived invite TOKEN is NEVER an admin credential.
const ADMIN_TOKEN = process.env.RELAY_ADMIN_TOKEN
const HEALTH_TOKEN = process.env.RELAY_HEALTH_TOKEN

function isLoopback(ip: string): boolean {
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1' || ip === 'localhost'
}
function adminAuthorized(req: Request, ip: string): boolean {
  if (ADMIN_TOKEN) return ctEq(req.headers.get('authorization'), `Bearer ${ADMIN_TOKEN}`)
  return isLoopback(ip)
}
function healthAuthorized(req: Request, ip: string): boolean {
  if (HEALTH_TOKEN) return ctEq(req.headers.get('authorization'), `Bearer ${HEALTH_TOKEN}`)
  return adminAuthorized(req, ip)
}

if (!TOKEN) {
  console.error('RELAY_TOKEN required')
  process.exit(1)
}

interface Peer {
  name: string
  rooms: string[]
  ws: any
  lastPong: number
  alive: boolean
  ip: string
  signPubKey: string
  ephEncPubKey: string
  ephEncPubKeySig: string
  sessionId: string
  bucket: { tokens: number; lastRefill: number }
}

interface QueuedMsg {
  data: string
  size: number
  expiresAt: number
  sender: string
}

interface WsData {
  authenticated: boolean
  authTimer: ReturnType<typeof setTimeout> | null
  ip: string
  name: string
  rooms: string[]
  challengeNonce: Uint8Array | null
}

const rooms = new Map<string, Map<string, Peer>>()
const offlineQueues = new Map<string, QueuedMsg[]>()
const ipConnections = new Map<string, number>()

let totalConnections = 0
let shuttingDown = false
let msgRelayed = 0
let msgRateLimited = 0
let msgQueued = 0
let msgDrained = 0

function log(level: string, msg: string, data?: Record<string, any>): void {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...data }))
}

// Names/rooms feed compound keys with '\0' separators — reject the separator itself.
function validName(s: any): boolean {
  return typeof s === 'string' && s.length >= 1 && s.length <= 64 && !s.includes('\0')
}

function getPeersInRoom(room: string): Map<string, Peer> {
  if (!rooms.has(room)) rooms.set(room, new Map())
  return rooms.get(room)!
}

function queueKey(room: string, peer: string): string {
  return `${room}\0${peer}`
}

function resolveIp(req: Request, server: any): string {
  if (TRUSTED_PROXY) {
    return req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
      ?? req.headers.get('x-real-ip')
      ?? 'direct'
  }
  return server.requestIP(req)?.address ?? 'direct'
}

function removePeer(peer: Peer): void {
  let removedAny = false
  for (const r of peer.rooms) {
    const rp = getPeersInRoom(r)
    if (rp.get(peer.name) !== peer) continue
    rp.delete(peer.name)
    removedAny = true
    if (rp.size === 0) {
      rooms.delete(r)
    } else {
      broadcast(r, peer.name, {
        type: 'peer_left',
        from: '_relay',
        payload: { peer: peer.name, room: r, peers: peerKeyMap(rp) },
      })
    }
  }
  if (removedAny) {
    totalConnections = Math.max(0, totalConnections - 1)
    decrIp(peer.ip)
    log('info', 'peer_removed', { rooms: peer.rooms, peer: peer.name })
  }
}

// Includes session_id in key distribution
function peerKeyMap(rp: Map<string, Peer>): Record<string, any> {
  const m: Record<string, any> = {}
  for (const [n, p] of rp) {
    m[n] = {
      sign_pubkey: p.signPubKey,
      eph_enc_pubkey: p.ephEncPubKey,
      eph_enc_pubkey_sig: p.ephEncPubKeySig,
      session_id: p.sessionId,
    }
  }
  return m
}

function incrIp(ip: string): void {
  ipConnections.set(ip, (ipConnections.get(ip) ?? 0) + 1)
}

function decrIp(ip: string): void {
  const n = (ipConnections.get(ip) ?? 1) - 1
  if (n <= 0) ipConnections.delete(ip)
  else ipConnections.set(ip, n)
}

function tryConsume(bucket: { tokens: number; lastRefill: number }): boolean {
  const now = Date.now()
  bucket.tokens = Math.min(RATE_LIMIT, bucket.tokens + ((now - bucket.lastRefill) / 60_000) * RATE_LIMIT)
  bucket.lastRefill = now
  if (bucket.tokens >= 1) {
    bucket.tokens -= 1
    return true
  }
  return false
}

let msgSeq = 0
function makeMsgId(): string {
  return Date.now().toString(36) + '-' + (msgSeq++).toString(36)
}

// Fair-share uses active peers count, minimum 3
// Returns true if the message was actually queued, false if a cap discarded it — so the
// caller can tell the sender the truth instead of an unconditional "queued".
function enqueue(room: string, targetPeer: string, senderPeer: string, data: string): boolean {
  const key = queueKey(room, targetPeer)
  let q = offlineQueues.get(key)
  if (!q) {
    q = []
    offlineQueues.set(key, q)
  }

  const totalSize = q.reduce((s, m) => s + m.size, 0)
  if (q.length >= QUEUE_MAX_MSGS || totalSize + data.length > QUEUE_MAX_BYTES) return false

  const activePeers = getPeersInRoom(room).size || 1
  const perSenderMax = Math.max(3, Math.ceil(QUEUE_MAX_MSGS / activePeers))
  if (q.filter(m => m.sender === senderPeer).length >= perSenderMax) return false

  q.push({ data, size: data.length, expiresAt: Date.now() + QUEUE_TTL_S * 1000, sender: senderPeer })
  msgQueued++
  return true
}

function drainQueue(peer: Peer): void {
  for (const r of peer.rooms) {
    const key = queueKey(r, peer.name)
    const q = offlineQueues.get(key)
    if (!q || !q.length) continue
    offlineQueues.delete(key)

    const now = Date.now()
    let drained = 0
    for (const msg of q) {
      if (msg.expiresAt < now) continue
      try {
        peer.ws.send(msg.data)
        drained++
        msgDrained++
      } catch { break }
    }
    if (drained) log('info', 'queue_drained', { peer: peer.name, room: r, drained })
  }
}

const queueCleanupTimer = setInterval(() => {
  const now = Date.now()
  for (const [key, q] of offlineQueues) {
    const filtered = q.filter(m => m.expiresAt > now)
    if (!filtered.length) offlineQueues.delete(key)
    else offlineQueues.set(key, filtered)
  }
}, 30_000)

const pingTimer = setInterval(() => {
  const seen = new Set<Peer>()
  for (const [, rp] of rooms) {
    for (const [, p] of rp) {
      if (seen.has(p)) continue
      seen.add(p)
      if (!p.alive) {
        log('warn', 'reaping_zombie', { peer: p.name })
        try { p.ws.close(4000, 'pong timeout') } catch {}
        continue
      }
      p.alive = false
      try { p.ws.ping() } catch {}
    }
  }
}, PING_INTERVAL_S * 1000)

const reapTimer = setInterval(() => {
  const now = Date.now()
  const thresh = PING_INTERVAL_S * 4 * 1000
  for (const [, rp] of rooms) {
    for (const [, p] of rp) {
      if (now - p.lastPong > thresh) {
        try { p.ws.close(4001, 'stale') } catch {}
      }
    }
  }
}, 5 * 60 * 1000)

const memTimer = setInterval(() => {
  const m = process.memoryUsage()
  const rssMb = (m.rss / 1024 / 1024) | 0
  if (rssMb > 512) log('warn', 'high_memory', { rss_mb: rssMb })
}, 60_000)

if (!REQUIRE_TLS) log('warn', 'tls_not_enforced', { hint: 'Set RELAY_REQUIRE_TLS=true behind TLS proxy' })

// ===========================================================================
// RELAY IDENTITY (optionally passphrase-encrypted at rest)
// ===========================================================================

let relayKeys: { publicKey: Uint8Array; privateKey: Uint8Array }

function deriveFileKey(pass: string, salt: Uint8Array): Uint8Array {
  return sodium.crypto_pwhash(
    sodium.crypto_secretbox_KEYBYTES, pass, salt,
    sodium.crypto_pwhash_OPSLIMIT_MODERATE, sodium.crypto_pwhash_MEMLIMIT_MODERATE,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  )
}

function readKeyFile(path: string, pass: string | undefined): any | null {
  if (!existsSync(path)) return null
  const s = JSON.parse(readFileSync(path, 'utf8'))
  if (!s.cipher) return s // plaintext format
  if (!pass) {
    console.error(`${path} is passphrase-encrypted — set RELAY_KEY_PASSPHRASE`)
    process.exit(1)
  }
  try {
    const key = deriveFileKey(pass, fromB64(s.salt))
    const plain = sodium.crypto_secretbox_open_easy(fromB64(s.cipher), fromB64(s.nonce), key)
    return JSON.parse(sodium.to_string(plain))
  } catch {
    console.error(`${path}: wrong passphrase`)
    process.exit(1)
  }
}

function writeKeyFile(path: string, obj: any, pass: string | undefined): void {
  try {
    mkdirSync(dirname(path), { recursive: true })
    let out: string
    if (pass) {
      const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES)
      const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
      const key = deriveFileKey(pass, salt)
      const cipher = sodium.crypto_secretbox_easy(sodium.from_string(JSON.stringify(obj)), nonce, key)
      out = JSON.stringify({ v: 2, kdf: 'argon2id13', salt: toB64(salt), nonce: toB64(nonce), cipher: toB64(cipher) }, null, 2)
    } else {
      out = JSON.stringify(obj, null, 2)
    }
    writeFileSync(path, out, { mode: 0o600 })
  } catch (e) { log('warn', 'key_write_failed', { error: String(e) }) }
}

function loadOrGenRelayKeys(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  try {
    const s = readKeyFile(RELAY_KEY_FILE, KEY_PASSPHRASE)
    if (s) {
      const keys = { publicKey: fromB64(s.public), privateKey: fromB64(s.private) }
      // Upgrade a plaintext file to encrypted-at-rest when a passphrase is configured.
      if (KEY_PASSPHRASE && !JSON.parse(readFileSync(RELAY_KEY_FILE, 'utf8')).cipher) {
        writeKeyFile(RELAY_KEY_FILE, s, KEY_PASSPHRASE)
        log('info', 'key_file_encrypted', { file: RELAY_KEY_FILE })
      }
      return keys
    }
  } catch (e) {
    if (String(e).includes('passphrase')) throw e
  }
  const kp = sodium.crypto_sign_keypair()
  writeKeyFile(RELAY_KEY_FILE, { public: toB64(kp.publicKey), private: toB64(kp.privateKey) }, KEY_PASSPHRASE)
  return kp
}

// ===========================================================================
// ALLOW-LIST v2 — persistent name↔key binding per room
// ===========================================================================
//
// v1 stored bare pubkeys per room, so a name's binding to its key existed only
// while the peer was CONNECTED — an offline peer's name could be squatted by any
// other allow-listed key. v2 binds name→pubkey persistently (and enforces
// key→name uniqueness per room). v1 files migrate: their keys become "legacy"
// (allowed, unnamed) and adopt a binding on their first authenticated connect.

interface AllowList {
  version: 2
  bindings: Record<string, Record<string, string>>  // room → name → pubkey
  legacy: Record<string, string[]>                  // room → [pubkeys] (v1 migration)
  revoked: Record<string, string[]>                 // room → [pubkeys] — refused even WITH the token
}

let allowList: AllowList = { version: 2, bindings: {}, legacy: {}, revoked: {} }

function loadAllowList(): void {
  try {
    if (!existsSync(RELAY_ALLOW_FILE)) return
    const s = JSON.parse(readFileSync(RELAY_ALLOW_FILE, 'utf8'))
    if (s.version === 2) {
      allowList = { version: 2, bindings: s.bindings ?? {}, legacy: s.legacy ?? {}, revoked: s.revoked ?? {} }
    } else {
      // v1 format: Record<room, string[]>
      allowList = { version: 2, bindings: {}, legacy: {}, revoked: {} }
      for (const [room, keys] of Object.entries(s) as [string, any][]) {
        if (Array.isArray(keys)) allowList.legacy[room] = keys
      }
      saveAllowList()
      log('info', 'allowlist_migrated_v2', { rooms: Object.keys(allowList.legacy).length })
    }
  } catch {}
}

function saveAllowList(): void {
  try {
    mkdirSync(dirname(RELAY_ALLOW_FILE), { recursive: true })
    writeFileSync(RELAY_ALLOW_FILE, JSON.stringify(allowList, null, 2), { mode: 0o600 })
  } catch {}
}

function nameForKey(room: string, pubkey: string): string | undefined {
  const b = allowList.bindings[room]
  if (!b) return undefined
  for (const [n, k] of Object.entries(b)) if (k === pubkey) return n
  return undefined
}

type AllowStatus = 'bound' | 'migrated' | 'unknown' | 'name_conflict' | 'key_conflict' | 'revoked'

function checkAllowed(room: string, name: string, pubkey: string): AllowStatus {
  // Revocation is a blocklist, not just binding removal — a revoked key must
  // not be able to re-register itself with the (long-lived) invite token.
  if (allowList.revoked[room]?.includes(pubkey)) return 'revoked'
  const bound = allowList.bindings[room]?.[name]
  if (bound === pubkey) return 'bound'
  if (bound && bound !== pubkey) return 'name_conflict'
  const other = nameForKey(room, pubkey)
  if (other && other !== name) return 'key_conflict'
  const leg = allowList.legacy[room]
  if (leg?.includes(pubkey)) {
    addBinding(room, name, pubkey)
    allowList.legacy[room] = leg.filter(k => k !== pubkey)
    if (!allowList.legacy[room].length) delete allowList.legacy[room]
    saveAllowList()
    return 'migrated'
  }
  return 'unknown'
}

function addBinding(room: string, name: string, pubkey: string): void {
  if (!allowList.bindings[room]) allowList.bindings[room] = {}
  if (allowList.bindings[room][name] !== pubkey) {
    allowList.bindings[room][name] = pubkey
    saveAllowList()
  }
}

function revokeBinding(room: string, name?: string, pubkey?: string, undo = false): { revoked: boolean; disconnected: boolean } {
  if (undo) {
    // Un-revoke: remove the key from the blocklist (it re-registers with the token).
    let changed = false
    if (pubkey && allowList.revoked[room]?.includes(pubkey)) {
      allowList.revoked[room] = allowList.revoked[room].filter(k => k !== pubkey)
      if (!allowList.revoked[room].length) delete allowList.revoked[room]
      changed = true
      saveAllowList()
    }
    return { revoked: changed, disconnected: false }
  }
  let revoked = false
  const b = allowList.bindings[room]
  let revokedName: string | undefined
  if (b) {
    if (name && b[name]) { pubkey = b[name]; delete b[name]; revokedName = name; revoked = true }
    else if (pubkey) {
      const n = nameForKey(room, pubkey)
      if (n) { delete b[n]; revokedName = n; revoked = true }
    }
    if (b && !Object.keys(b).length) delete allowList.bindings[room]
  }
  if (pubkey && allowList.legacy[room]?.includes(pubkey)) {
    allowList.legacy[room] = allowList.legacy[room].filter(k => k !== pubkey)
    if (!allowList.legacy[room].length) delete allowList.legacy[room]
    revoked = true
  }
  if (revoked && pubkey) {
    if (!allowList.revoked[room]) allowList.revoked[room] = []
    if (!allowList.revoked[room].includes(pubkey)) allowList.revoked[room].push(pubkey)
  }
  if (revoked) saveAllowList()

  let disconnected = false
  const live = revokedName ? getPeersInRoom(room).get(revokedName) : undefined
  if (live && (!pubkey || live.signPubKey === pubkey)) {
    try {
      live.ws.send(JSON.stringify({ type: 'evicted', from: '_relay', payload: 'revoked' }))
      live.ws.close(4022, 'revoked')
    } catch {}
    disconnected = true
  }
  return { revoked, disconnected }
}

// ===========================================================================
// KEY ROTATION CONTINUITY
// ===========================================================================
//
// A rotated peer authenticates with its NEW key plus a continuity statement:
// sign(new_pubkey || peer_name || String(ts), old_secret_key). If the old key
// holds the room's name binding, the binding migrates to the new key. The
// challenge_sig (made with the new key) proves possession of the new key, the
// continuity_sig proves the old identity authorized the handover.

function applyRotation(peerName: string, roomsList: string[], newPub64: string, rot: any): string[] {
  const migrated: string[] = []
  if (!rot || typeof rot.prev_sign_pubkey !== 'string' || typeof rot.continuity_sig !== 'string') return migrated
  try {
    const prevPub = fromB64(rot.prev_sign_pubkey)
    const newPub = fromB64(newPub64)
    const tsStr = String(rot.ts ?? '')
    const bytes = new Uint8Array([...newPub, ...sodium.from_string(peerName), ...sodium.from_string(tsStr)])
    if (!sodium.crypto_sign_verify_detached(fromB64(rot.continuity_sig), bytes, prevPub)) return migrated
    for (const r of roomsList) {
      if (allowList.bindings[r]?.[peerName] === rot.prev_sign_pubkey) {
        allowList.bindings[r][peerName] = newPub64
        migrated.push(r)
      }
      const leg = allowList.legacy[r]
      if (leg?.includes(rot.prev_sign_pubkey)) {
        allowList.legacy[r] = leg.map(k => (k === rot.prev_sign_pubkey ? newPub64 : k))
      }
    }
    if (migrated.length) {
      saveAllowList()
      log('info', 'key_rotated', { peer: peerName, rooms: migrated })
    }
  } catch {}
  return migrated
}

function relayFingerprint(key: Uint8Array): string {
  const hash = sodium.crypto_hash(key)
  return Array.from(hash.slice(0, 16))
    .map((b: number) => b.toString(16).padStart(2, '0'))
    .join('')
    .match(/.{4}/g)!
    .join(':')
}

function broadcast(room: string, sender: string, msg: any): void {
  const data = JSON.stringify(msg)
  for (const [n, p] of getPeersInRoom(room)) {
    if (n === sender) continue
    try {
      const r = p.ws.send(data)
      if (r === 0) log('warn', 'backpressure_drop', { peer: n })
    } catch {
      log('warn', 'send_fail_reap', { peer: n })
      try { p.ws.close(4002, 'send failed') } catch {}
    }
  }
}

// ===========================================================================
// SERVER (wrapped in async IIFE for sodium.ready)
// ===========================================================================

;(async () => {
  await sodium.ready
  relayKeys = loadOrGenRelayKeys()
  loadAllowList()
  log('info', 'relay_identity', { fingerprint: relayFingerprint(relayKeys.publicKey) })

const server = Bun.serve<WsData>({
  port: PORT,
  fetch(req, server) {
    const url = new URL(req.url)
    const ip = resolveIp(req, server)

    if (url.pathname === '/health') {
      if (!healthAuthorized(req, ip)) {
        return new Response('unauthorized', { status: 401 })
      }
      const m = process.memoryUsage()
      return new Response(JSON.stringify({
        uptime_s: Math.floor(process.uptime()),
        total_connections: totalConnections,
        memory: { rss_mb: (m.rss / 1024 / 1024) | 0, heap_mb: (m.heapUsed / 1024 / 1024) | 0 },
        metrics: { msg_relayed: msgRelayed, msg_rate_limited: msgRateLimited, msg_queued: msgQueued, msg_drained: msgDrained },
        rooms: Object.fromEntries([...rooms].map(([r, p]) => [r, [...p.keys()]])),
        offline_queues: offlineQueues.size,
        proto: PROTO,
      }), { headers: { 'Content-Type': 'application/json' } })
    }

    // Admin: allow-list inspection + revocation (replaces "edit the JSON by hand").
    if (url.pathname === '/admin/allowlist') {
      if (!adminAuthorized(req, ip)) {
        return new Response('unauthorized', { status: 401 })
      }
      return new Response(JSON.stringify(allowList, null, 2), { headers: { 'Content-Type': 'application/json' } })
    }
    if (url.pathname === '/admin/revoke' && req.method === 'POST') {
      if (!adminAuthorized(req, ip)) {
        return new Response('unauthorized', { status: 401 })
      }
      return req.json().then((body: any) => {
        if (!validName(body?.room) || (!validName(body?.name) && typeof body?.pubkey !== 'string')) {
          return new Response(JSON.stringify({ error: 'need room + (name | pubkey)' }), { status: 400 })
        }
        const res = revokeBinding(body.room, validName(body.name) ? body.name : undefined, body.pubkey, body.undo === true)
        log('info', 'admin_revoke', { room: body.room, name: body.name, undo: body.undo === true, ...res })
        return new Response(JSON.stringify(res), { headers: { 'Content-Type': 'application/json' } })
      }).catch(() => new Response(JSON.stringify({ error: 'invalid JSON' }), { status: 400 }))
    }

    if (shuttingDown) return new Response('shutting down', { status: 503 })
    if (REQUIRE_TLS && req.headers.get('x-forwarded-proto') !== 'https') {
      return new Response('TLS required', { status: 421 })
    }

    if ((ipConnections.get(ip) ?? 0) >= MAX_IP_CONNS) {
      return new Response('too many connections', { status: 429 })
    }

    const ok = server.upgrade(req, {
      data: { authenticated: false, authTimer: null, ip, name: '', rooms: [], challengeNonce: null } satisfies WsData,
    })
    return ok ? undefined : new Response('upgrade failed', { status: 500 })
  },

  websocket: {
    perMessageDeflate: false,
    maxPayloadLength: MAX_MSG_BYTES,
    backpressureLimit: 512 * 1024,
    closeOnBackpressureLimit: true,
    sendPings: false,
    idleTimeout: 0,

    open(ws: any) {
      const d = ws.data as WsData
      incrIp(d.ip)

      const nonce = sodium.randombytes_buf(32)
      d.challengeNonce = nonce
      const ts = Date.now().toString()
      const sigData = new Uint8Array([...nonce, ...sodium.from_string(ts)])
      ws.send(JSON.stringify({
        type: 'challenge',
        nonce: toB64(nonce),
        relay_pubkey: toB64(relayKeys.publicKey),
        relay_sig: toB64(sodium.crypto_sign_detached(sigData, relayKeys.privateKey)),
        timestamp: ts,
        proto: PROTO,
      }))

      d.authTimer = setTimeout(() => {
        log('warn', 'auth_timeout', { ip: d.ip })
        try { ws.close(4003, 'auth timeout') } catch {}
      }, AUTH_TIMEOUT_MS)
    },

    pong(ws: any) {
      const d = ws.data as WsData
      if (!d.authenticated) return
      const p = getPeersInRoom(d.rooms[0] ?? '').get(d.name)
      if (p) {
        p.alive = true
        p.lastPong = Date.now()
      }
    },

    drain(ws: any) {
      const d = ws.data as WsData
      if (d.authenticated) log('debug', 'drain', { peer: d.name })
    },

    message(ws: any, raw: string | Buffer) {
      const d = ws.data as WsData
      const str = typeof raw === 'string' ? raw : raw.toString()
      let msg: any
      try {
        msg = JSON.parse(str)
      } catch {
        ws.send(JSON.stringify({ type: 'error', from: '_relay', payload: 'invalid JSON' }))
        return
      }

      if (!d.authenticated) {
        if (msg.type !== 'auth') {
          ws.send(JSON.stringify({ type: 'error', from: '_relay', payload: 'auth required' }))
          ws.close(4004, 'auth required')
          return
        }
        if (!validName(msg.peer)) {
          ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: 'invalid peer name' }))
          ws.close(4006, 'bad name')
          return
        }
        if (!msg.sign_pubkey) {
          ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: 'sign_pubkey required' }))
          ws.close(4006, 'no key')
          return
        }

        // v2 clients send rooms[]; legacy clients send room. All-or-nothing membership.
        const isV2 = Array.isArray(msg.rooms) && msg.rooms.length > 0
        const roomsReq: string[] = isV2
          ? [...new Set(msg.rooms as any[])].filter(validName) as string[]
          : [msg.room ?? process.env.RELAY_ROOM ?? 'default']
        if (!roomsReq.length || roomsReq.length > MAX_ROOMS_PER_CONN || !roomsReq.every(validName)) {
          ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: 'invalid rooms' }))
          ws.close(4006, 'bad rooms')
          return
        }

        let challengeOk = false
        if (msg.challenge_sig && d.challengeNonce) {
          try {
            const sigData = new Uint8Array([
              ...d.challengeNonce,
              ...sodium.from_string(msg.peer),
              ...sodium.from_string(roomsReq.join(',')),
            ])
            challengeOk = sodium.crypto_sign_verify_detached(
              fromB64(msg.challenge_sig), sigData, fromB64(msg.sign_pubkey),
            )
          } catch { challengeOk = false }
          if (!challengeOk) {
            ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: 'bad challenge signature' }))
            ws.close(4005, 'bad challenge sig')
            return
          }
        } else if (REQUIRE_CHALLENGE) {
          ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: 'challenge_sig required' }))
          ws.close(4005, 'challenge required')
          return
        }

        // Key rotation continuity — only honored on a proven (challenge-signed) auth,
        // so a token-only client cannot rewrite bindings it doesn't control.
        if (challengeOk && msg.rotation) {
          applyRotation(msg.peer, roomsReq, msg.sign_pubkey, msg.rotation)
        }

        // Persistent binding check per room (all-or-nothing).
        const unknownRooms: string[] = []
        for (const r of roomsReq) {
          const st = checkAllowed(r, msg.peer, msg.sign_pubkey)
          if (st === 'revoked') {
            log('warn', 'revoked_key_rejected', { peer: msg.peer, room: r })
            ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: `key revoked in room "${r}"` }))
            ws.close(4022, 'revoked')
            return
          }
          if (st === 'name_conflict') {
            log('warn', 'identity_mismatch_rejected', { peer: msg.peer, room: r })
            ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: `peer "${msg.peer}" bound to different identity in room "${r}"` }))
            ws.close(4021, 'identity mismatch')
            return
          }
          if (st === 'key_conflict') {
            log('warn', 'key_bound_to_other_name', { peer: msg.peer, room: r })
            ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: `key already bound to another name in room "${r}"` }))
            ws.close(4021, 'key conflict')
            return
          }
          if (st === 'unknown') unknownRooms.push(r)
        }

        if (unknownRooms.length) {
          // New registration for at least one room: require the invite token.
          let tokenValid = false
          if (msg.sealed_token) {
            try {
              const curvePk = sodium.crypto_sign_ed25519_pk_to_curve25519(relayKeys.publicKey)
              const curveSk = sodium.crypto_sign_ed25519_sk_to_curve25519(relayKeys.privateKey)
              const decrypted = sodium.crypto_box_seal_open(fromB64(msg.sealed_token), curvePk, curveSk)
              tokenValid = ctEq(sodium.to_string(decrypted), TOKEN!)
            } catch {}
          } else if (msg.token) {
            tokenValid = ctEq(msg.token, TOKEN!)
          }
          if (!tokenValid) {
            ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: 'invalid token' }))
            ws.close(4005, 'bad token')
            return
          }
          for (const r of unknownRooms) addBinding(r, msg.peer, msg.sign_pubkey)
          log('info', 'peer_registered', { peer: msg.peer, rooms: unknownRooms, challenge: challengeOk })
        }

        // Identity-bound eviction: same key reconnecting supersedes its old connection.
        let evicted: Peer | null = null
        for (const r of roomsReq) {
          const existing = getPeersInRoom(r).get(msg.peer)
          if (!existing) continue
          if (existing.signPubKey !== msg.sign_pubkey) {
            // Defense-in-depth: bindings should have rejected this already.
            ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: `peer "${msg.peer}" bound to different identity` }))
            ws.close(4021, 'identity mismatch')
            return
          }
          evicted = existing
        }
        if (evicted) {
          log('info', 'evicting_stale_peer', { peer: msg.peer, reason: 'same-identity-reconnect' })
          try {
            evicted.ws.send(JSON.stringify({ type: 'evicted', from: '_relay', payload: 'superseded' }))
            evicted.ws.close(4020, 'superseded')
          } catch {}
          removePeer(evicted)
        }

        for (const r of roomsReq) {
          // Re-acquire after eviction: removePeer deletes emptied room maps.
          if (getPeersInRoom(r).size >= MAX_PEERS) {
            ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: `room "${r}" full` }))
            ws.close(4010, 'full')
            return
          }
        }

        if (d.authTimer) {
          clearTimeout(d.authTimer)
          d.authTimer = null
        }
        d.authenticated = true
        d.name = msg.peer
        d.rooms = roomsReq

        const now = Date.now()
        const peer: Peer = {
          name: msg.peer, rooms: roomsReq, ws,
          lastPong: now, alive: true, ip: d.ip,
          signPubKey: msg.sign_pubkey ?? '',
          ephEncPubKey: msg.eph_enc_pubkey ?? '',
          ephEncPubKeySig: msg.eph_enc_pubkey_sig ?? '',
          sessionId: msg.session_id ?? '',
          bucket: { tokens: RATE_LIMIT, lastRefill: now },
        }
        for (const r of roomsReq) getPeersInRoom(r).set(msg.peer, peer)
        totalConnections++

        if (isV2 || msg.proto >= 2) {
          const peersByRoom: Record<string, any> = {}
          for (const r of roomsReq) peersByRoom[r] = peerKeyMap(getPeersInRoom(r))
          ws.send(JSON.stringify({
            type: 'auth_ok', from: '_relay', proto: PROTO,
            payload: { peer: msg.peer, rooms: roomsReq, peers: peersByRoom },
          }))
        } else {
          // Legacy single-room reply shape for 0.2.x peers.
          ws.send(JSON.stringify({
            type: 'auth_ok', from: '_relay',
            payload: { peer: msg.peer, room: roomsReq[0], peers: peerKeyMap(getPeersInRoom(roomsReq[0])) },
          }))
        }
        for (const r of roomsReq) {
          broadcast(r, msg.peer, {
            type: 'peer_joined', from: '_relay',
            payload: {
              peer: msg.peer, room: r, peers: peerKeyMap(getPeersInRoom(r)),
              sign_pubkey: peer.signPubKey,
              eph_enc_pubkey: peer.ephEncPubKey,
              eph_enc_pubkey_sig: peer.ephEncPubKeySig,
              session_id: peer.sessionId,
            },
          })
        }
        setTimeout(() => drainQueue(peer), 50)
        log('info', 'peer_authenticated', { peer: msg.peer, rooms: roomsReq, ip: d.ip })
        return
      }

      // === AUTHENTICATED ===
      const peer = getPeersInRoom(d.rooms[0]).get(d.name)
      if (!peer) return

      if (!tryConsume(peer.bucket)) {
        msgRateLimited++
        ws.send(JSON.stringify({ type: 'error', from: '_relay', payload: 'rate limited', msg_id: msg.msg_id }))
        return
      }

      // Room discovery (consumed by the relay, not routed).
      if (msg.type === 'list_rooms') {
        const out: any[] = []
        for (const [r, rp] of rooms) {
          const member = d.rooms.includes(r)
          if (!DISCOVERY && !member) continue
          out.push({ name: r, peers: rp.size, ...(member ? { members: [...rp.keys()] } : {}) })
        }
        ws.send(JSON.stringify({ type: 'rooms', from: '_relay', payload: { discovery: DISCOVERY, rooms: out } }))
        return
      }

      msg.from = d.name
      if (!msg.msg_id) msg.msg_id = makeMsgId()
      msgRelayed++

      // Room routing: explicit msg.room must be one of the sender's rooms.
      let room = d.rooms[0]
      if (typeof msg.room === 'string') {
        if (!d.rooms.includes(msg.room)) {
          ws.send(JSON.stringify({ type: 'error', from: '_relay', payload: `not a member of room "${msg.room}"`, msg_id: msg.msg_id }))
          return
        }
        room = msg.room
      }

      if (msg.target) {
        const t = getPeersInRoom(room).get(msg.target)
        if (t) {
          // send() returns 0 when the socket is over its backpressure limit and the frame
          // was NOT buffered — tell the sender instead of dropping it silently.
          if (t.ws.send(JSON.stringify(msg)) === 0) {
            log('warn', 'unicast_backpressure_drop', { from: d.name, target: msg.target })
            ws.send(JSON.stringify({ type: 'error', from: '_relay', payload: `${msg.target} backpressured; message dropped`, msg_id: msg.msg_id }))
          }
        } else if (msg.no_queue) {
          // Session-encrypted frames are undecryptable after the target's keys rotate,
          // so queueing them only manufactures a future decrypt failure. Fail fast; the
          // sender re-sends as an offline envelope (encrypted to the identity key).
          ws.send(JSON.stringify({ type: 'error', from: '_relay', payload: `${msg.target} offline; not queued (session frame)`, msg_id: msg.msg_id }))
        } else {
          const queued = enqueue(room, msg.target, d.name, JSON.stringify(msg))
          ws.send(JSON.stringify({
            type: queued ? 'queued' : 'error', from: '_relay',
            payload: queued ? `${msg.target} offline` : `${msg.target} offline; queue full, message dropped`,
            msg_id: msg.msg_id,
            ...(queued ? { ttl_s: QUEUE_TTL_S } : {}),
          }))
        }
      } else {
        broadcast(room, d.name, msg)
      }
    },

    close(ws: any) {
      const d = ws.data as WsData
      if (d.authTimer) clearTimeout(d.authTimer)
      if (d.authenticated) {
        const p = getPeersInRoom(d.rooms[0] ?? '').get(d.name)
        if (p && p.ws === ws) removePeer(p)
      } else {
        decrIp(d.ip)
      }
    },
  },
})

function shutdown(sig: string): void {
  if (shuttingDown) return
  shuttingDown = true
  log('info', 'shutdown_start', { signal: sig })

  clearInterval(pingTimer)
  clearInterval(reapTimer)
  clearInterval(memTimer)
  clearInterval(queueCleanupTimer)

  const seen = new Set<any>()
  for (const [, rp] of rooms) {
    for (const [, p] of rp) {
      if (seen.has(p.ws)) continue
      seen.add(p.ws)
      try {
        p.ws.send(JSON.stringify({ type: 'relay_shutdown', from: '_relay', payload: 'restarting' }))
        p.ws.close(1001, 'shutdown')
      } catch {}
    }
  }

  const start = Date.now()
  const drainCheck = setInterval(() => {
    let remaining = 0
    for (const [, rp] of rooms) remaining += rp.size
    if (remaining === 0 || Date.now() - start > 5000) {
      clearInterval(drainCheck)
      log('info', 'shutdown_complete')
      process.exit(0)
    }
  }, 100)
}

process.on('SIGTERM', () => shutdown('SIGTERM'))
process.on('SIGINT', () => shutdown('SIGINT'))

log('info', 'relay_started', { port: PORT, max_peers: MAX_PEERS, rate_limit: RATE_LIMIT, queue_ttl_s: QUEUE_TTL_S, require_tls: REQUIRE_TLS, proto: PROTO, discovery: DISCOVERY })

})() // end async IIFE
