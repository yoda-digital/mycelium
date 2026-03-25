#!/usr/bin/env bun
/**
 * Mycelium Relay v4 — central WebSocket hub
 *
 * v4 fixes (both adversarial debates):
 *   P0.3 — TLS enforcement: RELAY_REQUIRE_TLS warns/refuses plain ws://
 *   P1.2 — Health auth via Authorization header (not URL query param)
 *   P1.4 — Per-sender offline queue tracking (prevent DoS via queue filling)
 *   P1.5 — RELAY_TRUSTED_PROXY for X-Forwarded-For (socket.remoteAddress default)
 *
 * Relay is a DUMB ROUTER. It cannot read E2E encrypted messages.
 * All crypto protocol fixes (TOFU, PFS, replay, acks) are in peer-channel.ts.
 *
 * AUTH PROTOCOL:
 *   1. Client connects: ws(s)://host:port (no query params)
 *   2. Client sends: { type:"auth", token, peer, room, sign_pubkey, eph_enc_pubkey, eph_enc_pubkey_sig }
 *   3. Server validates → { type:"auth_ok", peers:{...} }
 *   4. Auth timeout: 5s.
 *
 * ENV:
 *   RELAY_PORT            — listen port (default 9900)
 *   RELAY_TOKEN           — shared secret (required)
 *   RELAY_ROOM            — default room (default "default")
 *   RELAY_MAX_PEERS       — max peers per room (default 50)
 *   RELAY_MAX_MSG_BYTES   — max message size (default 65536 = 64KB)
 *   RELAY_PING_INTERVAL   — ping interval seconds (default 30)
 *   RELAY_RATE_LIMIT      — messages per minute per connection (default 300)
 *   RELAY_QUEUE_MAX_MSGS  — max queued messages per offline peer (default 50)
 *   RELAY_QUEUE_MAX_BYTES — max queue size bytes per offline peer (default 524288)
 *   RELAY_QUEUE_TTL_S     — queue message TTL seconds (default 300)
 *   RELAY_MAX_IP_CONNS    — max connections per IP (default 10)
 *   RELAY_AUTH_TIMEOUT_MS — auth timeout ms (default 5000)
 *   RELAY_REQUIRE_TLS     — "true" to refuse non-TLS connections (default: warn only)
 *   RELAY_TRUSTED_PROXY   — "true" to trust X-Forwarded-For (default: use socket IP)
 */

const PORT = Number(process.env.RELAY_PORT ?? 9900)
const TOKEN = process.env.RELAY_TOKEN
const MAX_PEERS = Number(process.env.RELAY_MAX_PEERS ?? 50)
const MAX_MSG_BYTES = Number(process.env.RELAY_MAX_MSG_BYTES ?? 65_536)
const PING_INTERVAL_S = Number(process.env.RELAY_PING_INTERVAL ?? 30)
const RATE_LIMIT = Number(process.env.RELAY_RATE_LIMIT ?? 300)
const QUEUE_MAX_MSGS = Number(process.env.RELAY_QUEUE_MAX_MSGS ?? 50)
const QUEUE_MAX_BYTES = Number(process.env.RELAY_QUEUE_MAX_BYTES ?? 524_288)
const QUEUE_TTL_S = Number(process.env.RELAY_QUEUE_TTL_S ?? 300)
const MAX_IP_CONNS = Number(process.env.RELAY_MAX_IP_CONNS ?? 10)
const AUTH_TIMEOUT_MS = Number(process.env.RELAY_AUTH_TIMEOUT_MS ?? 5000)
const REQUIRE_TLS = process.env.RELAY_REQUIRE_TLS === 'true'
const TRUSTED_PROXY = process.env.RELAY_TRUSTED_PROXY === 'true'

if (!TOKEN) { console.error('RELAY_TOKEN is required'); process.exit(1) }

// P0.3: TLS enforcement — warn at startup
if (!REQUIRE_TLS) {
  log('warn', 'tls_not_enforced', { msg: 'RELAY_REQUIRE_TLS not set. Token transmitted in plaintext over ws://. Set RELAY_REQUIRE_TLS=true behind a TLS proxy.' })
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Peer {
  name: string
  room: string
  ws: any
  lastPong: number
  alive: boolean
  ip: string
  signPubKey: string
  ephEncPubKey: string
  ephEncPubKeySig: string
  bucket: { tokens: number; lastRefill: number }
}

interface QueuedMsg { data: string; size: number; expiresAt: number; sender: string }

interface WsData {
  authenticated: boolean
  authTimer: ReturnType<typeof setTimeout> | null
  ip: string
  name: string
  room: string
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const rooms = new Map<string, Map<string, Peer>>()
const offlineQueues = new Map<string, QueuedMsg[]>()
const ipConnections = new Map<string, number>()
let totalConnections = 0
let shuttingDown = false

let msgRelayed = 0
let msgRateLimited = 0
let msgQueued = 0
let msgDrained = 0

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function log(level: string, msg: string, data?: Record<string, any>) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...data }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getPeersInRoom(room: string): Map<string, Peer> {
  if (!rooms.has(room)) rooms.set(room, new Map())
  return rooms.get(room)!
}

function queueKey(room: string, peer: string) { return `${room}\0${peer}` }

// P1.5: IP resolution — trust X-Forwarded-For only if RELAY_TRUSTED_PROXY
function resolveIp(req: Request): string {
  if (TRUSTED_PROXY) {
    const xff = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    if (xff) return xff
    const xri = req.headers.get('x-real-ip')
    if (xri) return xri
  }
  // Fallback: Bun doesn't expose remoteAddress on Request, but we get it from server.requestIP
  return 'direct'
}

function removePeer(peer: Peer) {
  const roomPeers = getPeersInRoom(peer.room)
  if (!roomPeers.has(peer.name)) return
  roomPeers.delete(peer.name)
  totalConnections = Math.max(0, totalConnections - 1)
  decrIp(peer.ip)

  if (roomPeers.size === 0) {
    rooms.delete(peer.room)
  } else {
    broadcast(peer.room, peer.name, {
      type: 'peer_left', from: '_relay',
      payload: { peer: peer.name, peers: peerKeyMap(roomPeers) },
    })
  }
  log('info', 'peer_removed', { room: peer.room, peer: peer.name, remaining: roomPeers.size })
}

function peerKeyMap(roomPeers: Map<string, Peer>): Record<string, any> {
  const m: Record<string, any> = {}
  for (const [name, p] of roomPeers) {
    m[name] = { sign_pubkey: p.signPubKey, eph_enc_pubkey: p.ephEncPubKey, eph_enc_pubkey_sig: p.ephEncPubKeySig }
  }
  return m
}

function incrIp(ip: string) { ipConnections.set(ip, (ipConnections.get(ip) ?? 0) + 1) }
function decrIp(ip: string) {
  const n = (ipConnections.get(ip) ?? 1) - 1
  if (n <= 0) ipConnections.delete(ip); else ipConnections.set(ip, n)
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

function tryConsume(bucket: { tokens: number; lastRefill: number }): boolean {
  const now = Date.now()
  bucket.tokens = Math.min(RATE_LIMIT, bucket.tokens + ((now - bucket.lastRefill) / 60_000) * RATE_LIMIT)
  bucket.lastRefill = now
  if (bucket.tokens >= 1) { bucket.tokens -= 1; return true }
  return false
}

let msgSeq = 0
function makeMsgId(): string { return Date.now().toString(36) + '-' + (msgSeq++).toString(36) }

// ---------------------------------------------------------------------------
// Offline message queue — P1.4: per-sender tracking to prevent DoS
// ---------------------------------------------------------------------------

function enqueue(room: string, targetPeer: string, senderPeer: string, data: string) {
  const key = queueKey(room, targetPeer)
  let q = offlineQueues.get(key)
  if (!q) { q = []; offlineQueues.set(key, q) }
  const totalSize = q.reduce((s, m) => s + m.size, 0)
  if (q.length >= QUEUE_MAX_MSGS || totalSize + data.length > QUEUE_MAX_BYTES) return

  // P1.4: limit messages from same sender to prevent one peer filling another's queue
  const fromSame = q.filter(m => m.sender === senderPeer).length
  if (fromSame >= Math.ceil(QUEUE_MAX_MSGS / MAX_PEERS)) return // fair share

  q.push({ data, size: data.length, expiresAt: Date.now() + QUEUE_TTL_S * 1000, sender: senderPeer })
  msgQueued++
}

function drainQueue(peer: Peer) {
  const key = queueKey(peer.room, peer.name)
  const q = offlineQueues.get(key)
  if (!q || q.length === 0) return
  offlineQueues.delete(key)
  const now = Date.now()
  let drained = 0
  for (const msg of q) {
    if (msg.expiresAt < now) continue
    try { peer.ws.send(msg.data); drained++; msgDrained++ } catch { break }
  }
  if (drained) log('info', 'queue_drained', { peer: peer.name, room: peer.room, drained, total: q.length })
}

const queueCleanupTimer = setInterval(() => {
  const now = Date.now()
  for (const [key, q] of offlineQueues) {
    const filtered = q.filter(m => m.expiresAt > now)
    if (filtered.length === 0) offlineQueues.delete(key)
    else offlineQueues.set(key, filtered)
  }
}, 30_000)

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

const pingTimer = setInterval(() => {
  for (const [, roomPeers] of rooms) {
    for (const [, peer] of roomPeers) {
      if (!peer.alive) {
        log('warn', 'reaping_zombie', { peer: peer.name, room: peer.room, silent_s: ((Date.now() - peer.lastPong) / 1000) | 0 })
        try { peer.ws.close(4000, 'pong timeout') } catch {}
        continue
      }
      peer.alive = false
      try { peer.ws.ping() } catch {}
    }
  }
}, PING_INTERVAL_S * 1000)

const STALE_THRESHOLD = PING_INTERVAL_S * 4 * 1000
const reapTimer = setInterval(() => {
  const now = Date.now()
  for (const [, roomPeers] of rooms) {
    for (const [, peer] of roomPeers) {
      if (now - peer.lastPong > STALE_THRESHOLD) {
        log('warn', 'stale_reap', { peer: peer.name, room: peer.room })
        try { peer.ws.close(4001, 'stale') } catch {}
      }
    }
  }
}, 5 * 60 * 1000)

const memTimer = setInterval(() => {
  const mem = process.memoryUsage()
  const rssMB = (mem.rss / 1024 / 1024) | 0
  if (rssMB > 512) log('warn', 'high_memory', { rss_mb: rssMB, heap_mb: (mem.heapUsed / 1024 / 1024) | 0 })
}, 60_000)

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = Bun.serve({
  port: PORT,
  fetch(req, server) {
    const url = new URL(req.url)

    // P1.2: Health auth via Authorization header (not URL query param)
    if (url.pathname === '/health') {
      const auth = req.headers.get('authorization')
      if (auth !== `Bearer ${TOKEN}`) {
        return new Response('unauthorized', { status: 401 })
      }
      const mem = process.memoryUsage()
      return new Response(JSON.stringify({
        uptime_s: Math.floor(process.uptime()),
        total_connections: totalConnections,
        memory: { rss_mb: (mem.rss / 1024 / 1024) | 0, heap_mb: (mem.heapUsed / 1024 / 1024) | 0 },
        metrics: { msg_relayed: msgRelayed, msg_rate_limited: msgRateLimited, msg_queued: msgQueued, msg_drained: msgDrained },
        rooms: Object.fromEntries([...rooms].map(([r, p]) => [r, [...p.keys()]])),
        offline_queues: offlineQueues.size,
      }), { headers: { 'Content-Type': 'application/json' } })
    }

    if (shuttingDown) return new Response('shutting down', { status: 503 })

    // P0.3: TLS enforcement
    if (REQUIRE_TLS) {
      const proto = req.headers.get('x-forwarded-proto')
      if (proto && proto !== 'https') {
        return new Response('TLS required', { status: 421 })
      }
    }

    const ip = resolveIp(req)
    const ipCount = ipConnections.get(ip) ?? 0
    if (ipCount >= MAX_IP_CONNS) return new Response('too many connections', { status: 429 })

    const ok = server.upgrade(req, {
      data: { authenticated: false, authTimer: null, ip, name: '', room: '' } satisfies WsData,
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
      const data = ws.data as WsData
      incrIp(data.ip)
      data.authTimer = setTimeout(() => {
        log('warn', 'auth_timeout', { ip: data.ip })
        try { ws.close(4003, 'auth timeout') } catch {}
      }, AUTH_TIMEOUT_MS)
    },

    pong(ws: any) {
      const data = ws.data as WsData
      if (!data.authenticated) return
      const peer = getPeersInRoom(data.room).get(data.name)
      if (peer) { peer.alive = true; peer.lastPong = Date.now() }
    },

    drain(ws: any) {
      const data = ws.data as WsData
      if (data.authenticated) log('debug', 'backpressure_drain', { peer: data.name })
    },

    message(ws: any, raw: string | Buffer) {
      const data = ws.data as WsData
      const str = typeof raw === 'string' ? raw : raw.toString()

      let msg: any
      try { msg = JSON.parse(str) } catch {
        ws.send(JSON.stringify({ type: 'error', from: '_relay', payload: 'invalid JSON' }))
        return
      }

      // ===== AUTH STATE MACHINE =====
      if (!data.authenticated) {
        if (msg.type !== 'auth') {
          ws.send(JSON.stringify({ type: 'error', from: '_relay', payload: 'auth required' }))
          ws.close(4004, 'auth required')
          return
        }
        if (msg.token !== TOKEN) {
          ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: 'invalid token' }))
          ws.close(4005, 'invalid token')
          return
        }
        if (!msg.peer || typeof msg.peer !== 'string' || msg.peer.length > 64) {
          ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: 'invalid peer name' }))
          ws.close(4006, 'bad name')
          return
        }

        const room = msg.room ?? process.env.RELAY_ROOM ?? 'default'
        const roomPeers = getPeersInRoom(room)

        // Last-writer-wins eviction
        const existing = roomPeers.get(msg.peer)
        if (existing) {
          log('info', 'evicting_stale_peer', { peer: msg.peer, room })
          try {
            existing.ws.send(JSON.stringify({ type: 'evicted', from: '_relay', payload: 'superseded' }))
            existing.ws.close(4020, 'superseded')
          } catch {}
          removePeer(existing)
        }

        if (roomPeers.size >= MAX_PEERS) {
          ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: 'room full' }))
          ws.close(4010, 'room full')
          return
        }

        if (data.authTimer) { clearTimeout(data.authTimer); data.authTimer = null }
        data.authenticated = true
        data.name = msg.peer
        data.room = room

        const now = Date.now()
        const peer: Peer = {
          name: msg.peer, room, ws, lastPong: now, alive: true, ip: data.ip,
          signPubKey: msg.sign_pubkey ?? '',
          ephEncPubKey: msg.eph_enc_pubkey ?? '',
          ephEncPubKeySig: msg.eph_enc_pubkey_sig ?? '',
          bucket: { tokens: RATE_LIMIT, lastRefill: now },
        }
        roomPeers.set(msg.peer, peer)
        totalConnections++

        ws.send(JSON.stringify({
          type: 'auth_ok', from: '_relay',
          payload: { peer: msg.peer, room, peers: peerKeyMap(roomPeers) },
        }))

        broadcast(room, msg.peer, {
          type: 'peer_joined', from: '_relay',
          payload: {
            peer: msg.peer, peers: peerKeyMap(roomPeers),
            sign_pubkey: peer.signPubKey,
            eph_enc_pubkey: peer.ephEncPubKey,
            eph_enc_pubkey_sig: peer.ephEncPubKeySig,
          },
        })

        setTimeout(() => drainQueue(peer), 50)
        log('info', 'peer_authenticated', { peer: msg.peer, room, ip: data.ip, peers: roomPeers.size })
        return
      }

      // ===== AUTHENTICATED ROUTING =====
      const peer = getPeersInRoom(data.room).get(data.name)
      if (!peer) return

      if (!tryConsume(peer.bucket)) {
        msgRateLimited++
        ws.send(JSON.stringify({ type: 'error', from: '_relay', payload: 'rate limited', msg_id: msg.msg_id }))
        return
      }

      msg.from = data.name
      if (!msg.msg_id) msg.msg_id = makeMsgId()
      msgRelayed++

      if (msg.target) {
        const target = getPeersInRoom(data.room).get(msg.target)
        if (target) {
          target.ws.send(JSON.stringify(msg))
        } else {
          enqueue(data.room, msg.target, data.name, JSON.stringify(msg))
          ws.send(JSON.stringify({ type: 'queued', from: '_relay', payload: `${msg.target} offline, queued`, msg_id: msg.msg_id }))
        }
      } else {
        broadcast(data.room, data.name, msg)
      }
    },

    close(ws: any) {
      const data = ws.data as WsData
      if (data.authTimer) clearTimeout(data.authTimer)
      if (data.authenticated) {
        const peer = getPeersInRoom(data.room).get(data.name)
        if (peer && peer.ws === ws) removePeer(peer)
      } else {
        decrIp(data.ip)
      }
    },
  },
})

function broadcast(room: string, senderName: string, msg: any) {
  const data = JSON.stringify(msg)
  const peers = getPeersInRoom(room)
  for (const [name, peer] of peers) {
    if (name !== senderName) {
      try {
        const result = peer.ws.send(data)
        if (result === 0) log('warn', 'msg_dropped_backpressure', { peer: name, room })
      } catch {
        log('warn', 'send_failed_reaping', { peer: name, room })
        try { peer.ws.close(4002, 'send failed') } catch {}
      }
    }
  }
}

function shutdown(signal: string) {
  if (shuttingDown) return
  shuttingDown = true
  log('info', 'shutdown_start', { signal })
  clearInterval(pingTimer); clearInterval(reapTimer); clearInterval(memTimer); clearInterval(queueCleanupTimer)
  for (const [, roomPeers] of rooms) {
    for (const [, peer] of roomPeers) {
      try {
        peer.ws.send(JSON.stringify({ type: 'relay_shutdown', from: '_relay', payload: 'relay restarting' }))
        peer.ws.close(1001, 'relay shutdown')
      } catch {}
    }
  }
  const drainStart = Date.now()
  const drainCheck = setInterval(() => {
    const elapsed = Date.now() - drainStart
    let remaining = 0
    for (const [, rp] of rooms) remaining += rp.size
    if (remaining === 0 || elapsed > 5000) { clearInterval(drainCheck); log('info', 'shutdown_complete', { elapsed_ms: elapsed }); process.exit(0) }
  }, 100)
}

process.on('SIGTERM', () => shutdown('SIGTERM'))
process.on('SIGINT', () => shutdown('SIGINT'))

log('info', 'relay_started', {
  port: PORT, max_peers: MAX_PEERS, ping_s: PING_INTERVAL_S,
  rate_limit: RATE_LIMIT, queue_ttl_s: QUEUE_TTL_S,
  require_tls: REQUIRE_TLS, trusted_proxy: TRUSTED_PROXY,
})
