#!/usr/bin/env bun
/**
 * Mycelium Relay
 *
 * Dumb router. Stores sign_pubkey for identity-binding but does NOT verify
 * signatures — all crypto enforcement is in peer-channel.ts.
 *
 * Auth flow:
 *   1. Client connects ws(s)://host:port
 *   2. Sends { type:"auth", token, peer, room, sign_pubkey, eph_enc_pubkey, eph_enc_pubkey_sig, session_id }
 *   3. Relay validates → { type:"auth_ok", peers:{...} } with all peer keys + session_ids
 *   4. Identity-bound: same sign_pubkey = evict old (reconnect), different = reject.
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

if (!TOKEN) {
  console.error('RELAY_TOKEN required')
  process.exit(1)
}

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
  room: string
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

function getPeersInRoom(room: string): Map<string, Peer> {
  if (!rooms.has(room)) rooms.set(room, new Map())
  return rooms.get(room)!
}

function queueKey(room: string, peer: string): string {
  return `${room}\0${peer}`
}

function resolveIp(req: Request): string {
  if (TRUSTED_PROXY) {
    return req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
      ?? req.headers.get('x-real-ip')
      ?? 'direct'
  }
  return 'direct'
}

function removePeer(peer: Peer): void {
  const rp = getPeersInRoom(peer.room)
  if (!rp.has(peer.name)) return
  rp.delete(peer.name)
  totalConnections = Math.max(0, totalConnections - 1)
  decrIp(peer.ip)

  if (rp.size === 0) {
    rooms.delete(peer.room)
  } else {
    broadcast(peer.room, peer.name, {
      type: 'peer_left',
      from: '_relay',
      payload: { peer: peer.name, peers: peerKeyMap(rp) },
    })
  }
  log('info', 'peer_removed', { room: peer.room, peer: peer.name, remaining: rp.size })
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
function enqueue(room: string, targetPeer: string, senderPeer: string, data: string): void {
  const key = queueKey(room, targetPeer)
  let q = offlineQueues.get(key)
  if (!q) {
    q = []
    offlineQueues.set(key, q)
  }

  const totalSize = q.reduce((s, m) => s + m.size, 0)
  if (q.length >= QUEUE_MAX_MSGS || totalSize + data.length > QUEUE_MAX_BYTES) return

  const activePeers = getPeersInRoom(room).size || 1
  const perSenderMax = Math.max(3, Math.ceil(QUEUE_MAX_MSGS / activePeers))
  if (q.filter(m => m.sender === senderPeer).length >= perSenderMax) return

  q.push({ data, size: data.length, expiresAt: Date.now() + QUEUE_TTL_S * 1000, sender: senderPeer })
  msgQueued++
}

function drainQueue(peer: Peer): void {
  const key = queueKey(peer.room, peer.name)
  const q = offlineQueues.get(key)
  if (!q || !q.length) return
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
  if (drained) log('info', 'queue_drained', { peer: peer.name, room: peer.room, drained })
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
  for (const [, rp] of rooms) {
    for (const [, p] of rp) {
      if (!p.alive) {
        log('warn', 'reaping_zombie', { peer: p.name, room: p.room })
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

const server = Bun.serve({
  port: PORT,
  fetch(req, server) {
    const url = new URL(req.url)

    if (url.pathname === '/health') {
      if (req.headers.get('authorization') !== `Bearer ${TOKEN}`) {
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
      }), { headers: { 'Content-Type': 'application/json' } })
    }

    if (shuttingDown) return new Response('shutting down', { status: 503 })
    if (REQUIRE_TLS && req.headers.get('x-forwarded-proto') !== 'https') {
      return new Response('TLS required', { status: 421 })
    }

    const ip = resolveIp(req)
    if ((ipConnections.get(ip) ?? 0) >= MAX_IP_CONNS) {
      return new Response('too many connections', { status: 429 })
    }

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
      const d = ws.data as WsData
      incrIp(d.ip)
      d.authTimer = setTimeout(() => {
        log('warn', 'auth_timeout', { ip: d.ip })
        try { ws.close(4003, 'auth timeout') } catch {}
      }, AUTH_TIMEOUT_MS)
    },

    pong(ws: any) {
      const d = ws.data as WsData
      if (!d.authenticated) return
      const p = getPeersInRoom(d.room).get(d.name)
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
        if (msg.token !== TOKEN) {
          ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: 'invalid token' }))
          ws.close(4005, 'bad token')
          return
        }
        if (!msg.peer || typeof msg.peer !== 'string' || msg.peer.length > 64) {
          ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: 'invalid peer name' }))
          ws.close(4006, 'bad name')
          return
        }
        if (!msg.sign_pubkey) {
          ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: 'sign_pubkey required' }))
          ws.close(4006, 'no key')
          return
        }

        const room = msg.room ?? process.env.RELAY_ROOM ?? 'default'
        const rp = getPeersInRoom(room)

        // Identity-bound eviction
        const existing = rp.get(msg.peer)
        if (existing) {
          if (existing.signPubKey !== msg.sign_pubkey) {
            // DIFFERENT identity claiming same name → REJECT (not evict)
            log('warn', 'identity_mismatch_rejected', {
              peer: msg.peer, room,
              existing_key: existing.signPubKey.slice(0, 16),
              new_key: msg.sign_pubkey.slice(0, 16),
            })
            ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: `peer "${msg.peer}" bound to different identity` }))
            ws.close(4021, 'identity mismatch')
            return
          }
          // SAME identity → legitimate reconnect → evict old
          log('info', 'evicting_stale_peer', { peer: msg.peer, room, reason: 'same-identity-reconnect' })
          try {
            existing.ws.send(JSON.stringify({ type: 'evicted', from: '_relay', payload: 'superseded' }))
            existing.ws.close(4020, 'superseded')
          } catch {}
          removePeer(existing)
        }

        if (rp.size >= MAX_PEERS) {
          ws.send(JSON.stringify({ type: 'auth_error', from: '_relay', payload: 'room full' }))
          ws.close(4010, 'full')
          return
        }

        if (d.authTimer) {
          clearTimeout(d.authTimer)
          d.authTimer = null
        }
        d.authenticated = true
        d.name = msg.peer
        d.room = room

        const now = Date.now()
        const peer: Peer = {
          name: msg.peer, room, ws,
          lastPong: now, alive: true, ip: d.ip,
          signPubKey: msg.sign_pubkey ?? '',
          ephEncPubKey: msg.eph_enc_pubkey ?? '',
          ephEncPubKeySig: msg.eph_enc_pubkey_sig ?? '',
          sessionId: msg.session_id ?? '',
          bucket: { tokens: RATE_LIMIT, lastRefill: now },
        }
        rp.set(msg.peer, peer)
        totalConnections++

        ws.send(JSON.stringify({
          type: 'auth_ok', from: '_relay',
          payload: { peer: msg.peer, room, peers: peerKeyMap(rp) },
        }))
        broadcast(room, msg.peer, {
          type: 'peer_joined', from: '_relay',
          payload: {
            peer: msg.peer, peers: peerKeyMap(rp),
            sign_pubkey: peer.signPubKey,
            eph_enc_pubkey: peer.ephEncPubKey,
            eph_enc_pubkey_sig: peer.ephEncPubKeySig,
            session_id: peer.sessionId,
          },
        })
        setTimeout(() => drainQueue(peer), 50)
        log('info', 'peer_authenticated', { peer: msg.peer, room, ip: d.ip, peers: rp.size })
        return
      }

      // === AUTHENTICATED ROUTING ===
      const peer = getPeersInRoom(d.room).get(d.name)
      if (!peer) return

      if (!tryConsume(peer.bucket)) {
        msgRateLimited++
        ws.send(JSON.stringify({ type: 'error', from: '_relay', payload: 'rate limited', msg_id: msg.msg_id }))
        return
      }

      msg.from = d.name
      if (!msg.msg_id) msg.msg_id = makeMsgId()
      msgRelayed++

      if (msg.target) {
        const t = getPeersInRoom(d.room).get(msg.target)
        if (t) {
          t.ws.send(JSON.stringify(msg))
        } else {
          enqueue(d.room, msg.target, d.name, JSON.stringify(msg))
          ws.send(JSON.stringify({ type: 'queued', from: '_relay', payload: `${msg.target} offline`, msg_id: msg.msg_id }))
        }
      } else {
        broadcast(d.room, d.name, msg)
      }
    },

    close(ws: any) {
      const d = ws.data as WsData
      if (d.authTimer) clearTimeout(d.authTimer)
      if (d.authenticated) {
        const p = getPeersInRoom(d.room).get(d.name)
        if (p && p.ws === ws) removePeer(p)
      } else {
        decrIp(d.ip)
      }
    },
  },
})

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

function shutdown(sig: string): void {
  if (shuttingDown) return
  shuttingDown = true
  log('info', 'shutdown_start', { signal: sig })

  clearInterval(pingTimer)
  clearInterval(reapTimer)
  clearInterval(memTimer)
  clearInterval(queueCleanupTimer)

  for (const [, rp] of rooms) {
    for (const [, p] of rp) {
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

log('info', 'relay_started', { port: PORT, max_peers: MAX_PEERS, rate_limit: RATE_LIMIT, queue_ttl_s: QUEUE_TTL_S, require_tls: REQUIRE_TLS })
