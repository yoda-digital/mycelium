#!/usr/bin/env bun
/**
 * Mycelium Peer Channel — MCP server for E2E encrypted peer messaging.
 *
 * Ed25519 identity + Curve25519 ephemeral (PFS) + NaCl authenticated encryption.
 * TOFU fail-closed (room-scoped). Canonical signatures over msg_id+seq+room.
 * Write-ahead replay log. Offline delivery via identity-key sealed envelopes
 * (signed ts freshness window; no PFS for offline frames — documented tradeoff).
 * Automatic idempotent retransmission (same msg_id; receivers dedup + re-ack).
 * Inbox fallback (myc_recv) so delivery does not depend on experimental
 * host notification support. Permission messages go through the same E2E
 * envelope. Bad/missing sig = hard block.
 *
 * Env: MYC_RELAY, MYC_TOKEN, MYC_PEER, MYC_ROOM (comma list), MYC_KEY_FILE,
 *      MYC_TOFU_FILE, MYC_REPLAY_FILE, MYC_RELAY_FINGERPRINT (comma list),
 *      MYC_KEY_PASSPHRASE, MYC_OFFLINE_MAX_AGE_S, MYC_MAX_MSG_BYTES
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import sodium from 'libsodium-wrappers-sumo'
import { existsSync, readFileSync, writeFileSync, mkdirSync, appendFileSync } from 'fs'
import { canonicalize, PROTO } from './canonical.ts'

const toB64 = (x: Uint8Array) => sodium.to_base64(x, sodium.base64_variants.ORIGINAL)
const fromB64 = (x: string) => sodium.from_base64(x, sodium.base64_variants.ORIGINAL)
import { dirname, resolve } from 'path'
import { homedir } from 'os'

const VERSION = '0.3.0'
const RELAY_LIST = (process.env.MYC_RELAY ?? '').split(',').map(s => s.trim()).filter(Boolean)
let relayIdx = 0
const TOKEN = process.env.MYC_TOKEN
const PEER = process.env.MYC_PEER
const ROOMS = [...new Set((process.env.MYC_ROOM ?? 'default').split(',').map(s => s.trim()).filter(Boolean))].slice(0, 8)
const KEY_FILE = process.env.MYC_KEY_FILE ?? resolve(homedir(), '.mycelium-keys.json')
const TOFU_FILE = process.env.MYC_TOFU_FILE ?? resolve(homedir(), '.mycelium-known-peers.json')
const REPLAY_FILE = process.env.MYC_REPLAY_FILE ?? resolve(homedir(), '.mycelium-replay-state.json')
// Comma-separated list so multi-relay failover composes with identity pinning
// (v0.2.x forced operators to choose between the two).
const RELAY_FP_SET = new Set(
  (process.env.MYC_RELAY_FINGERPRINT ?? '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean),
)
const KEY_PASSPHRASE = process.env.MYC_KEY_PASSPHRASE
const OFFLINE_MAX_AGE_MS = Number(process.env.MYC_OFFLINE_MAX_AGE_S ?? 3600) * 1000
const MAX_LOGICAL_BYTES = Number(process.env.MYC_MAX_MSG_BYTES ?? 1_048_576)

if (!RELAY_LIST.length || !TOKEN || !PEER || PEER.includes('\0') || !ROOMS.length) {
  console.error('Required: MYC_RELAY, MYC_TOKEN, MYC_PEER (and at least one MYC_ROOM)')
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

// Compound key for room-scoped state: sessions, TOFU pins, replay windows, STS.
function rk(room: string, peer: string): string {
  return `${room}\0${peer}`
}

// ===========================================================================
// LONG-TERM KEYS (Ed25519 — identity; optionally passphrase-encrypted at rest)
// ===========================================================================

interface LTKeys {
  signPublicKey: Uint8Array
  signPrivateKey: Uint8Array
  // After a rotation: the previous public key + a continuity signature
  // (sign(newPub || peerName || String(rotatedAt), oldSecret)) so relays can
  // migrate the name binding without operator intervention.
  prev?: { sign_public: string; continuity_sig: string; rotated_at: number }
}

let ltKeys: LTKeys
// Identity-derived Curve25519 keys — the stable decryption identity for offline
// (sealed-box) envelopes. Unlike session ephemerals these survive reconnects.
let idCurve: { publicKey: Uint8Array; privateKey: Uint8Array }

function deriveFileKey(pass: string, salt: Uint8Array): Uint8Array {
  return sodium.crypto_pwhash(
    sodium.crypto_secretbox_KEYBYTES, pass, salt,
    sodium.crypto_pwhash_OPSLIMIT_MODERATE, sodium.crypto_pwhash_MEMLIMIT_MODERATE,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  )
}

function readKeyFile(path: string): any | null {
  if (!existsSync(path)) return null
  const s = JSON.parse(readFileSync(path, 'utf8'))
  if (!s.cipher) return s
  if (!KEY_PASSPHRASE) {
    log(`${path} is passphrase-encrypted — set MYC_KEY_PASSPHRASE`)
    process.exit(1)
  }
  try {
    const key = deriveFileKey(KEY_PASSPHRASE, fromB64(s.salt))
    const plain = sodium.crypto_secretbox_open_easy(fromB64(s.cipher), fromB64(s.nonce), key)
    return JSON.parse(sodium.to_string(plain))
  } catch {
    log(`${path}: wrong passphrase`)
    process.exit(1)
  }
}

function writeKeyFile(path: string, obj: any): void {
  let out: string
  if (KEY_PASSPHRASE) {
    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES)
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    const key = deriveFileKey(KEY_PASSPHRASE, salt)
    const cipher = sodium.crypto_secretbox_easy(sodium.from_string(JSON.stringify(obj)), nonce, key)
    out = JSON.stringify({ v: 2, kdf: 'argon2id13', salt: toB64(salt), nonce: toB64(nonce), cipher: toB64(cipher) }, null, 2)
  } else {
    out = JSON.stringify(obj, null, 2)
  }
  safeWrite(path, out)
}

function persistLTKeys(): void {
  writeKeyFile(KEY_FILE, {
    sign_public: toB64(ltKeys.signPublicKey),
    sign_secret: toB64(ltKeys.signPrivateKey),
    ...(ltKeys.prev ? { prev: ltKeys.prev } : {}),
  })
}

function loadOrGenLTKeys(): LTKeys {
  try {
    const s = readKeyFile(KEY_FILE)
    if (s) {
      const keys: LTKeys = {
        signPublicKey: fromB64(s.sign_public),
        signPrivateKey: fromB64(s.sign_secret),
        ...(s.prev ? { prev: s.prev } : {}),
      }
      // Upgrade plaintext file to encrypted-at-rest when a passphrase is configured.
      if (KEY_PASSPHRASE && !JSON.parse(readFileSync(KEY_FILE, 'utf8')).cipher) {
        ltKeys = keys
        persistLTKeys()
        log(`Key file encrypted at rest → ${KEY_FILE}`)
      }
      return keys
    }
  } catch (e) {
    log(`Key file unreadable (${e}) — generating new identity`)
  }

  const kp = sodium.crypto_sign_keypair()
  const keys: LTKeys = { signPublicKey: kp.publicKey, signPrivateKey: kp.privateKey }
  ltKeys = keys
  persistLTKeys()
  log(`Generated Ed25519 identity → ${KEY_FILE}`)
  return keys
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
// TOFU — FAIL-CLOSED, ROOM-SCOPED (v2)
// ===========================================================================
//
// v1 keyed pins by bare peer name, so two rooms with different peers that
// happen to share a name collided into spurious violations. v2 pins per
// (room, name). A v1 file migrates by importing its (room-agnostic) pins into
// every configured room — exactly the trust the v1 semantics granted.

interface TofuEntry {
  sign_pubkey: string
  first_seen: string
  last_seen: string
}

let tofuStore: { version: 2; rooms: Record<string, Record<string, TofuEntry>> } = { version: 2, rooms: {} }

function loadTofu(): void {
  try {
    if (!existsSync(TOFU_FILE)) return
    const s = JSON.parse(readFileSync(TOFU_FILE, 'utf8'))
    if (s.version === 2) {
      tofuStore = { version: 2, rooms: s.rooms ?? {} }
      return
    }
    // v1 flat Record<name, entry> — import into every configured room.
    tofuStore = { version: 2, rooms: {} }
    for (const room of ROOMS) tofuStore.rooms[room] = { ...s }
    saveTofu()
    log(`TOFU store migrated to v2 (room-scoped)`)
  } catch {}
}

function saveTofu(): void {
  safeWrite(TOFU_FILE, JSON.stringify(tofuStore, null, 2))
}

function tofuGet(room: string, peer: string): TofuEntry | undefined {
  return tofuStore.rooms[room]?.[peer]
}

function tofuCheck(room: string, peer: string, key64: string): 'trusted' | 'new' | 'changed' {
  const now = new Date().toISOString()
  if (!tofuStore.rooms[room]) tofuStore.rooms[room] = {}
  const entry = tofuStore.rooms[room][peer]

  if (!entry) {
    tofuStore.rooms[room][peer] = { sign_pubkey: key64, first_seen: now, last_seen: now }
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

function tofuOverride(room: string, peer: string, key64: string): void {
  const now = new Date().toISOString()
  if (!tofuStore.rooms[room]) tofuStore.rooms[room] = {}
  tofuStore.rooms[room][peer] = { sign_pubkey: key64, first_seen: now, last_seen: now }
  saveTofu()
}

// Fingerprint for out-of-band verification
function fingerprint(key64: string): string {
  const bytes = fromB64(key64)
  const hash = sodium.crypto_hash(bytes) // SHA-512
  return Array.from(hash.slice(0, 16))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .match(/.{4}/g)!
    .join(':')
}

// ===========================================================================
// PEER SESSIONS (keyed by room\0peer)
// ===========================================================================

interface PeerSession {
  room: string
  peerName: string
  signPubKey: Uint8Array
  ephEncPubKey: Uint8Array
  ephSig: string
  sharedKey: Uint8Array
  tofuStatus: 'trusted' | 'new'
  sessionId: string
  stsVerified: boolean
}

const peerSessions = new Map<string, PeerSession>()
const pendingTrustKeys = new Map<string, {
  sign_pubkey: string
  eph_enc_pubkey: string
  eph_enc_pubkey_sig: string
  session_id?: string
}>()
// (room\0peer) whose STS binding signature FAILED verification. Fail-closed until
// the human re-verifies fingerprints out-of-band and runs myc_trust.
const stsFailedPeers = new Set<string>()

function processPeerKeys(
  room: string,
  peerName: string,
  signPubKey64: string,
  ephEncPubKey64: string,
  ephSig64: string,
  remoteSessionId?: string,
): PeerSession | null {
  if (!signPubKey64 || !ephEncPubKey64 || !ephSig64) return null
  const key = rk(room, peerName)
  if (stsFailedPeers.has(key)) {
    log(`🔴 BLOCKED: ${peerName}@${room} failed STS verification — myc_trust required to re-enable`)
    return null // FAIL-CLOSED until explicit human override
  }
  try {
    const signPubKey = fromB64(signPubKey64)
    const ephEncPubKey = fromB64(ephEncPubKey64)

    if (!sodium.crypto_sign_verify_detached(fromB64(ephSig64), ephEncPubKey, signPubKey)) {
      log(`⚠️ SECURITY: Bad eph key sig for ${peerName}@${room}`)
      return null
    }

    const tofu = tofuCheck(room, peerName, signPubKey64)
    if (tofu === 'changed') {
      log(`🔴 TOFU VIOLATION: ${peerName}@${room} key changed! BLOCKED.`)
      return null // FAIL-CLOSED
    }

    const sharedKey = sodium.crypto_box_beforenm(ephEncPubKey, ephKeys.encPrivateKey)
    const session: PeerSession = {
      room, peerName,
      signPubKey, ephEncPubKey, ephSig: ephSig64, sharedKey,
      tofuStatus: tofu,
      sessionId: remoteSessionId ?? '',
      stsVerified: false,
    }
    peerSessions.set(key, session)
    // Initiate STS for new peers, then flush anything waiting on this session.
    setTimeout(() => initSTS(room, peerName), 100)
    setTimeout(() => retryOutboxFor(room, peerName), 200)
    return session
  } catch (e) {
    log(`Bad keys for ${peerName}@${room}: ${e}`)
    return null
  }
}

// ===========================================================================
// STS MUTUAL AUTHENTICATION — session confirmation on top of signed key exchange
// ===========================================================================
//
// The Curve25519 ephemeral that derives the shared key is ALREADY bound to each
// peer's Ed25519 identity via `eph_enc_pubkey_sig` (verified in processPeerKeys),
// so the DH exchange is authenticated and relay-MITM-resistant before STS runs.
// STS adds an explicit, live, mutually-confirmed channel binding over BOTH session
// ephemerals + BOTH session_ids + the room (domain separation), signed with the
// long-term identity keys.
//
// Design invariants (fixing the v0.1.x collision that broke all delivery):
//   • Exactly ONE peer initiates — the lexicographically smaller name — so the two
//     symmetric peers never clobber each other's pending state.
//   • The signed bytes are a deterministic, name-ordered binding both sides derive
//     identically (no throwaway keypairs, nothing to mis-pair).
//   • STS TIMEOUT is lenient: the channel stays TOFU/eph-sig-authenticated, just
//     without the 🤝 flag (version skew or slow peers must not break delivery).
//   • STS SIGNATURE MISMATCH is fail-closed: a peer that produced a *wrong* binding
//     signature over an authenticated channel is either buggy or under active attack,
//     so the session is torn down, the peer is blocked, and the human must re-verify
//     fingerprints and run myc_trust to re-enable (same recovery as a TOFU violation).

interface STSPending {
  timer: ReturnType<typeof setTimeout>
}

const stsPending = new Map<string, STSPending>()

// Fail-closed teardown on STS binding-signature mismatch (possible MITM).
function stsFail(room: string, peerName: string, phase: string): void {
  const key = rk(room, peerName)
  const s = peerSessions.get(key)
  log(`🔴 STS VERIFICATION FAILED (${phase}) for ${peerName}@${room} — possible MITM! Session blocked.`)
  if (s) {
    // Preserve the keys so myc_trust can re-establish after out-of-band verification.
    pendingTrustKeys.set(key, {
      sign_pubkey: toB64(s.signPubKey),
      eph_enc_pubkey: toB64(s.ephEncPubKey),
      eph_enc_pubkey_sig: s.ephSig,
      session_id: s.sessionId,
    })
  }
  peerSessions.delete(key)
  stsFailedPeers.add(key)
  const pending = stsPending.get(key)
  if (pending) {
    clearTimeout(pending.timer)
    stsPending.delete(key)
  }
  deliver({
    content: `🔴 STS VERIFICATION FAILED for ${peerName} (room ${room}) — possible MITM. Messages to/from this peer are BLOCKED. Verify fingerprints out-of-band, then use myc_trust to re-enable.`,
    meta: { type: 'sts_failed', peer: peerName, room },
  })
}

function stsIsInitiator(peerName: string): boolean {
  return PEER! < peerName
}

// Deterministic binding both peers compute identically: name-ordered
// (loEph || hiEph || loSid || hiSid || room). Session+room-specific ⇒ no
// cross-session or cross-room replay.
function stsBinding(room: string, peerName: string): Uint8Array | null {
  const s = peerSessions.get(rk(room, peerName))
  if (!s) return null
  const mine = { name: PEER!, eph: ephKeys.encPublicKey, sid: sessionId }
  const theirs = { name: peerName, eph: s.ephEncPubKey, sid: s.sessionId }
  const [a, b] = mine.name < theirs.name ? [mine, theirs] : [theirs, mine]
  return new Uint8Array([
    ...a.eph, ...b.eph,
    ...sodium.from_string(a.sid), ...sodium.from_string(b.sid),
    ...sodium.from_string(room),
  ])
}

function initSTS(room: string, peerName: string): void {
  if (!stsIsInitiator(peerName)) return // responder waits for _sts_init
  const key = rk(room, peerName)
  if (!peerSessions.has(key)) return
  const enc = encryptFor(room, peerName, JSON.stringify({ sts: 'init' }))
  if (!enc) return
  sendCtrl(room, peerName, '_sts_init', enc)
  const timer = setTimeout(() => {
    stsPending.delete(key)
    log(`STS timeout for ${peerName}@${room} — TOFU/eph-sig authenticated only`)
  }, 10_000)
  stsPending.set(key, { timer })
}

// Responder: prove agreement on the binding by signing it and replying.
function handleSTSInit(room: string, fromPeer: string): void {
  const binding = stsBinding(room, fromPeer)
  if (!binding) return
  const sig = toB64(sodium.crypto_sign_detached(binding, ltKeys.signPrivateKey))
  const enc = encryptFor(room, fromPeer, JSON.stringify({ sts_sig: sig }))
  if (!enc) return
  sendCtrl(room, fromPeer, '_sts_reply', enc)
}

// Initiator: verify responder's binding signature, then confirm our own side.
function handleSTSReply(room: string, fromPeer: string, decryptedPayload: string): void {
  const key = rk(room, fromPeer)
  const s = peerSessions.get(key)
  const pending = stsPending.get(key)
  if (!s || !pending) return
  let data: any
  try { data = JSON.parse(decryptedPayload) } catch { return }
  if (!data.sts_sig) return

  const binding = stsBinding(room, fromPeer)
  if (!binding) return
  let bindingOk = false
  try { bindingOk = sodium.crypto_sign_verify_detached(fromB64(data.sts_sig), binding, s.signPubKey) } catch {}
  if (!bindingOk) {
    stsFail(room, fromPeer, 'reply')
    return
  }

  const mySig = toB64(sodium.crypto_sign_detached(binding, ltKeys.signPrivateKey))
  const enc = encryptFor(room, fromPeer, JSON.stringify({ sts_sig: mySig }))
  if (enc) sendCtrl(room, fromPeer, '_sts_complete', enc)

  s.stsVerified = true
  clearTimeout(pending.timer)
  stsPending.delete(key)
  log(`STS verified: ${fromPeer}@${room}`)
}

// Responder: verify initiator's binding signature to complete mutual confirmation.
function handleSTSComplete(room: string, fromPeer: string, decryptedPayload: string): void {
  const s = peerSessions.get(rk(room, fromPeer))
  if (!s) return
  let data: any
  try { data = JSON.parse(decryptedPayload) } catch { return }
  if (!data.sts_sig) return
  const binding = stsBinding(room, fromPeer)
  if (!binding) return
  let bindingOk = false
  try { bindingOk = sodium.crypto_sign_verify_detached(fromB64(data.sts_sig), binding, s.signPubKey) } catch {}
  if (!bindingOk) {
    stsFail(room, fromPeer, 'complete')
    return
  }
  s.stsVerified = true
  log(`STS verified (responder): ${fromPeer}@${room}`)
}

// ===========================================================================
// ENCRYPTION
// ===========================================================================

function encryptFor(room: string, peer: string, plaintext: string): { encrypted: string; nonce: string } | null {
  const s = peerSessions.get(rk(room, peer))
  if (!s) return null
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES)
  const encrypted = toB64(sodium.crypto_box_easy_afternm(sodium.from_string(plaintext), nonce, s.sharedKey))
  return { encrypted, nonce: toB64(nonce) }
}

function decryptFrom(room: string, peer: string, enc64: string, nonce64: string): string | null {
  const s = peerSessions.get(rk(room, peer))
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

// Offline envelopes: sealed to the recipient's IDENTITY-derived Curve25519 key,
// which survives reconnects — this is what makes store-and-forward decryptable.
// Tradeoff (documented): no PFS for offline frames — a future compromise of the
// recipient's identity key decrypts captured offline ciphertexts. Authenticity
// comes from the canonical Ed25519 envelope signature, verified against the
// TOFU-pinned sender key (both sides must have met at least once while online).
function sealForIdentity(signPubKey64: string, plaintext: string): string | null {
  try {
    const curvePk = sodium.crypto_sign_ed25519_pk_to_curve25519(fromB64(signPubKey64))
    return toB64(sodium.crypto_box_seal(sodium.from_string(plaintext), curvePk))
  } catch {
    return null
  }
}

function openSealed(enc64: string): string | null {
  try {
    return sodium.to_string(sodium.crypto_box_seal_open(fromB64(enc64), idCurve.publicKey, idCurve.privateKey))
  } catch {
    return null
  }
}

// ===========================================================================
// CANONICAL SIGNATURE — includes msg_id + seq + room (+ ts on offline frames)
// ===========================================================================

function canonicalSign(msg: any): string {
  return toB64(sodium.crypto_sign_detached(sodium.from_string(canonicalize(msg)), ltKeys.signPrivateKey))
}

function verifySigWithKey(signPubKey: Uint8Array, msg: any, sig64: string): boolean {
  try {
    return sodium.crypto_sign_verify_detached(
      fromB64(sig64),
      sodium.from_string(canonicalize(msg)),
      signPubKey,
    )
  } catch {
    return false
  }
}

function verifySig(room: string, peerName: string, msg: any, sig64: string): boolean {
  const s = peerSessions.get(rk(room, peerName))
  if (!s) return false
  return verifySigWithKey(s.signPubKey, msg, sig64)
}

// ===========================================================================
// STATE
// ===========================================================================

const connectedPeers = new Map<string, string[]>() // room → peer names
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

function allPeerNames(): string[] {
  const names = new Set<string>()
  for (const [, list] of connectedPeers) for (const n of list) names.add(n)
  return [...names]
}

// Rooms that currently have a live session with `target` (for room resolution).
function roomsWithPeer(target: string): string[] {
  return ROOMS.filter(r => connectedPeers.get(r)?.includes(target))
}

// ===========================================================================
// FRAME CONSTRUCTION
// ===========================================================================

// Build + sign + send an encrypted control/data frame over the CURRENT SESSION.
// Single source of truth for the on-wire envelope shape so every message type
// stays canonical-sign compatible. `no_queue` is a routing hint (deliberately
// outside the signature): session frames must fail fast at the relay instead of
// being queued into guaranteed decrypt failures — tampering with it only
// restores the old, worse behavior.
function sendCtrl(
  room: string,
  target: string,
  type: string,
  enc: { encrypted: string; nonce: string },
  extra?: Record<string, any>,
  msgId?: string,
): string {
  const body: any = {
    target, room, type,
    encrypted: enc.encrypted, nonce: enc.nonce,
    e2e: true, sender: PEER, session_id: sessionId,
    payload: null, msg_id: msgId ?? makeMsgId(), seq: outboundSeq++,
    ts: Date.now(), proto: PROTO,
    ...extra,
  }
  body.sig = canonicalSign(body)
  body.no_queue = true
  wsSend(body)
  return body.msg_id
}

// Build + sign + send an OFFLINE envelope (sealed to the target's identity key,
// queued by the relay). Requires a TOFU pin for the target. `ts` is signed and
// enforced by the receiver (freshness window) — offline frames are decryptable
// forever, so replay protection cannot rely on session rotation.
function sendOffline(
  room: string,
  target: string,
  type: string,
  plaintext: string,
  msgId?: string,
  extra?: Record<string, any>,
): string | null {
  const pin = tofuGet(room, target)
  if (!pin) return null
  const sealed = sealForIdentity(pin.sign_pubkey, plaintext)
  if (!sealed) return null
  const body: any = {
    target, room, type,
    encrypted: sealed, nonce: null,
    e2e: true, offline: true, sender: PEER, session_id: null,
    payload: null, msg_id: msgId ?? makeMsgId(), seq: null,
    ts: Date.now(), proto: PROTO,
    ...extra,
  }
  body.sig = canonicalSign(body)
  wsSend(body)
  return body.msg_id
}

// ===========================================================================
// REPLAY PROTECTION — persisted, write-ahead, session-scoped, room-scoped
// ===========================================================================

// Offline envelopes are decryptable for their whole freshness window, so dedup
// retention must OUTLIVE that window (v0.2.x's 30min would reopen replay at
// minute 31 of a 60min window).
const SEEN_EXPIRY_MS = OFFLINE_MAX_AGE_MS + 5 * 60 * 1000
const SEEN_MAX = 10_000
// Anti-replay window per (room, sender, session): highest seq seen + bitmap of
// the SEQ_WINDOW seqs at/below it (RFC 4303 style). Bit i of `mask` = seq (last - i) seen.
const SEQ_WINDOW = 64n
const SEQ_MASK_ALL = (1n << SEQ_WINDOW) - 1n
interface SeqWindow { last: number; mask: bigint }
let seenMsgIds = new Map<string, number>()
let peerSeqs: Record<string, Record<string, SeqWindow>> = {}

function loadReplay(): void {
  try {
    if (existsSync(REPLAY_FILE)) {
      const s = JSON.parse(readFileSync(REPLAY_FILE, 'utf8'))
      if (s.seen) seenMsgIds = new Map(Object.entries(s.seen).map(([k, v]) => [k, v as number]))
      if (s.seqs) {
        for (const [from, sids] of Object.entries(s.seqs) as [string, any][]) {
          // Pre-0.3.0 keys were bare peer names; scope them to the first room.
          const scoped = from.includes('\0') ? from : rk(ROOMS[0], from)
          peerSeqs[scoped] = {}
          for (const [sid, v] of Object.entries(sids) as [string, any][]) {
            // v0.2.0 persisted a bare number (strict floor) — migrate conservatively:
            // treat the whole window at/below it as seen.
            if (typeof v === 'number') peerSeqs[scoped][sid] = { last: v, mask: SEQ_MASK_ALL }
            else peerSeqs[scoped][sid] = { last: v.last, mask: BigInt('0x' + (v.mask || '0')) }
          }
        }
      }
    }
  } catch {}
}

function saveReplay(): void {
  const obj: Record<string, number> = {}
  for (const [k, v] of seenMsgIds) obj[k] = v
  const seqs: Record<string, Record<string, { last: number; mask: string }>> = {}
  for (const [from, sids] of Object.entries(peerSeqs)) {
    seqs[from] = {}
    for (const [sid, w] of Object.entries(sids)) {
      seqs[from][sid] = { last: w.last, mask: w.mask.toString(16) }
    }
  }
  safeWrite(REPLAY_FILE, JSON.stringify({ seen: obj, seqs }))
}

// Dedup key is scoped to the ROOM + SENDER so one peer cannot burn another
// peer's msg_id namespace (the relay stamps `from` to the authenticated
// identity, so it is unspoofable).
function seenKey(room: string, from: string, msgId: string): string {
  return `${room}\0${from}\0${msgId}`
}

function writeAheadMsgId(room: string, from: string, msgId: string): void {
  const key = seenKey(room, from, msgId)
  seenMsgIds.set(key, Date.now())
  try { appendFileSync(REPLAY_FILE + '.wal', key + '\n') } catch {}
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

// PURE duplicate check — commits nothing. Callers commit via commitReplay()
// only after the frame is BOTH signature-verified AND decrypted: committing on
// an undecryptable frame would burn its msg_id and make the sender's idempotent
// same-msg_id retransmission dedup-away without ever being read (the v0.2.x
// nack path could never actually recover for exactly this reason).
function checkReplay(
  room: string,
  from: string,
  msgId: string | undefined,
  seq: number | undefined,
  sid: string | undefined,
): { duplicate: boolean } {
  if (msgId && seenMsgIds.has(seenKey(room, from, msgId))) return { duplicate: true }

  // Sliding-window seq check per (room, sender, session): an exact-seen or
  // below-window seq is a replayed stale frame; an UNSEEN seq at or below `last`
  // but inside the window is a legitimately reordered frame and is accepted.
  // `seq` is covered by the signature, so an attacker cannot move a frame.
  if (typeof seq === 'number' && sid) {
    const w = peerSeqs[rk(room, from)]?.[sid]
    if (w && seq <= w.last) {
      const offset = BigInt(w.last - seq)
      if (offset >= SEQ_WINDOW) return { duplicate: true }          // below the window: stale
      if ((w.mask >> offset) & 1n) return { duplicate: true }       // exact seq already seen
    }
  }
  return { duplicate: false }
}

function commitReplay(
  room: string,
  from: string,
  msgId: string | undefined,
  seq: number | undefined,
  sid: string | undefined,
): void {
  if (msgId) writeAheadMsgId(room, from, msgId)
  if (typeof seq === 'number' && sid) {
    const key = rk(room, from)
    if (!peerSeqs[key]) peerSeqs[key] = {}
    const w = peerSeqs[key][sid] ?? { last: -1, mask: 0n }
    if (seq > w.last) {
      const shift = BigInt(seq - w.last)
      w.mask = shift >= SEQ_WINDOW ? 1n : ((w.mask << shift) | 1n) & SEQ_MASK_ALL
      w.last = seq
    } else {
      const offset = BigInt(w.last - seq)
      if (offset < SEQ_WINDOW) w.mask |= 1n << offset
    }
    peerSeqs[key][sid] = w
  }
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
// ORDERING
// ===========================================================================
//
// A peer holds ONE active relay connection at a time (sequential failover), and the
// relay forwards frames in receive order over a single TCP/WebSocket stream, so the
// application stream is already FIFO. We deliver immediately in arrival order;
// `msg_id` dedup + the signed-`seq` sliding window remain the replay defense, and
// the window tolerates reordering (relay queue drains) without dropping.

// ===========================================================================
// INBOX — host-independent delivery fallback
// ===========================================================================
//
// MCP notifications (`notifications/claude/channel`) are an EXPERIMENTAL host
// capability. Every delivery is ALSO appended here so `myc_recv` works on any
// MCP host — without this, a host that ignores the notification channel could
// send but never read.

interface InboxEntry {
  ts: number
  kind: 'message' | 'event'
  content: string
  meta: Record<string, any>
}

const INBOX_MAX = 500
const inbox: InboxEntry[] = []
let inboxDropped = 0

function deliver(params: { content: string; meta: Record<string, any> }): void {
  const kind: InboxEntry['kind'] = params.meta?.from_peer ? 'message' : 'event'
  inbox.push({ ts: Date.now(), kind, content: params.content, meta: params.meta ?? {} })
  while (inbox.length > INBOX_MAX) {
    inbox.shift()
    inboxDropped++
  }
  void safeNotify({ method: 'notifications/claude/channel', params })
}

// ===========================================================================
// E2E DELIVERY ACKS + OUTBOX (automatic idempotent retransmission)
// ===========================================================================
//
// Every tracked send lives in the outbox until acked. Retransmissions REUSE the
// original msg_id: receivers dedup on (room, sender, msg_id) and RE-ACK verified
// duplicates, so a lost ack cannot cause duplicate delivery and a lost message
// is eventually recovered without involving the model. Triggers: nack (stale
// ciphertext), relay delivery-error reports, ack timeout, target (re)appearing,
// relay reconnect. After RETRY_MAX attempts the failure is surfaced honestly.

const ACK_TIMEOUT_MS = 30_000
const OFFLINE_ACK_TIMEOUT_MS = OFFLINE_MAX_AGE_MS + 5 * 60 * 1000
const RETRY_MAX = 5
const OUTBOX_MAX = 200

interface OutboxEntry {
  room: string
  target: string
  plaintext: string
  type: string
  requestId?: string
  attempts: number
  wasOffline: boolean
  createdAt: number
}

const outbox = new Map<string, OutboxEntry>()
const pendingAcks = new Map<string, { room: string; target: string; timer: ReturnType<typeof setTimeout>; offline: boolean }>()

function trackAck(room: string, msgId: string, target: string, offline: boolean): void {
  const existing = pendingAcks.get(msgId)
  if (existing) clearTimeout(existing.timer)
  const timer = setTimeout(() => {
    pendingAcks.delete(msgId)
    if (outbox.has(msgId)) {
      resendOutbox(msgId, offline ? 'offline delivery window expired' : 'delivery NOT confirmed (30s)')
    } else {
      deliver({
        content: `⚠️ Message ${msgId} to ${target}: delivery NOT confirmed. Relay may have dropped it.`,
        meta: { type: 'ack_timeout', target, room, msg_id: msgId },
      })
    }
  }, offline ? OFFLINE_ACK_TIMEOUT_MS : ACK_TIMEOUT_MS)
  pendingAcks.set(msgId, { room, target, timer, offline })
}

function handleAck(room: string, ackMsgId: string, fromPeer: string): void {
  const p = pendingAcks.get(ackMsgId)
  // Only the peer the message was actually sent to may confirm its delivery.
  if (!p || p.target !== fromPeer || p.room !== room) return
  clearTimeout(p.timer)
  pendingAcks.delete(ackMsgId)
  const e = outbox.get(ackMsgId)
  outbox.delete(ackMsgId)
  if (e && (e.wasOffline || e.attempts > 0)) {
    // Deferred/retried deliveries get an explicit confirmation — the sender's
    // model was previously told delivery was uncertain.
    deliver({
      content: `✅ Message ${ackMsgId} to ${fromPeer} confirmed delivered.`,
      meta: { type: 'delivered', target: fromPeer, room, msg_id: ackMsgId },
    })
  }
}

function failOutbox(msgId: string, reason: string): void {
  const e = outbox.get(msgId)
  outbox.delete(msgId)
  const p = pendingAcks.get(msgId)
  if (p) {
    clearTimeout(p.timer)
    pendingAcks.delete(msgId)
  }
  if (!e) return
  deliver({
    content: `⚠️ Message ${msgId} to ${e.target} FAILED after ${e.attempts} attempt(s): ${reason}. It was NOT delivered.`,
    meta: { type: 'delivery_failed', target: e.target, room: e.room, msg_id: msgId },
  })
}

// Re-send an outbox entry over the best available path: live session first,
// offline envelope second, otherwise wait (peer_joined / reconnect re-triggers).
function resendOutbox(msgId: string, reason: string): void {
  const e = outbox.get(msgId)
  if (!e) return
  if (e.attempts >= RETRY_MAX) {
    failOutbox(msgId, reason)
    return
  }
  e.attempts++
  const key = rk(e.room, e.target)
  const extra = e.requestId ? { request_id: e.requestId } : undefined
  const p = pendingAcks.get(msgId)
  if (p) clearTimeout(p.timer)
  pendingAcks.delete(msgId)

  if (!ws || ws.readyState !== WebSocket.OPEN || !authenticated) {
    // No relay right now — reconnect flush will retry. Long watchdog as backstop.
    trackAck(e.room, msgId, e.target, true)
    return
  }
  if (peerSessions.has(key)) {
    const enc = encryptFor(e.room, e.target, e.plaintext)
    if (enc) {
      sendCtrl(e.room, e.target, e.type, enc, extra, msgId)
      trackAck(e.room, msgId, e.target, false)
      log(`↻ resent ${msgId} to ${e.target}@${e.room} via session (attempt ${e.attempts}: ${reason})`)
      return
    }
  }
  if (!pendingTrustKeys.has(key) && !stsFailedPeers.has(key) && sendOffline(e.room, e.target, e.type, e.plaintext, msgId, extra)) {
    e.wasOffline = true
    trackAck(e.room, msgId, e.target, true)
    log(`↻ resent ${msgId} to ${e.target}@${e.room} as offline envelope (attempt ${e.attempts}: ${reason})`)
    return
  }
  // No path (peer unknown/blocked): keep the entry with a long watchdog.
  trackAck(e.room, msgId, e.target, true)
}

// A session with (room, peer) just became available — flush anything waiting.
function retryOutboxFor(room: string, target: string): void {
  for (const [msgId, e] of outbox) {
    if (e.room === room && e.target === target && !pendingAcks.get(msgId)) {
      resendOutbox(msgId, 'peer reappeared')
    }
  }
}

// Relay (re)connected — flush entries queued while disconnected.
function flushOutbox(): void {
  for (const [msgId] of outbox) {
    if (!pendingAcks.get(msgId)) resendOutbox(msgId, 'relay reconnected')
  }
}

function sendAck(room: string, fromPeer: string, ackMsgId: string): void {
  ackAny(room, fromPeer, 'ack', ackMsgId)
}

// Negative ack: a signature-verified frame arrived that we could NOT decrypt
// (stale session ciphertext). Tells the sender exactly which message to resend;
// the sender's outbox resends it AUTOMATICALLY (same msg_id).
function sendNack(room: string, fromPeer: string, nackMsgId: string): void {
  ackAny(room, fromPeer, 'nack', nackMsgId)
}

// Acks/nacks travel over the session when one exists, otherwise as offline
// envelopes — an ack for an offline message must reach a sender who may
// themselves have gone offline.
function ackAny(room: string, peer: string, kind: 'ack' | 'nack', msgId: string): void {
  const payload = `${kind}:${msgId}`
  const enc = encryptFor(room, peer, payload)
  if (enc) {
    sendCtrl(room, peer, `_${kind}`, enc)
    return
  }
  sendOffline(room, peer, `_${kind}`, payload)
}

function handleNack(room: string, nackMsgId: string, fromPeer: string): void {
  const p = pendingAcks.get(nackMsgId)
  const e = outbox.get(nackMsgId)
  // Only the peer the message was addressed to may fail it — and only while it
  // is still tracked, so a spammy peer cannot mint retries for arbitrary ids.
  if (!e || e.target !== fromPeer || e.room !== room) return
  if (p) {
    clearTimeout(p.timer)
    pendingAcks.delete(nackMsgId)
  }
  // Stale ciphertext — retransmit automatically (the receiver rolled its keys).
  resendOutbox(nackMsgId, `${fromPeer} could not decrypt (stale session ciphertext)`)
}

// ===========================================================================
// CHUNKING — logical messages above the relay frame cap
// ===========================================================================
//
// The relay caps frames at RELAY_MAX_MSG_BYTES (default 64KB). Larger texts are
// split into parts; each part is an ordinary E2E message whose plaintext is a
// chunk wrapper, so parts get signatures, acks, dedup and retransmission for
// free. Receivers reassemble after decryption (chunk metadata is inside the
// authenticated ciphertext — the relay sees only opaque, same-sized-ish frames).

const CHUNK_LIMIT = 24_000 // plaintext bytes per part (fits the 64KB frame after seal+b64)
const CHUNK_ASSEMBLY_TIMEOUT_MS = 120_000
const CHUNK_MAX_BUFFERS_PER_PEER = 8

interface ChunkBuf {
  parts: Map<number, Uint8Array>
  n: number
  bytes: number
  type: string
  requestId?: string
  offline: boolean
  timer: ReturnType<typeof setTimeout>
}

const chunkBufs = new Map<string, ChunkBuf>() // room\0from\0logicalId → buf

function chunkKey(room: string, from: string, id: string): string {
  return `${room}\0${from}\0${id}`
}

function splitChunks(text: string, logicalId: string): { partId: string; plaintext: string }[] | null {
  const bytes = sodium.from_string(text)
  if (bytes.length <= CHUNK_LIMIT) return null
  const n = Math.ceil(bytes.length / CHUNK_LIMIT)
  const parts: { partId: string; plaintext: string }[] = []
  for (let i = 0; i < n; i++) {
    const slice = bytes.slice(i * CHUNK_LIMIT, (i + 1) * CHUNK_LIMIT)
    parts.push({
      partId: `${logicalId}#${i}`,
      plaintext: JSON.stringify({ __myc_chunk: { id: logicalId, i, n, data: toB64(slice) } }),
    })
  }
  return parts
}

// Returns null if the content is not a chunk part; otherwise handles buffering
// and returns the assembled message when complete (or 'partial' while waiting).
function tryChunk(
  room: string,
  from: string,
  content: string,
  msg: any,
): { content: string; n: number; logicalId: string } | 'partial' | 'invalid' | null {
  if (!content.startsWith('{"__myc_chunk"')) return null
  let c: any
  try { c = JSON.parse(content).__myc_chunk } catch { return null }
  if (!c || typeof c.id !== 'string' || !Number.isInteger(c.i) || !Number.isInteger(c.n) || typeof c.data !== 'string') return null
  if (c.n < 1 || c.n > Math.ceil(MAX_LOGICAL_BYTES / CHUNK_LIMIT) + 1 || c.i < 0 || c.i >= c.n) return 'invalid'

  const key = chunkKey(room, from, c.id)
  let buf = chunkBufs.get(key)
  if (!buf) {
    let perPeer = 0
    for (const k of chunkBufs.keys()) if (k.startsWith(`${room}\0${from}\0`)) perPeer++
    if (perPeer >= CHUNK_MAX_BUFFERS_PER_PEER) {
      log(`chunk buffer cap for ${from}@${room} — dropping ${c.id}`)
      return 'invalid'
    }
    buf = {
      parts: new Map(), n: c.n, bytes: 0,
      type: msg.type ?? 'info', requestId: msg.request_id,
      offline: msg.offline === true,
      timer: setTimeout(() => {
        chunkBufs.delete(key)
        deliver({
          content: `⚠️ Incomplete chunked message ${c.id} from ${from} (room ${room}) timed out — parts are being retransmitted automatically by the sender; if this persists, the message was lost.`,
          meta: { type: 'chunk_timeout', from_peer: from, room, msg_id: c.id },
        })
      }, CHUNK_ASSEMBLY_TIMEOUT_MS),
    }
    chunkBufs.set(key, buf)
  }
  if (c.n !== buf.n) return 'invalid'
  if (!buf.parts.has(c.i)) {
    let data: Uint8Array
    try { data = fromB64(c.data) } catch { return 'invalid' }
    buf.bytes += data.length
    if (buf.bytes > MAX_LOGICAL_BYTES) {
      clearTimeout(buf.timer)
      chunkBufs.delete(key)
      log(`chunked message ${c.id} from ${from}@${room} exceeded ${MAX_LOGICAL_BYTES} bytes — dropped`)
      return 'invalid'
    }
    buf.parts.set(c.i, data)
  }
  if (buf.parts.size < buf.n) return 'partial'

  clearTimeout(buf.timer)
  chunkBufs.delete(key)
  const total = new Uint8Array(buf.bytes)
  let off = 0
  for (let i = 0; i < buf.n; i++) {
    const part = buf.parts.get(i)!
    total.set(part, off)
    off += part.length
  }
  return { content: sodium.to_string(total), n: buf.n, logicalId: c.id }
}

// ===========================================================================
// MCP SERVER
// ===========================================================================

const mcp = new Server(
  { name: `myc-${PEER}`, version: VERSION },
  {
    capabilities: { experimental: { 'claude/channel': {}, 'claude/channel/permission': {} }, tools: {} },
    instructions: [
      `Mycelium peer "${PEER}" in room(s) "${ROOMS.join(', ')}".`,
      'All messages E2E encrypted. Signatures bind msg_id+seq+room (relay can\'t replay or re-route).',
      'Live sessions use ephemeral keys (PFS). Offline peers receive identity-key envelopes (no PFS, documented).',
      'Failed deliveries retransmit automatically; you are told only on confirmed delivery of a deferred message or terminal failure.',
      'TOFU-pinned identities — 🔴BLOCKED = fail-closed, use myc_trust after verification.',
      'Bad/missing signatures on encrypted messages = HARD BLOCKED (not delivered).',
      'Permission messages are encrypted too — relay can\'t forge approvals.',
      'Tools: myc_send, myc_broadcast, myc_recv (inbox drain — use this if notifications are not visible), myc_peers, myc_rooms, myc_trust, myc_rotate_key',
    ].join('\n'),
  },
)

mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'myc_send',
      description: 'E2E encrypted unicast (PFS when live, identity-envelope when target offline; signed, ack-tracked, auto-retransmitted)',
      inputSchema: {
        type: 'object',
        properties: {
          target: { type: 'string', description: `Peer. Known: ${allPeerNames().join(', ') || '(none)'}` },
          text: { type: 'string' },
          type: { type: 'string', description: 'request | response | info | announcement, a custom app type, or _perm_verdict (remote permission approval). Other _-prefixed types are reserved.' },
          request_id: { type: 'string', description: 'Correlate request/response pairs' },
          room: { type: 'string', description: `Room (needed only if the target name exists in several). Joined: ${ROOMS.join(', ')}` },
        },
        required: ['target', 'text'],
      },
    },
    {
      name: 'myc_broadcast',
      description: 'E2E encrypted to ALL peers (N×unicast, each copy ack-tracked + auto-retransmitted)',
      inputSchema: {
        type: 'object',
        properties: {
          text: { type: 'string' },
          type: { type: 'string', description: 'request | info | announcement or a custom app type (reserved _-prefixed types rejected)' },
          room: { type: 'string', description: 'Limit to one room (default: all joined rooms)' },
          include_offline: { type: 'boolean', description: 'Also deliver to known-but-offline peers via identity envelopes (default false)' },
        },
        required: ['text'],
      },
    },
    {
      name: 'myc_recv',
      description: 'Drain the inbox: returns messages/events received since the last call. Host-independent fallback — works even when channel notifications are not surfaced.',
      inputSchema: {
        type: 'object',
        properties: {
          max: { type: 'number', description: 'Max entries to return (default 50)' },
          peek: { type: 'boolean', description: 'Return without draining (default false)' },
        },
      },
    },
    {
      name: 'myc_peers',
      description: 'List peers per room with TOFU + encryption status, plus inbox count',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'myc_rooms',
      description: 'List rooms on the relay (discovery; relay-configurable)',
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
          room: { type: 'string', description: 'Room (needed only if the peer is blocked in several)' },
          confirm: { type: 'boolean', description: 'Must be true after verifying fingerprint' },
        },
        required: ['peer_name'],
      },
    },
    {
      name: 'myc_rotate_key',
      description: 'Rotate this peer\'s Ed25519 identity key. Announces a signed continuity statement to all known peers (online + offline envelopes) and migrates the relay name binding — no TOFU violations for peers that receive the announcement.',
      inputSchema: {
        type: 'object',
        properties: {
          confirm: { type: 'boolean', description: 'Must be true — rotation is permanent' },
        },
      },
    },
  ],
}))

// Pending myc_rooms request awaiting the relay's `rooms` reply.
let roomsResolver: ((v: any) => void) | null = null

mcp.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params as { name: string; arguments: Record<string, any> }
  const offline = !ws || ws.readyState !== WebSocket.OPEN || !authenticated

  switch (name) {
    case 'myc_send': {
      const sType = safeSendType(args.type)
      if (sType === null) return { content: [{ type: 'text', text: BAD_TYPE_MSG }] }
      return { content: [{ type: 'text', text: sendEncrypted(resolveRoom(args.target, args.room), args.target, args.text, sType, args.request_id) }] }
    }

    case 'myc_broadcast': {
      const bType = safeSendType(args.type)
      if (bType === null) return { content: [{ type: 'text', text: BAD_TYPE_MSG }] }
      const rooms = args.room ? [String(args.room)].filter(r => ROOMS.includes(r)) : ROOMS
      if (!rooms.length) return { content: [{ type: 'text', text: `❌ Not a member of room "${args.room}". Joined: ${ROOMS.join(', ')}` }] }
      const results: string[] = []
      const covered = new Set<string>() // dedup same identity present in several rooms
      for (const r of rooms) {
        const targets = new Set<string>(connectedPeers.get(r) ?? [])
        if (args.include_offline) {
          for (const n of Object.keys(tofuStore.rooms[r] ?? {})) targets.add(n)
        }
        for (const t of targets) {
          if (t === PEER) continue
          const idKey = tofuGet(r, t)?.sign_pubkey ?? `${r}:${t}`
          if (covered.has(idKey)) continue
          covered.add(idKey)
          results.push(`${r}/${sendEncrypted(r, t, args.text, bType)}`)
        }
      }
      if (!results.length) return { content: [{ type: 'text', text: 'No peers' }] }
      return { content: [{ type: 'text', text: `Broadcast (${results.length}): ${results.join('; ')}` }] }
    }

    case 'myc_recv': {
      const max = Math.min(Number(args?.max ?? 50) || 50, INBOX_MAX)
      const slice = inbox.slice(0, max)
      const lines = slice.map(e => {
        const t = new Date(e.ts).toISOString().slice(11, 19)
        const m = e.meta
        if (e.kind === 'message') {
          return `[${t}] ${m.from_peer}@${m.room ?? ROOMS[0]} (${m.type}${m.request_id ? `, req ${m.request_id}` : ''}${m.offline ? ', offline-envelope' : ''}): ${e.content}`
        }
        return `[${t}] ⚙ ${e.content}`
      })
      if (!args?.peek) {
        inbox.splice(0, slice.length)
        if (inboxDropped) {
          lines.unshift(`(+${inboxDropped} older entries dropped — inbox cap ${INBOX_MAX})`)
          inboxDropped = 0
        }
      }
      return { content: [{ type: 'text', text: lines.length ? lines.join('\n') : 'No pending messages.' }] }
    }

    case 'myc_peers': {
      const lines: string[] = []
      for (const r of ROOMS) {
        const peers = connectedPeers.get(r) ?? []
        const roomLines = peers.map(p => {
          const s = peerSessions.get(rk(r, p))
          if (!s) return `  ${p} 🔴 BLOCKED (TOFU violation or no keys)`
          return `  ${p} ${s.tofuStatus === 'new' ? '🆕' : '🔒'}${s.stsVerified ? '🤝' : ''}`
        })
        const known = Object.keys(tofuStore.rooms[r] ?? {}).filter(n => n !== PEER && !peers.includes(n))
        if (known.length) roomLines.push(`  (offline, reachable via identity envelope: ${known.join(', ')})`)
        lines.push(`${r}:`, ...(roomLines.length ? roomLines : ['  (no peers)']))
      }
      const blocked = [...pendingTrustKeys.keys()].filter(k => !peerSessions.has(k))
        .map(k => { const [r, n] = k.split('\0'); return `${n}@${r}` })
      if (blocked.length) {
        lines.push(`🔴 BLOCKED: ${blocked.join(', ')} — use myc_trust after fingerprint verification`)
      }
      if (inbox.length) lines.push(`📥 ${inbox.length} pending in inbox (myc_recv)`)
      if (offline) lines.push(`⚠️ Relay disconnected (attempt ${reconnectAttempt}) — sends are queued locally`)
      return { content: [{ type: 'text', text: lines.join('\n') }] }
    }

    case 'myc_rooms': {
      if (offline) return { content: [{ type: 'text', text: `⚠️ Not connected (attempt ${reconnectAttempt})` }] }
      const reply = await new Promise<any>((res) => {
        roomsResolver = res
        wsSend({ type: 'list_rooms' })
        setTimeout(() => { if (roomsResolver === res) { roomsResolver = null; res(null) } }, 5000)
      })
      if (!reply) return { content: [{ type: 'text', text: '⚠️ No reply from relay (older relay without discovery, or discovery disabled)' }] }
      const lines = (reply.rooms ?? []).map((r: any) =>
        `${r.name}: ${r.peers} peer(s)${r.members ? ` — ${r.members.join(', ')}` : ''}${ROOMS.includes(r.name) ? ' (joined)' : ''}`)
      if (!reply.discovery) lines.push('(relay discovery disabled — only joined rooms shown)')
      return { content: [{ type: 'text', text: lines.length ? lines.join('\n') : 'No active rooms.' }] }
    }

    case 'myc_trust': {
      const candidates = [...pendingTrustKeys.keys()].filter(k => k.split('\0')[1] === args.peer_name)
      const scoped = args.room ? candidates.filter(k => k.split('\0')[0] === args.room) : candidates
      if (!scoped.length) return { content: [{ type: 'text', text: `No pending key for ${args.peer_name}${args.room ? ` in room ${args.room}` : ''}` }] }
      if (scoped.length > 1) {
        return { content: [{ type: 'text', text: `${args.peer_name} is blocked in several rooms (${scoped.map(k => k.split('\0')[0]).join(', ')}) — pass room explicitly.` }] }
      }
      const key = scoped[0]
      const [room, peerName] = key.split('\0')
      const pk = pendingTrustKeys.get(key)!

      // Always show fingerprint first
      const fp = fingerprint(pk.sign_pubkey)
      if (!args.confirm) {
        return { content: [{ type: 'text', text: `🔑 ${peerName}@${room} fingerprint:\n\n  ${fp}\n\nVerify this matches the peer's fingerprint (run myc_peers on that instance).\nThen call myc_trust with confirm=true.` }] }
      }
      tofuOverride(room, peerName, pk.sign_pubkey)
      // Explicit human override also clears an STS-failure block (same recovery path).
      stsFailedPeers.delete(key)
      // session_id MUST be forwarded: the STS binding covers both session ids, so a
      // session stored with sessionId '' can never mutually verify (v0.2.0 bug).
      const session = processPeerKeys(room, peerName, pk.sign_pubkey, pk.eph_enc_pubkey, pk.eph_enc_pubkey_sig, pk.session_id)
      pendingTrustKeys.delete(key)
      return { content: [{ type: 'text', text: session ? `✅ ${peerName}@${room} trusted (${fp})` : `❌ Key verification failed` }] }
    }

    case 'myc_rotate_key': {
      if (!args.confirm) {
        return { content: [{ type: 'text', text: `Key rotation is PERMANENT. Current fingerprint: ${fingerprint(toB64(ltKeys.signPublicKey))}\nA signed continuity statement will be sent to every known peer (online now, or as an offline envelope), and the relay name binding migrates automatically. Call again with confirm=true.` }] }
      }
      return { content: [{ type: 'text', text: rotateKey() }] }
    }

    default:
      throw new Error(`Unknown: ${name}`)
  }
})

// Resolve which room a unicast should use: explicit arg wins; otherwise the
// single room where the target is live (or TOFU-known); ambiguity is an error.
function resolveRoom(target: string, roomArg?: string): string {
  if (roomArg && ROOMS.includes(roomArg)) return roomArg
  const live = roomsWithPeer(target)
  if (live.length === 1) return live[0]
  if (live.length > 1) return live[0] // same name live in several rooms: first joined room
  const known = ROOMS.filter(r => tofuGet(r, target))
  if (known.length >= 1) return known[0]
  return ROOMS[0]
}

// Callers supply the message `type` from tool arguments (attacker-influenceable via
// prompt injection of the local model). Custom application types pass through verbatim
// (multi-agent workflows route on them), but reserved control frames
// (_sts_*/_ack/_nack/_perm_req/_key_rotate) are REJECTED WITH AN ERROR, never silently
// rewritten: a caller must not be able to forge protocol traffic. `_perm_verdict` is
// the one sendable control type — it IS the remote permission-approval mechanism.
function safeSendType(t: any): string | null {
  if (t == null || t === '') return 'info'
  if (typeof t !== 'string' || t.length > 64 || /[^\x20-\x7e]/.test(t)) return null
  if (t.startsWith('_') && t !== '_perm_verdict') return null
  return t
}

const BAD_TYPE_MSG = '❌ Invalid message type: reserved control types (_*) other than _perm_verdict cannot be sent, and a type must be a printable string of at most 64 chars. Use request/response/info/announcement or a custom application type.'

// Unified send: live session → PFS frames; TOFU-known offline peer → identity
// envelope; relay down → local outbox queue. Every path is ack-tracked with
// automatic retransmission, chunking transparently above the frame cap.
function sendEncrypted(
  room: string,
  target: string,
  text: string,
  msgType: string,
  requestId?: string,
): string {
  const key = rk(room, target)
  if (stsFailedPeers.has(key) || (pendingTrustKeys.has(key) && !peerSessions.has(key))) {
    return `${target} 🔴BLOCKED`
  }
  const textBytes = sodium.from_string(text).length
  if (textBytes > MAX_LOGICAL_BYTES) {
    return `${target} ❌ message too large (${textBytes} > ${MAX_LOGICAL_BYTES} bytes; raise MYC_MAX_MSG_BYTES)`
  }

  const session = peerSessions.get(key)
  const known = tofuGet(room, target)
  if (!session && !known) {
    return `${target} 🔴 unknown peer — first contact requires both peers online`
  }
  if (outbox.size >= OUTBOX_MAX) {
    return `${target} ❌ outbox full (${OUTBOX_MAX} unconfirmed messages) — wait for acks or failures`
  }

  const logicalId = makeMsgId()
  const parts = splitChunks(text, logicalId)
  const units: { msgId: string; plaintext: string }[] =
    parts?.map(p => ({ msgId: p.partId, plaintext: p.plaintext })) ?? [{ msgId: logicalId, plaintext: text }]

  const connected = ws?.readyState === WebSocket.OPEN && authenticated
  let mode: 'session' | 'offline' | 'local' = session && connected ? 'session' : connected ? 'offline' : 'local'

  for (const u of units) {
    outbox.set(u.msgId, {
      room, target, plaintext: u.plaintext, type: msgType,
      requestId, attempts: 0, wasOffline: mode !== 'session', createdAt: Date.now(),
    })
    const extra = requestId ? { request_id: requestId } : undefined
    if (mode === 'session') {
      const enc = encryptFor(room, target, u.plaintext)
      if (enc) {
        sendCtrl(room, target, msgType, enc, extra, u.msgId)
        trackAck(room, u.msgId, target, false)
        continue
      }
      mode = 'offline'
    }
    if (mode === 'offline') {
      if (sendOffline(room, target, msgType, u.plaintext, u.msgId, extra)) {
        trackAck(room, u.msgId, target, true)
        continue
      }
      mode = 'local'
    }
    // Local queue: flushed on reconnect (long watchdog as backstop).
    trackAck(room, u.msgId, target, true)
  }

  const suffix = parts ? ` (${parts.length} chunks)` : ''
  if (mode === 'session') return `${target} 🔒${session!.tofuStatus === 'new' ? '🆕' : ''}${suffix}`
  if (mode === 'offline') return `${target} 📮 queued for offline delivery (identity envelope, no PFS)${suffix}`
  return `${target} ⏳ relay disconnected — queued locally, will send on reconnect${suffix}`
}

// ===========================================================================
// KEY ROTATION
// ===========================================================================
//
// sign(newPub || peerName || String(ts), oldSecret) is the continuity statement.
// Receivers only honor it when the OLD key is their currently-pinned key for
// this name, so an old announcement cannot roll a pin back after a later
// rotation, and an attacker without the old key cannot rotate anyone.

function rotateKey(): string {
  const newKp = sodium.crypto_sign_keypair()
  const ts = Date.now()
  const oldPub64 = toB64(ltKeys.signPublicKey)
  const bytes = new Uint8Array([...newKp.publicKey, ...sodium.from_string(PEER!), ...sodium.from_string(String(ts))])
  const continuitySig = toB64(sodium.crypto_sign_detached(bytes, ltKeys.signPrivateKey))
  const payload = JSON.stringify({ rotate: { new_pubkey: toB64(newKp.publicKey), continuity_sig: continuitySig, ts } })

  // Announce with the OLD identity (sessions + envelope signatures still verify
  // against the pinned old key) before swapping.
  let online = 0, offline = 0
  for (const r of ROOMS) {
    const live = new Set(connectedPeers.get(r) ?? [])
    for (const p of live) {
      if (p === PEER) continue
      const enc = encryptFor(r, p, payload)
      if (enc) { sendCtrl(r, p, '_key_rotate', enc); online++ }
    }
    for (const p of Object.keys(tofuStore.rooms[r] ?? {})) {
      if (p === PEER || live.has(p)) continue
      if (sendOffline(r, p, '_key_rotate', payload)) offline++
    }
  }

  ltKeys = {
    signPublicKey: newKp.publicKey,
    signPrivateKey: newKp.privateKey,
    prev: { sign_public: oldPub64, continuity_sig: continuitySig, rotated_at: ts },
  }
  persistLTKeys()
  idCurve = {
    publicKey: sodium.crypto_sign_ed25519_pk_to_curve25519(newKp.publicKey),
    privateKey: sodium.crypto_sign_ed25519_sk_to_curve25519(newKp.privateKey),
  }
  const fp = fingerprint(toB64(newKp.publicKey))
  log(`🔑 identity rotated — new fingerprint ${fp}`)
  // Reconnect under the new identity; auth carries the continuity statement so
  // the relay migrates the name binding.
  if (ws) try { ws.close(4200, 'rekey') } catch {}
  return `✅ Identity rotated. New fingerprint: ${fp}\nAnnounced to ${online} online peer(s), ${offline} offline envelope(s). Reconnecting with the new key; the relay binding migrates automatically.`
}

// Receiver side: verify continuity against the CURRENTLY-PINNED key, then move
// every matching room pin to the new key.
function handleKeyRotate(room: string, fromPeer: string, decryptedPayload: string): void {
  let data: any
  try { data = JSON.parse(decryptedPayload)?.rotate } catch { return }
  if (!data || typeof data.new_pubkey !== 'string' || typeof data.continuity_sig !== 'string') return
  try {
    const newPub = fromB64(data.new_pubkey)
    const bytes = new Uint8Array([...newPub, ...sodium.from_string(fromPeer), ...sodium.from_string(String(data.ts ?? ''))])
    let rotatedRooms: string[] = []
    for (const r of ROOMS) {
      const pin = tofuGet(r, fromPeer)
      if (!pin) continue
      const pinnedKey = fromB64(pin.sign_pubkey)
      if (!sodium.crypto_sign_verify_detached(fromB64(data.continuity_sig), bytes, pinnedKey)) continue
      tofuOverride(r, fromPeer, data.new_pubkey)
      rotatedRooms.push(r)
    }
    if (rotatedRooms.length) {
      deliver({
        content: `🔑 ${fromPeer} rotated their identity key (continuity verified, pins updated in: ${rotatedRooms.join(', ')}). New fingerprint: ${fingerprint(data.new_pubkey)}`,
        meta: { type: 'key_rotated', peer: fromPeer, rooms: rotatedRooms.join(',') },
      })
    }
  } catch {}
}

// Permission messages through E2E envelope — ack-tracked + retransmitted like
// any other message (an approval request is the last thing to lose silently).
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
  for (const r of ROOMS) {
    for (const peer of connectedPeers.get(r) ?? []) {
      const enc = encryptFor(r, peer, payload)
      if (!enc) continue
      const msgId = makeMsgId()
      outbox.set(msgId, {
        room: r, target: peer, plaintext: payload, type: '_perm_req',
        requestId: params.request_id, attempts: 0, wasOffline: false, createdAt: Date.now(),
      })
      sendCtrl(r, peer, '_perm_req', enc, { request_id: params.request_id }, msgId)
      trackAck(r, msgId, peer, false)
    }
  }
})

// ===========================================================================
// INBOUND: REGULAR MESSAGES (session frames + offline envelopes)
// ===========================================================================

async function processRegularMessage(room: string, msg: any): Promise<void> {
  // Every legitimate peer message is E2E-encrypted AND signed. Anything else is a
  // relay/attacker injection attempt — hard-block it rather than surfacing
  // unauthenticated content to the model.
  if (!msg.e2e) { log(`🔴 BLOCKED: non-E2E peer message from ${msg.from}`); return }
  if (!msg.sender) { log(`🔴 BLOCKED: missing sender field from ${msg.from}`); return }
  if (msg.sender !== msg.from) { log(`🔴 BLOCKED: sender/from mismatch: ${msg.sender} vs ${msg.from}`); return }
  if (!msg.sig) { log(`🔴 BLOCKED: unsigned e2e message from ${msg.from}`); return }
  if (!msg.encrypted) { log(`🔴 BLOCKED: e2e message missing ciphertext from ${msg.from}`); return }

  if (msg.offline === true) {
    await processOfflineEnvelope(room, msg)
    return
  }
  if (!msg.nonce) { log(`🔴 BLOCKED: session frame missing nonce from ${msg.from}`); return }
  if (!verifySig(room, msg.from, msg, msg.sig)) {
    logSigFail(room, msg)
    return
  }

  // Replay/seq state is consulted AFTER the frame is authenticated and committed
  // only after successful decryption — see checkReplay/commitReplay.
  const { duplicate } = checkReplay(room, msg.from, msg.msg_id, msg.seq, msg.session_id)
  if (duplicate) {
    // A verified duplicate usually means our ack was lost — RE-ACK so the
    // sender's retransmission loop terminates, but do not deliver twice.
    if (msg.msg_id && msg.type !== '_ack' && msg.type !== '_nack') sendAck(room, msg.from, msg.msg_id)
    log(`Replay dedup: re-acked ${msg.msg_id} from ${msg.from}`)
    return
  }

  // Decrypt failure on a VERIFIED frame = stale ciphertext (peer sent it before we
  // reconnected and rotated ephemeral keys) or corruption. The frame's origin and
  // msg_id are authenticated — nack the sender; its outbox retransmits AUTOMATICALLY
  // (as an identity envelope if need be). msg_id is NOT committed, so the
  // retransmission with the same msg_id will be accepted, not dedup-dropped.
  const content = decryptFrom(room, msg.from, msg.encrypted, msg.nonce)
  if (content == null) {
    log(`🔴 decrypt failed from ${msg.from} (stale session ciphertext?) — nacking ${msg.msg_id}`)
    if (msg.msg_id) sendNack(room, msg.from, msg.msg_id)
    return
  }

  commitReplay(room, msg.from, msg.msg_id, msg.seq, msg.session_id)
  if (msg.msg_id && msg.from && msg.type !== '_ack') sendAck(room, msg.from, msg.msg_id)
  await deliverContent(room, msg, content, false)
}

// Offline envelope: sealed to our identity key, signed by the sender's
// TOFU-pinned identity, with a signed freshness window (offline ciphertexts
// never expire cryptographically, so time + persisted dedup bound replay).
async function processOfflineEnvelope(room: string, msg: any): Promise<void> {
  const pin = tofuGet(room, msg.from)
  if (!pin) {
    log(`🔴 BLOCKED: offline envelope from unknown peer ${msg.from}@${room} (first contact requires both online)`)
    return
  }
  if (stsFailedPeers.has(rk(room, msg.from))) {
    log(`🔴 BLOCKED: offline envelope from STS-failed peer ${msg.from}@${room}`)
    return
  }
  if (!verifySigWithKey(fromB64(pin.sign_pubkey), msg, msg.sig)) {
    logSigFail(room, msg)
    return
  }
  if (typeof msg.ts !== 'number' || Math.abs(Date.now() - msg.ts) > OFFLINE_MAX_AGE_MS) {
    log(`🔴 BLOCKED: stale/undated offline envelope ${msg.msg_id} from ${msg.from} (ts ${msg.ts})`)
    deliver({
      content: `⚠️ Stale offline message from ${msg.from} (id ${msg.msg_id ?? 'unknown'}) rejected — older than the ${OFFLINE_MAX_AGE_MS / 60000}min freshness window.`,
      meta: { type: 'offline_stale', from_peer: msg.from, room, msg_id: msg.msg_id ?? '' },
    })
    return
  }
  const { duplicate } = checkReplay(room, msg.from, msg.msg_id, undefined, undefined)
  if (duplicate) {
    if (msg.msg_id && msg.type !== '_ack' && msg.type !== '_nack') sendAck(room, msg.from, msg.msg_id)
    return
  }
  const content = openSealed(msg.encrypted)
  if (content == null) {
    log(`🔴 offline envelope from ${msg.from} failed to open — nacking ${msg.msg_id}`)
    if (msg.msg_id) sendNack(room, msg.from, msg.msg_id)
    return
  }
  commitReplay(room, msg.from, msg.msg_id, undefined, undefined)

  // Offline control frames (acks/nacks/rotation announcements for peers who were
  // away) are handled here since they bypass the session-frame router.
  if (msg.type === '_ack') { if (content.startsWith('ack:')) handleAck(room, content.slice(4), msg.from); return }
  if (msg.type === '_nack') { if (content.startsWith('nack:')) handleNack(room, content.slice(5), msg.from); return }
  if (msg.type === '_key_rotate') { handleKeyRotate(room, msg.from, content); return }
  if (typeof msg.type === 'string' && msg.type.startsWith('_') && msg.type !== '_perm_verdict') {
    log(`🔴 BLOCKED: reserved control type ${msg.type} in offline envelope from ${msg.from}`)
    return
  }

  if (msg.msg_id) sendAck(room, msg.from, msg.msg_id)
  await deliverContent(room, msg, content, true)
}

// Shared tail: chunk reassembly + inbox + notification.
async function deliverContent(room: string, msg: any, content: string, viaOffline: boolean): Promise<void> {
  const chunk = tryChunk(room, msg.from, content, msg)
  if (chunk === 'partial' || chunk === 'invalid') return
  let finalContent = content
  let meta: Record<string, any> = {
    from_peer: msg.from, type: msg.type ?? 'info', room,
    msg_id: msg.msg_id ?? '', e2e: 'encrypted', sig: '✅',
    ...(viaOffline ? { offline: true } : {}),
    ...(msg.request_id ? { request_id: msg.request_id } : {}),
  }
  if (chunk) {
    finalContent = chunk.content
    meta.msg_id = chunk.logicalId
    meta.chunked = chunk.n
  }
  const session = peerSessions.get(rk(room, msg.from))
  meta.tofu = viaOffline ? '📮' : session ? (session.tofuStatus === 'new' ? '🆕' : '🔒') : '🔴'

  if (msg.type === '_perm_verdict') {
    try {
      const v = JSON.parse(finalContent)
      await safeNotify({
        method: 'notifications/claude/channel/permission' as any,
        params: { request_id: v.request_id, behavior: v.behavior },
      })
    } catch {}
    return
  }

  deliver({ content: finalContent, meta })
}

function logSigFail(room: string, msg: any): void {
  const hint = msg.proto && msg.proto !== PROTO
    ? ` (protocol mismatch: theirs v${msg.proto}, ours v${PROTO} — upgrade the older peer)`
    : ''
  log(`🔴 BLOCKED: bad signature from ${msg.from}@${room}${hint}`)
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
      // Verify relay identity if fingerprint(s) configured. A comma-separated
      // set lets multi-relay failover keep identity pinning (one fp per relay).
      if (RELAY_FP_SET.size && msg.relay_pubkey) {
        try {
          const rpk = fromB64(msg.relay_pubkey)
          const fp = fingerprint(msg.relay_pubkey)
          if (!RELAY_FP_SET.has(fp.toLowerCase())) {
            log(`RELAY IDENTITY MISMATCH: got ${fp}, not in pinned set`)
            ws!.close(4099, 'relay identity mismatch')
            return
          }
          if (!msg.relay_sig || !msg.timestamp) {
            log(`RELAY SIG MISSING — refusing to authenticate`)
            ws!.close(4099, 'relay sig missing')
            return
          }
          const nonce = fromB64(msg.nonce)
          const sigData = new Uint8Array([...nonce, ...sodium.from_string(msg.timestamp)])
          if (!sodium.crypto_sign_verify_detached(fromB64(msg.relay_sig), sigData, rpk)) {
            log(`RELAY SIG INVALID`)
            ws!.close(4099, 'relay sig invalid')
            return
          }
          log(`Relay identity verified: ${fp}`)
        } catch (e) {
          log(`Relay identity check error: ${e}`)
          ws!.close(4099, 'relay identity error')
          return
        }
      } else if (RELAY_FP_SET.size && !msg.relay_pubkey) {
        // Pinning configured but the relay presented no identity: fail closed.
        log(`RELAY IDENTITY MISSING — pinning configured, refusing to authenticate`)
        ws!.close(4099, 'relay identity missing')
        return
      }

      // Sign challenge (covers peer name + the full rooms list)
      const nonce = fromB64(msg.nonce)
      const sigData = new Uint8Array([
        ...nonce,
        ...sodium.from_string(PEER!),
        ...sodium.from_string(ROOMS.join(',')),
      ])
      const challengeSig = toB64(sodium.crypto_sign_detached(sigData, ltKeys.signPrivateKey))

      // Build auth message. `room` kept for legacy relays (single-room only —
      // a multi-room list against a legacy relay fails the challenge sig with a
      // clear auth error rather than silently joining the wrong room).
      const authMsg: any = {
        type: 'auth', peer: PEER, room: ROOMS[0], rooms: ROOMS, proto: PROTO,
        sign_pubkey: toB64(ltKeys.signPublicKey),
        eph_enc_pubkey: toB64(ephKeys.encPublicKey),
        eph_enc_pubkey_sig: ephKeys.pubKeySig,
        session_id: sessionId,
        challenge_sig: challengeSig,
      }
      // After a rotation: continuity statement so the relay migrates the name
      // binding from the old key to the new one.
      if (ltKeys.prev) {
        authMsg.rotation = {
          prev_sign_pubkey: ltKeys.prev.sign_public,
          continuity_sig: ltKeys.prev.continuity_sig,
          ts: ltKeys.prev.rotated_at,
        }
      }

      // Seal token if relay pubkey available. NO plaintext fallback on a seal
      // failure when pinning is configured — a malformed relay_pubkey must not
      // downgrade the token to plaintext.
      if (msg.relay_pubkey) {
        try {
          const relayCurvePk = sodium.crypto_sign_ed25519_pk_to_curve25519(fromB64(msg.relay_pubkey))
          authMsg.sealed_token = toB64(sodium.crypto_box_seal(sodium.from_string(TOKEN!), relayCurvePk))
        } catch {
          if (RELAY_FP_SET.size) {
            log('Token sealing failed with pinning configured — refusing plaintext downgrade')
            ws!.close(4099, 'seal failed')
            return
          }
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
      // A new session invalidates prior STS handshake state — clear those timers so
      // they can't delete freshly-established STS state. pendingAcks timers are KEPT:
      // a message that raced the disconnect genuinely has unconfirmed delivery, and
      // its outbox entry retransmits once sessions are re-established.
      for (const [, p] of stsPending) clearTimeout(p.timer)
      stsPending.clear()
      connectedPeers.clear()

      // v2 payload: { rooms: [...], peers: { room: map } }. Legacy: { room, peers: map }.
      const peersByRoom: Record<string, any> = msg.payload?.rooms
        ? msg.payload.peers ?? {}
        : { [msg.payload?.room ?? ROOMS[0]]: msg.payload?.peers ?? {} }

      for (const [room, peersMap] of Object.entries(peersByRoom) as [string, any][]) {
        for (const [n, info] of Object.entries(peersMap ?? {}) as [string, any][]) {
          if (n !== PEER) {
            const s = processPeerKeys(room, n, info.sign_pubkey, info.eph_enc_pubkey, info.eph_enc_pubkey_sig, info.session_id)
            if (!s && info.sign_pubkey) pendingTrustKeys.set(rk(room, n), info)
          }
        }
        connectedPeers.set(room, Object.keys(peersMap ?? {}).filter(p => p !== PEER))
      }
      startHB()
      log(`Auth OK (${allPeerNames().length} peers across ${Object.keys(peersByRoom).length} room(s))`)
      // Flush sends queued while disconnected + retry unconfirmed deliveries.
      setTimeout(() => flushOutbox(), 500)
      return
    }

    if (msg.type === 'auth_error') {
      log(`Auth fail: ${msg.payload}`)
      authenticated = false
      return
    }

    if (msg.type === 'evicted') {
      log(`Evicted: ${msg.payload}`)
      if (msg.payload === 'revoked') {
        deliver({
          content: `🔴 This peer was REVOKED by the relay operator. Reconnection will be refused until re-invited.`,
          meta: { type: 'revoked' },
        })
      }
      return
    }

    if (!mcpReady || !authenticated) return

    // --- Relay control ---
    if (msg.from === '_relay') {
      const room = typeof msg.payload?.room === 'string' ? msg.payload.room : ROOMS[0]

      if (msg.type === 'peer_joined') {
        const p = msg.payload
        if (p?.sign_pubkey && p?.eph_enc_pubkey && p?.eph_enc_pubkey_sig) {
          const session = processPeerKeys(room, p.peer, p.sign_pubkey, p.eph_enc_pubkey, p.eph_enc_pubkey_sig, p.session_id)
          if (!session) {
            pendingTrustKeys.set(rk(room, p.peer), p)
            deliver({
              content: `🔴 TOFU VIOLATION: ${p.peer} (room ${room}) — BLOCKED. Verify fingerprint and use myc_trust.`,
              meta: { type: 'tofu_violation', peer: p.peer, room },
            })
          }
          updatePeerList(room, msg.payload.peers)
          const label = session
            ? (session.tofuStatus === 'new' ? '🆕' : '🔒')
            : '🔴BLOCKED'
          deliver({
            content: `➕ ${p.peer} ${label} (${room}) — peers: ${(connectedPeers.get(room) ?? []).join(', ') || '(none)'}`,
            meta: { type: 'peer_joined', peer: p.peer, room },
          })
        }
        return
      }

      if (msg.type === 'peer_left') {
        peerSessions.delete(rk(room, msg.payload?.peer))
        pendingTrustKeys.delete(rk(room, msg.payload?.peer))
        updatePeerList(room, msg.payload?.peers)
        deliver({
          content: `➖ ${msg.payload?.peer} (${room})`,
          meta: { type: 'peer_left', peer: msg.payload?.peer, room },
        })
        return
      }

      if (msg.type === 'relay_shutdown') {
        log('Relay shutdown')
        reconnectAttempt = 0
        return
      }

      if (msg.type === 'rooms') {
        if (roomsResolver) {
          roomsResolver(msg.payload)
          roomsResolver = null
        }
        return
      }

      // Relay delivery-status frames. The relay reports drops honestly (rate
      // limit, backpressure, queue full, offline-not-queued) and deferred
      // delivery ('queued'). Delivery errors for tracked messages feed the
      // outbox retransmission loop instead of the model.
      if (msg.type === 'queued' || msg.type === 'error') {
        const detail = String(msg.payload ?? '').replace(/[\r\n]+/g, ' ').slice(0, 160)
        if (msg.type === 'error') {
          log(`Relay error: ${detail} (msg ${msg.msg_id ?? '?'})`)
          const tracked = msg.msg_id && outbox.has(msg.msg_id)
          if (tracked) {
            const p = pendingAcks.get(msg.msg_id)
            if (p) {
              clearTimeout(p.timer)
              pendingAcks.delete(msg.msg_id)
            }
            // Rate limits clear on their own — back off before retrying. Every
            // other reported drop retries immediately over the best path
            // (session gone → identity envelope).
            if (/rate limited/.test(detail)) {
              setTimeout(() => resendOutbox(msg.msg_id, `relay: ${detail}`), 5000)
            } else {
              resendOutbox(msg.msg_id, `relay: ${detail}`)
            }
          } else {
            deliver({
              content: `⚠️ Relay reports delivery failure: ${detail} (msg ${msg.msg_id ?? 'unknown'}). The message was NOT delivered.`,
              meta: { type: 'relay_error', msg_id: msg.msg_id ?? '' },
            })
          }
        } else {
          // 'queued' now only happens for offline envelopes (session frames are
          // no_queue) — the sender was already told at send time. Log only.
          log(`Relay queued: ${detail} (msg ${msg.msg_id ?? '?'}, ttl ${msg.ttl_s ?? '?'}s)`)
        }
        return
      }
      return
    }

    // --- Peer frames: resolve the room the relay routed this in ---
    const room = typeof msg.room === 'string' && ROOMS.includes(msg.room) ? msg.room : ROOMS[0]

    // Offline envelopes (including offline acks/nacks/rotations) are sealed to
    // the identity key and verified against TOFU pins — route them as a unit.
    if (msg.offline === true) {
      await processRegularMessage(room, msg)
      return
    }

    // --- Acks (session variant; authenticated encryption provides auth) ---
    if (msg.type === '_ack') {
      if (msg.e2e && msg.encrypted && msg.nonce) {
        const dec = decryptFrom(room, msg.from, msg.encrypted, msg.nonce)
        if (dec?.startsWith('ack:')) handleAck(room, dec.slice(4), msg.from)
      }
      return
    }

    if (msg.type === '_nack') {
      if (msg.e2e && msg.encrypted && msg.nonce) {
        const dec = decryptFrom(room, msg.from, msg.encrypted, msg.nonce)
        if (dec?.startsWith('nack:')) handleNack(room, dec.slice(5), msg.from)
      }
      return
    }

    // --- STS mutual authentication ---
    if (msg.type === '_sts_init' || msg.type === '_sts_reply' || msg.type === '_sts_complete') {
      if (!msg.e2e || !msg.encrypted || !msg.nonce) return
      if (!msg.sig || !msg.sender || msg.sender !== msg.from || !verifySig(room, msg.from, msg, msg.sig)) {
        log(`BLOCKED: bad sig on ${msg.type} from ${msg.from}`)
        return
      }
      const dec = decryptFrom(room, msg.from, msg.encrypted, msg.nonce)
      if (!dec) return

      if (msg.type === '_sts_init') handleSTSInit(room, msg.from)
      else if (msg.type === '_sts_reply') handleSTSReply(room, msg.from, dec)
      else if (msg.type === '_sts_complete') handleSTSComplete(room, msg.from, dec)
      return
    }

    // --- Key rotation announcement (session variant) ---
    if (msg.type === '_key_rotate') {
      if (!msg.e2e || !msg.encrypted || !msg.nonce) return
      if (!msg.sig || !msg.sender || msg.sender !== msg.from || !verifySig(room, msg.from, msg, msg.sig)) {
        log(`🔴 BLOCKED: bad sig on _key_rotate from ${msg.from}`)
        return
      }
      const dec = decryptFrom(room, msg.from, msg.encrypted, msg.nonce)
      if (dec) handleKeyRotate(room, msg.from, dec)
      return
    }

    // --- Encrypted permission requests ---
    if (msg.type === '_perm_req') {
      if (!msg.e2e || !msg.encrypted || !msg.nonce) return // drop non-E2E perm messages
      // Hard block on bad sig
      if (!msg.sig || !msg.sender || msg.sender !== msg.from || !verifySig(room, msg.from, msg, msg.sig)) {
        log(`🔴 BLOCKED: bad sig on _perm_req from ${msg.from}`)
        return
      }
      const dec = decryptFrom(room, msg.from, msg.encrypted, msg.nonce)
      if (!dec) return
      // Approval requests are ack-tracked by the sender — confirm receipt.
      if (msg.msg_id) sendAck(room, msg.from, msg.msg_id)
      try {
        const params = JSON.parse(dec)
        deliver({
          content: `⚠️ ${msg.from} needs approval: ${params.tool_name}: ${params.description}`,
          meta: { type: 'permission_request', from_peer: msg.from, room, request_id: params.request_id },
        })
      } catch {}
      return
    }

    // --- REGULAR PEER MESSAGE (incl. _perm_verdict, which flows through the
    // full verify→dedup→decrypt→commit→ack pipeline and is dispatched to the
    // permission channel in deliverContent) ---
    await processRegularMessage(room, msg)
  })

  ws.addEventListener('close', (e) => {
    log(`Disconnected (${(e as any).reason || (e as any).code})`)
    connectedPeers.clear()
    authenticated = false
    ws = null
    stopHB()
    scheduleReconnect()
  })

  ws.addEventListener('error', () => {})
}

function updatePeerList(room: string, peersMap: any): void {
  if (!peersMap || typeof peersMap !== 'object') return
  connectedPeers.set(room, Object.keys(peersMap).filter(p => p !== PEER))
  for (const [n, info] of Object.entries(peersMap) as [string, any][]) {
    if (n !== PEER && !peerSessions.has(rk(room, n)) && info.sign_pubkey && info.eph_enc_pubkey && info.eph_enc_pubkey_sig) {
      const s = processPeerKeys(room, n, info.sign_pubkey, info.eph_enc_pubkey, info.eph_enc_pubkey_sig, info.session_id)
      if (!s && info.sign_pubkey) pendingTrustKeys.set(rk(room, n), info)
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
  if (ws?.readyState === WebSocket.OPEN && (authenticated || msg.type === 'auth')) {
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
  idCurve = {
    publicKey: sodium.crypto_sign_ed25519_pk_to_curve25519(ltKeys.signPublicKey),
    privateKey: sodium.crypto_sign_ed25519_sk_to_curve25519(ltKeys.signPrivateKey),
  }
  ephKeys = genEphKeys()
  loadTofu()
  loadReplay()
  loadWAL()

  log(`Identity: ${toB64(ltKeys.signPublicKey).slice(0, 16)}... (proto v${PROTO})`)
  log(`Fingerprint: ${fingerprint(toB64(ltKeys.signPublicKey))}`)
  log(`Rooms: ${ROOMS.join(', ')} | TOFU: ${Object.values(tofuStore.rooms).reduce((n, r) => n + Object.keys(r).length, 0)} pins | Replay: ${seenMsgIds.size} seen`)

  await mcp.connect(new StdioServerTransport())
  mcpReady = true
  connectRelay()

  function cleanup(): void {
    saveReplay()
    clearInterval(replayTimer)
    if (reconnectTimer) clearTimeout(reconnectTimer)
    stopHB()
    for (const [, p] of pendingAcks) clearTimeout(p.timer)
    for (const [, p] of stsPending) clearTimeout(p.timer)
    for (const [, b] of chunkBufs) clearTimeout(b.timer)
    if (ws) try { ws.close(1000) } catch {}
    process.exit(0)
  }

  process.on('SIGTERM', cleanup)
  process.on('SIGINT', cleanup)
})()
