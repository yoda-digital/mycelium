/**
 * Shared test plumbing: an MCP stdio client over a spawned peer-channel.ts process,
 * plus waitUntil. Used by test-integration.ts and test-replay-poison.ts — a single
 * copy so a change to the MCP framing or the notification method name cannot be
 * updated in one test and silently stop being observed in the other.
 */

import { join } from 'path'

export interface PeerProcOpts {
  name: string
  relayUrl: string
  token: string
  scratchDir: string
  room?: string
  /** Basename prefix for key/tofu/replay files (defaults to `name`) — lets a test
   *  restart a peer under the same name with a DIFFERENT identity. */
  filePrefix?: string
  /** Additional env (MYC_RELAY_FINGERPRINT, MYC_KEY_PASSPHRASE, …). */
  extraEnv?: Record<string, string>
  /** Override the spawn command (default: bun run peer-channel.ts). Lets a test run
   *  the NODE-target build under `node` to prove cross-runtime portability. */
  cmd?: string[]
}

export class PeerProc {
  proc: any
  name: string
  private buf = ''
  private nextId = 1
  private pending = new Map<number, (v: any) => void>()
  channelMsgs: any[] = []
  stderr: string[] = []

  constructor(opts: PeerProcOpts) {
    this.name = opts.name
    const prefix = opts.filePrefix ?? opts.name
    this.proc = Bun.spawn(opts.cmd ?? ['bun', 'run', 'peer-channel.ts'], {
      cwd: import.meta.dir,
      env: {
        ...process.env,
        MYC_RELAY: opts.relayUrl,
        MYC_TOKEN: opts.token,
        MYC_PEER: opts.name,
        MYC_ROOM: opts.room ?? 'default',
        MYC_KEY_FILE: join(opts.scratchDir, `${prefix}-keys.json`),
        MYC_TOFU_FILE: join(opts.scratchDir, `${prefix}-tofu.json`),
        MYC_REPLAY_FILE: join(opts.scratchDir, `${prefix}-replay.json`),
        ...(opts.extraEnv ?? {}),
      },
      stdin: 'pipe', stdout: 'pipe', stderr: 'pipe',
    })
    this.readStdout()
    this.readStderr()
  }

  private async readStdout(): Promise<void> {
    const reader = this.proc.stdout.getReader()
    const dec = new TextDecoder()
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      this.buf += dec.decode(value, { stream: true })
      let idx: number
      while ((idx = this.buf.indexOf('\n')) >= 0) {
        const line = this.buf.slice(0, idx).trim()
        this.buf = this.buf.slice(idx + 1)
        if (!line) continue
        let msg: any
        try { msg = JSON.parse(line) } catch { continue }
        if (msg.id !== undefined && this.pending.has(msg.id)) {
          this.pending.get(msg.id)!(msg)
          this.pending.delete(msg.id)
        } else if (msg.method === 'notifications/claude/channel') {
          this.channelMsgs.push(msg.params)
        }
      }
    }
  }

  private async readStderr(): Promise<void> {
    const reader = this.proc.stderr.getReader()
    const dec = new TextDecoder()
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      for (const l of dec.decode(value, { stream: true }).split('\n')) {
        if (l.trim()) this.stderr.push(l.trim())
      }
    }
  }

  private send(obj: any): void { this.proc.stdin.write(JSON.stringify(obj) + '\n'); this.proc.stdin.flush?.() }

  request(method: string, params: any): Promise<any> {
    const id = this.nextId++
    return new Promise((resolve) => {
      this.pending.set(id, resolve)
      this.send({ jsonrpc: '2.0', id, method, params })
    })
  }

  async initialize(): Promise<void> {
    await this.request('initialize', {
      protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'itest', version: '1.0.0' },
    })
    this.send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} })
  }

  callTool(name: string, args: any): Promise<any> { return this.request('tools/call', { name, arguments: args }) }
  toolText(res: any): string { return res?.result?.content?.[0]?.text ?? '' }
  stderrHas(re: RegExp): boolean { return this.stderr.some(l => re.test(l)) }
  from(peer: string): any[] { return this.channelMsgs.filter(m => m.meta?.from_peer === peer) }
  clear(): void { this.channelMsgs = [] }
  kill(): void { try { this.proc.kill() } catch {} }
}

export async function waitUntil(fn: () => boolean, timeoutMs: number, stepMs = 50): Promise<boolean> {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    if (fn()) return true
    await Bun.sleep(stepMs)
  }
  return fn()
}
