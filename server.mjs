#!/usr/bin/env node
// Solo Remote — LAN proxy for the soloterm HTTP API.
// Solo binds to 127.0.0.1 only, so this server exposes a LAN-reachable UI
// and forwards /api/* to solo with the bearer token injected server-side.
// The token never leaves this machine.

import http from 'node:http'
import { spawn, execFile } from 'node:child_process'
import { readdirSync, statSync, writeFileSync, existsSync, openSync, readSync, closeSync, unlinkSync, realpathSync, watch as fsWatch } from 'node:fs'
import { promisify } from 'node:util'
import crypto from 'node:crypto'
import { createRequire } from 'node:module'
const webpush = createRequire(import.meta.url)('web-push')
const run = promisify(execFile)
import { readFileSync } from 'node:fs'
import { networkInterfaces } from 'node:os'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const PORT = Number(process.env.PORT || 8123)
const DISCOVERY = process.env.SOLO_DISCOVERY ||
  path.join(process.env.HOME, '.config/soloterm/http-api.json')
const __dirname = path.dirname(fileURLToPath(import.meta.url))

function solo() {
  // Read per-request so a restarted solo (new token/port) keeps working.
  const d = JSON.parse(readFileSync(DISCOVERY, 'utf8'))
  return { base: d.endpointBaseUrl, token: d.token }
}

// --- auth: PIN + passkeys, sessions with a 5-minute interaction window ---
// auth.json holds the PIN, VAPID keys, registered passkeys, push subscriptions.
// Sessions are random tokens; they die after 5 minutes without USER interaction
// (the client marks user-triggered requests with x-interactive; polling doesn't count).
const AUTH_FILE = path.join(__dirname, 'auth.json')
let auth
if (existsSync(AUTH_FILE)) auth = JSON.parse(readFileSync(AUTH_FILE, 'utf8'))
else auth = {}
if (!auth.pin) auth.pin = String(crypto.randomInt(0, 1000000)).padStart(6, '0')
if (!auth.secret) auth.secret = crypto.randomBytes(32).toString('hex')
if (!auth.vapid) auth.vapid = webpush.generateVAPIDKeys()
auth.credentials = auth.credentials || []
if (auth.notifyEnabled == null) auth.notifyEnabled = true
auth.pushSubs = auth.pushSubs || []
function saveAuth() { writeFileSync(AUTH_FILE, JSON.stringify(auth, null, 2), { mode: 0o600 }) }
saveAuth()
// contact for push services (they may use it to reach the operator about problems)
const PUSH_CONTACT = process.env.PUSH_CONTACT || 'mailto:solo-remote@example.com'
webpush.setVapidDetails(PUSH_CONTACT, auth.vapid.publicKey, auth.vapid.privateKey)

const IDLE_MS = 5 * 60 * 1000
const sessions = new Map()   // token -> lastInteractive ms
function newSession() {
  const t = crypto.randomBytes(32).toString('hex')
  sessions.set(t, Date.now())
  return t
}
function sessionFrom(req) {
  const m = /(?:^|;\s*)solo_remote=([a-f0-9]{64})/.exec(req.headers.cookie || '')
  if (!m) return null
  const last = sessions.get(m[1])
  if (last == null) return null
  if (Date.now() - last > IDLE_MS) { sessions.delete(m[1]); return null }
  if (req.headers['x-interactive']) sessions.set(m[1], Date.now())
  return m[1]
}
function setCookie(res, extra = {}) {
  const t = newSession()
  res.writeHead(extra.status || 303, {
    'set-cookie': `solo_remote=${t}; Max-Age=${90 * 24 * 3600}; Path=/; HttpOnly; SameSite=Lax`,
    ...(extra.headers || {}),
  })
}

// brute-force guard: after 5 bad attempts, lock the login for 60s
const pinGuard = { fails: 0, lockedUntil: 0 }

// --- WebAuthn (passkeys), ES256/RS256, attestation "none" ---
const challenges = new Map()   // key -> { challenge, at }
function b64url(buf) { return Buffer.from(buf).toString('base64url') }

function cborDecode(buf) {
  let off = 0
  function item() {
    const ib = buf[off++]
    const major = ib >> 5, info = ib & 31
    let n = info
    if (info === 24) { n = buf[off]; off += 1 }
    else if (info === 25) { n = buf.readUInt16BE(off); off += 2 }
    else if (info === 26) { n = buf.readUInt32BE(off); off += 4 }
    else if (info === 27) { n = Number(buf.readBigUInt64BE(off)); off += 8 }
    switch (major) {
      case 0: return n
      case 1: return -1 - n
      case 2: { const v = buf.subarray(off, off + n); off += n; return v }
      case 3: { const v = buf.subarray(off, off + n).toString('utf8'); off += n; return v }
      case 4: { const a = []; for (let i = 0; i < n; i++) a.push(item()); return a }
      case 5: { const m = new Map(); for (let i = 0; i < n; i++) { const k = item(); m.set(k, item()) } return m }
      case 7: if (info === 20) return false; if (info === 21) return true; if (info === 22) return null; return undefined
      default: throw new Error('cbor: unsupported major ' + major)
    }
  }
  const v = item()
  return { value: v, rest: buf.subarray(off) }
}

function coseToKey(cose) {
  const kty = cose.get(1), alg = cose.get(3)
  if (kty === 2 && alg === -7) {  // EC2 / ES256
    return {
      alg: 'ES256',
      key: crypto.createPublicKey({
        key: { kty: 'EC', crv: 'P-256', x: b64url(cose.get(-2)), y: b64url(cose.get(-3)) },
        format: 'jwk',
      }).export({ format: 'jwk' }),
    }
  }
  if (kty === 3 && alg === -257) {  // RSA / RS256
    return {
      alg: 'RS256',
      key: crypto.createPublicKey({
        key: { kty: 'RSA', n: b64url(cose.get(-1)), e: b64url(cose.get(-2)) },
        format: 'jwk',
      }).export({ format: 'jwk' }),
    }
  }
  throw new Error('unsupported key type')
}

function verifyWebauthnSig(cred, authenticatorData, clientDataJSON, signature) {
  const signed = Buffer.concat([authenticatorData, crypto.createHash('sha256').update(clientDataJSON).digest()])
  const pub = crypto.createPublicKey({ key: cred.key, format: 'jwk' })
  return crypto.verify('sha256', signed, pub, signature)
}

function rpIdFor(req) { return (req.headers.host || '').split(':')[0] }

// --- push notifications: server-side watcher for agent/process events ---
async function sendPushAll(payload) {
  const dead = []
  await Promise.all(auth.pushSubs.map(async sub => {
    try { await webpush.sendNotification(sub, JSON.stringify(payload)) }
    catch (e) { if (e.statusCode === 404 || e.statusCode === 410) dead.push(sub.endpoint) }
  }))
  if (dead.length) { auth.pushSubs = auth.pushSubs.filter(s => !dead.includes(s.endpoint)); saveAuth() }
}

const watch = { procStatus: {}, agentIdle: {}, primed: false }
const pendingNotifs = new Set()   // tags sent but not yet seen/cleared
const notifLog = []               // recent notifications, newest last
let notifSeq = 0
const viewing = { procId: null, at: 0 }   // process open on the phone (heartbeat)
function isViewing(procId) { return viewing.procId === procId && Date.now() - viewing.at < 45000 }
function notifyOnce(tag, payload, { push = true } = {}) {
  if (pendingNotifs.has(tag)) return
  if (payload.procId != null && isViewing(payload.procId)) return   // already looking at it
  pendingNotifs.add(tag)
  notifLog.push({ id: ++notifSeq, tag, title: payload.title, body: payload.body, procId: payload.procId ?? null, at: Date.now(), read: false })
  if (notifLog.length > 100) notifLog.splice(0, notifLog.length - 100)
  if (push && auth.notifyEnabled) sendPushAll({ ...payload, tag })
}
async function watchTick() {
  try {
    const { base, token } = solo()
    const r = await fetch(base + '/api/processes', { headers: { authorization: `Bearer ${token}` } })
    const procs = (await r.json()).data.processes
    for (const p of procs) {
      const prev = watch.procStatus[p.id]
      if (watch.primed && (prev === 'running' || prev === 'starting') && (p.status === 'exited' || p.status === 'failed')) {
        notifyOnce('dead-' + p.id, { title: `${p.name} ${p.status}`, body: `project: ${p.projectName}`, procId: p.id }, { push: false })
      }
      if (p.status === 'running') pendingNotifs.delete('dead-' + p.id)
      watch.procStatus[p.id] = p.status
    }
    const agents = procs.filter(p => p.kind === 'agent' && p.status === 'running')
    for (const a of agents) {
      try {
        const s = JSON.parse((await mcpCall('get_process_status', { process_id: a.id, project_id: a.projectId })).content?.[0]?.text || '{}')
        const idle = s.agent_state?.idle
        if (idle == null) continue
        const prev = watch.agentIdle[a.id]
        if (watch.primed && prev === false && idle === true) watch.idleSince = { ...watch.idleSince, [a.id]: Date.now() }
        if (idle === false) {
          delete (watch.idleSince || {})[a.id]
          pendingNotifs.delete('idle-' + a.id)   // busy again: future idles may notify
        }
        // debounced: only notify when the idle state has stuck for 12s
        const since = (watch.idleSince || {})[a.id]
        if (watch.primed && idle === true && since && Date.now() - since > 12000) {
          delete watch.idleSince[a.id]
          const title = (a.pid && (await claudeInfo(a.pid).catch(() => ({}))).title) || a.name
          notifyOnce('idle-' + a.id, { title: `${title} is waiting`, body: `${a.name} · ${a.projectName}`, procId: a.id })
        }
        watch.agentIdle[a.id] = idle
      } catch {}
    }
    watch.primed = true
  } catch {}
}
setInterval(watchTick, 6000)

const LOGIN_PAGE_FILE = path.join(__dirname, 'login.html')
function sendLogin(res, err = '') {
  // 200, not 401: Chrome's PWA installability checks reject non-OK start_url
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
  try { res.end(readFileSync(LOGIN_PAGE_FILE, 'utf8').replace('__ERR__', err)) }
  catch { res.end('login.html missing') }
}

async function readBody(req) {
  return new Promise((ok, err) => {
    const chunks = []
    req.on('data', c => chunks.push(c))
    req.on('end', () => ok(Buffer.concat(chunks).toString()))
    req.on('error', err)
  })
}

// --- MCP bridge (stdio) for capabilities the HTTP API lacks, e.g. send_input ---
const MCP_BIN = process.env.SOLO_MCP_BIN || '/Applications/Solo.app/Contents/MacOS/mcp'
let mcp = null

function mcpConnect() {
  // strip solo's per-process identity vars: if the server was launched from
  // inside a solo-managed shell, the helper would otherwise identify as THAT
  // process and every call breaks once solo renumbers it
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('SOLO_')))
  // detached: the helper gets its own session with NO controlling tty — solo
  // also identifies MCP clients by their pty, so a helper inheriting a
  // solo-managed terminal gets bound to that (ephemeral) process identity
  const child = spawn(MCP_BIN, [], { stdio: ['pipe', 'pipe', 'ignore'], env, detached: true })
  child.unref()
  const pending = new Map()
  let nextId = 1
  let buf = ''
  child.stdout.on('data', d => {
    buf += d
    let i
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1)
      if (!line.trim()) continue
      try {
        const msg = JSON.parse(line)
        const p = pending.get(msg.id)
        if (p) { pending.delete(msg.id); msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result) }
      } catch {}
    }
  })
  const state = {
    child,
    request(method, params) {
      const id = nextId++
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n')
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject })
        setTimeout(() => { if (pending.delete(id)) reject(new Error('mcp timeout')) }, 10000)
      })
    },
    ready: null,
  }
  state.ready = state.request('initialize', {
    protocolVersion: '2025-03-26', capabilities: {},
    clientInfo: { name: 'solo-remote', version: '1' },
  }).then(() => {
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n')
  })
  child.on('exit', () => {
    for (const p of pending.values()) p.reject(new Error('mcp exited'))
    if (mcp === state) mcp = null
  })
  return state
}

async function mcpCall(tool, args, retried) {
  if (!mcp) mcp = mcpConnect()
  try {
    await mcp.ready
    const r = await mcp.request('tools/call', { name: tool, arguments: args })
    if (r?.isError) throw new Error(r.content?.[0]?.text || 'tool error')
    return r
  } catch (e) {
    // a hung helper never recovers on its own — and a helper bound to a
    // stale solo process identity fails every call: kill it, retry fresh
    if (!retried && /timeout|exited|no longer exists/.test(String(e.message))) {
      try { mcp.child.kill() } catch {}
      mcp = null
      return mcpCall(tool, args, true)
    }
    throw e
  }
}

// --- tee log location ---
// stable dir survives macOS /tmp purging (which permanently kills color for
// live sessions: script's deleted-but-open fd can't be re-attached)
const TEE_DIR = path.join(process.env.HOME, '.solo-remote-tee')
function teePath(pid) {
  const a = path.join(TEE_DIR, pid + '.log')
  if (existsSync(a)) return a
  const b = `/tmp/solo-tee-${pid}.log`
  return existsSync(b) ? b : a
}
// housekeeping on boot: drop logs whose process is gone
try {
  for (const f of readdirSync(TEE_DIR)) {
    const pid = Number(f.replace('.log', ''))
    if (pid) { try { process.kill(pid, 0) } catch { try { unlinkSync(path.join(TEE_DIR, f)) } catch {} } }
  }
} catch {}

// --- agent titles ---
// Solo shows AI-generated session titles in its sidebar but doesn't expose them
// over any API (they're in-memory OSC terminal titles). For Claude agents we can
// recover the same title from Claude Code's session files in ~/.claude/projects:
// the pty pid gives us cwd (lsof) and often the session id (`claude --resume <id>`),
// and the session .jsonl contains {"type":"ai-title","aiTitle":"..."} records.
const titleCache = new Map()   // pid -> { title, sessionId, at }

async function claudeInfo(pid) {
  const hit = titleCache.get(pid)
  if (hit && Date.now() - hit.at < 20000) return hit
  let title = null, sessionId = null, file = null, infoCwd = null
  try {
    // find the claude process: the pty pid itself, or a direct child
    let cmd = (await run('ps', ['-o', 'command=', '-p', String(pid)])).stdout.trim()
    let cpid = pid
    if (!/\bclaude\b/.test(cmd)) {
      const kids = (await run('pgrep', ['-P', String(pid)]).catch(() => ({ stdout: '' }))).stdout.split('\n').filter(Boolean)
      for (const k of kids) {
        const kcmd = (await run('ps', ['-o', 'command=', '-p', k])).stdout.trim()
        if (/\bclaude\b/.test(kcmd)) { cmd = kcmd; cpid = Number(k); break }
      }
    }
    if (!/\bclaude\b/.test(cmd)) throw new Error('not a claude agent')

    const cwdOut = (await run('lsof', ['-a', '-p', String(cpid), '-d', 'cwd', '-Fn'])).stdout
    const cwd = (cwdOut.split('\n').find(l => l.startsWith('n')) || '').slice(1)
    if (!cwd) throw new Error('no cwd')
    infoCwd = cwd
    const dir = `${process.env.HOME}/.claude/projects/${cwd.replace(/[\/.]/g, '-')}`

    const m = cmd.match(/--resume[= ]+([0-9a-f-]{36})/) || cmd.match(/--session-id[= ]+([0-9a-f-]{36})/i)
    if (m) file = `${dir}/${m[1]}.jsonl`
    else {
      // no explicit session id: pick the session file most recently written
      // since this process started (covers fresh sessions and bare --resume)
      const started = new Date((await run('ps', ['-o', 'lstart=', '-p', String(cpid)])).stdout.trim()).getTime()
      const files = readdirSync(dir).filter(f => f.endsWith('.jsonl'))
        .map(f => ({ f: `${dir}/${f}`, st: statSync(`${dir}/${f}`) }))
        .filter(x => x.st.mtimeMs >= started - 60000)
        .sort((a, b) => b.st.mtimeMs - a.st.mtimeMs)
      file = files[0]?.f
    }
    if (file) {
      sessionId = path.basename(file, '.jsonl')
      const grep = await run('grep', ['-h', '"type":"ai-title"', file]).catch(() => ({ stdout: '' }))
      const last = grep.stdout.trim().split('\n').filter(Boolean).pop()
      if (last) title = JSON.parse(last).aiTitle || null
    }
  } catch {}
  const info = { title, sessionId, file, cwd: infoCwd, at: Date.now() }
  titleCache.set(pid, info)
  return info
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x')

  if (url.pathname === '/login' && req.method === 'POST') {
    const isJson = (req.headers['content-type'] || '').includes('json')
    if (Date.now() < pinGuard.lockedUntil) {
      if (isJson) { res.writeHead(429, { 'content-type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'locked — try again in a minute' })); return }
      return sendLogin(res, 'locked — try again in a minute')
    }
    const body = await readBody(req)
    const pin = isJson ? String(JSON.parse(body).pin || '') : (new URLSearchParams(body).get('pin') || '')
    if (pin.length === auth.pin.length && crypto.timingSafeEqual(Buffer.from(pin), Buffer.from(auth.pin))) {
      pinGuard.fails = 0
      if (isJson) { setCookie(res, { status: 200, headers: { 'content-type': 'application/json' } }); res.end(JSON.stringify({ ok: true, data: {} })) }
      else { setCookie(res, { headers: { location: '/' } }); res.end() }
    } else {
      if (++pinGuard.fails >= 5) { pinGuard.fails = 0; pinGuard.lockedUntil = Date.now() + 60000 }
      if (isJson) { res.writeHead(401, { 'content-type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'wrong pin' })) }
      else sendLogin(res, 'wrong pin')
    }
    return
  }

  // passkey login: no session required (this IS the login)
  if (url.pathname === '/webauthn/login-options') {
    const challenge = b64url(crypto.randomBytes(32))
    challenges.set('login', { challenge, at: Date.now() })
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({
      ok: true,
      data: {
        challenge,
        rpId: rpIdFor(req),
        allowCredentials: auth.credentials.map(c => ({ type: 'public-key', id: c.id })),
        userVerification: 'required',
        timeout: 60000,
      },
    }))
    return
  }

  if (url.pathname === '/webauthn/login' && req.method === 'POST') {
    try {
      const body = JSON.parse(await readBody(req))
      const cred = auth.credentials.find(c => c.id === body.id)
      if (!cred) throw new Error('unknown credential')
      const clientDataJSON = Buffer.from(body.response.clientDataJSON, 'base64url')
      const clientData = JSON.parse(clientDataJSON.toString())
      const expect = challenges.get('login')
      if (!expect || Date.now() - expect.at > 120000) throw new Error('challenge expired')
      if (clientData.type !== 'webauthn.get' || clientData.challenge !== expect.challenge) throw new Error('bad challenge')
      const authenticatorData = Buffer.from(body.response.authenticatorData, 'base64url')
      const rpIdHash = crypto.createHash('sha256').update(rpIdFor(req)).digest()
      if (!authenticatorData.subarray(0, 32).equals(rpIdHash)) throw new Error('rpId mismatch')
      if (!verifyWebauthnSig(cred, authenticatorData, clientDataJSON, Buffer.from(body.response.signature, 'base64url')))
        throw new Error('bad signature')
      challenges.delete('login')
      setCookie(res, { status: 200, headers: { 'content-type': 'application/json' } })
      res.end(JSON.stringify({ ok: true, data: {} }))
    } catch (e) {
      res.writeHead(401, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: String(e.message || e) }))
    }
    return
  }

  const publicAsset = url.pathname.startsWith('/icons/') || url.pathname === '/manifest.json' || url.pathname === '/sw.js'
  const session = sessionFrom(req)
  if (!publicAsset && !session) {
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) return sendLogin(res)
    res.writeHead(401, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: false, error: 'unauthorized' }))
    return
  }

  if (url.pathname === '/logout' && req.method === 'POST') {
    if (session) sessions.delete(session)
    res.writeHead(200, {
      'set-cookie': 'solo_remote=; Max-Age=0; Path=/',
      'content-type': 'application/json',
    })
    res.end(JSON.stringify({ ok: true, data: {} }))
    return
  }

  // passkey registration: requires an authenticated session
  if (url.pathname === '/webauthn/reg-options') {
    const challenge = b64url(crypto.randomBytes(32))
    challenges.set('reg', { challenge, at: Date.now() })
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({
      ok: true,
      data: {
        challenge,
        rp: { id: rpIdFor(req), name: 'Solo Remote' },
        user: { id: b64url(Buffer.from('solo-remote-user')), name: 'dean', displayName: 'Dean' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
        attestation: 'none',
        excludeCredentials: auth.credentials.map(c => ({ type: 'public-key', id: c.id })),
        timeout: 60000,
      },
    }))
    return
  }

  if (url.pathname === '/webauthn/register' && req.method === 'POST') {
    try {
      const body = JSON.parse(await readBody(req))
      const clientDataJSON = Buffer.from(body.response.clientDataJSON, 'base64url')
      const clientData = JSON.parse(clientDataJSON.toString())
      const expect = challenges.get('reg')
      if (!expect || Date.now() - expect.at > 120000) throw new Error('challenge expired')
      if (clientData.type !== 'webauthn.create' || clientData.challenge !== expect.challenge) throw new Error('bad challenge')
      const att = cborDecode(Buffer.from(body.response.attestationObject, 'base64url')).value
      const authData = att.get('authData')
      // authData: rpIdHash(32) flags(1) counter(4) aaguid(16) credIdLen(2) credId cosePubKey
      const credIdLen = authData.readUInt16BE(53)
      const credId = authData.subarray(55, 55 + credIdLen)
      const cose = cborDecode(authData.subarray(55 + credIdLen)).value
      const { alg, key } = coseToKey(cose)
      auth.credentials.push({ id: b64url(credId), alg, key, addedAt: new Date().toISOString() })
      saveAuth()
      challenges.delete('reg')
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, data: { count: auth.credentials.length } }))
    } catch (e) {
      res.writeHead(400, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: String(e.message || e) }))
    }
    return
  }

  if (url.pathname === '/auth-info') {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true, data: { passkeys: auth.credentials.length, vapidPublicKey: auth.vapid.publicKey, pushSubs: auth.pushSubs.length, notifyEnabled: auth.notifyEnabled } }))
    return
  }

  if (url.pathname === '/notify-seen' && req.method === 'POST') {
    try {
      const { procId } = JSON.parse(await readBody(req))
      pendingNotifs.delete('idle-' + procId)
      pendingNotifs.delete('dead-' + procId)
      for (const n of notifLog) if (n.procId === procId || n.tag === 'dead-' + procId) n.read = true
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, data: {} }))
    } catch (e) {
      res.writeHead(400, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: String(e.message || e) }))
    }
    return
  }

  if (url.pathname === '/notifications') {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true, data: {
      items: [...notifLog].reverse(),
      unread: notifLog.filter(n => !n.read).length,
    }}))
    return
  }

  if (url.pathname === '/notifications/read' && req.method === 'POST') {
    for (const n of notifLog) n.read = true
    pendingNotifs.clear()
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true, data: {} }))
    return
  }

  if (url.pathname === '/notifications/clear' && req.method === 'POST') {
    notifLog.length = 0
    pendingNotifs.clear()
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true, data: {} }))
    return
  }

  if (url.pathname === '/viewing' && req.method === 'POST') {
    try {
      const { procId } = JSON.parse(await readBody(req))
      viewing.procId = procId ?? null
      viewing.at = Date.now()
    } catch {}
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true, data: {} }))
    return
  }

  if (url.pathname === '/notify-config' && req.method === 'POST') {
    try {
      const { enabled } = JSON.parse(await readBody(req))
      auth.notifyEnabled = !!enabled
      saveAuth()
    } catch {}
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true, data: { enabled: auth.notifyEnabled } }))
    return
  }

  if (url.pathname === '/push/subscribe' && req.method === 'POST') {
    try {
      const sub = JSON.parse(await readBody(req))
      if (!sub?.endpoint) throw new Error('bad subscription')
      if (!auth.pushSubs.find(s => s.endpoint === sub.endpoint)) { auth.pushSubs.push(sub); saveAuth() }
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, data: { count: auth.pushSubs.length } }))
    } catch (e) {
      res.writeHead(400, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: String(e.message || e) }))
    }
    return
  }

  if (url.pathname.startsWith('/api/')) {
    try {
      const { base, token } = solo()
      const body = req.method === 'GET' || req.method === 'HEAD'
        ? undefined
        : await new Promise((ok, err) => {
            const chunks = []
            req.on('data', c => chunks.push(c))
            req.on('end', () => ok(Buffer.concat(chunks)))
            req.on('error', err)
          })
      const upstream = await fetch(base + url.pathname + url.search, {
        method: req.method,
        headers: {
          authorization: `Bearer ${token}`,
          ...(req.headers['content-type'] ? { 'content-type': req.headers['content-type'] } : {}),
        },
        body: body?.length ? body : undefined,
      })
      res.writeHead(upstream.status, { 'content-type': upstream.headers.get('content-type') || 'application/json' })
      res.end(Buffer.from(await upstream.arrayBuffer()))
    } catch (e) {
      res.writeHead(502, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'solo unreachable', detail: String(e.message || e) }))
    }
    return
  }

  if (url.pathname === '/input' && req.method === 'POST') {
    try {
      const body = JSON.parse(await new Promise((ok, err) => {
        const chunks = []
        req.on('data', c => chunks.push(c))
        req.on('end', () => ok(Buffer.concat(chunks).toString()))
        req.on('error', err)
      }))
      const args = { process_id: Number(body.processId) }
      // the anonymous MCP session has no project scope: resolve it per process
      try {
        const { base, token } = solo()
        const pr = await fetch(`${base}/api/processes/${args.process_id}`, { headers: { authorization: `Bearer ${token}` } })
        const pj = (await pr.json()).data
        if (pj?.projectId) args.project_id = pj.projectId
      } catch {}
      if (body.bytes) args.bytes = body.bytes
      else { args.input = String(body.input ?? ''); args.submit = body.submit !== false }
      await mcpCall('send_input', args)
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, data: {} }))
    } catch (e) {
      res.writeHead(502, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: String(e.message || e) }))
    }
    return
  }

  // --- color terminal stream ---
  // Agents spawned with the "Claude (color)" tool run inside `script -qF`,
  // which tees the raw pty byte stream (ANSI intact) to /tmp/solo-tee-<pid>.log.
  // /tee reports availability + pty size; /tee-data serves bytes from an offset
  // for xterm.js to replay/follow.
  if (url.pathname === '/tee') {
    const pid = Number(url.searchParams.get('pid'))
    const log = teePath(pid)
    let info = { available: false }
    try {
      const size = statSync(log).size
      info = { available: true, size }
      // outer pty = solo's desktop terminal size (the root pid's tty)
      try {
        const otty = (await run('ps', ['-o', 'tty=', '-p', String(pid)])).stdout.trim()
        if (otty && otty !== '??') {
          const osz = (await run('stty', ['-f', '/dev/' + otty, 'size'])).stdout.trim().split(/\s+/).map(Number)
          if (osz[0] && osz[1]) { info.outerRows = osz[0]; info.outerCols = osz[1] }
        }
      } catch {}
      // pty size: find a descendant on a ttys* terminal
      let pids = [pid]
      for (let d = 0; d < 3 && pids.length; d++) {
        const kids = (await Promise.all(pids.map(p => run('pgrep', ['-P', String(p)]).catch(() => ({ stdout: '' })))))
          .flatMap(r => r.stdout.split('\n').filter(Boolean))
        for (const k of kids) {
          const tty = (await run('ps', ['-o', 'tty=', '-p', k])).stdout.trim()
          if (tty && tty !== '??') {
            const sz = (await run('stty', ['-f', '/dev/' + tty, 'size'])).stdout.trim().split(/\s+/).map(Number)
            if (sz[0] && sz[1]) { info.rows = sz[0]; info.cols = sz[1] }
            break
          }
        }
        if (info.rows) break
        pids = kids
      }
    } catch {}
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true, data: info }))
    return
  }

  if (url.pathname === '/resize' && req.method === 'POST') {
    // resize the wrapped session's inner pty so the TUI reflows to the
    // viewer's dimensions (solo's outer pty is untouched)
    try {
      const body = JSON.parse(await new Promise((ok, err) => {
        const chunks = []
        req.on('data', c => chunks.push(c))
        req.on('end', () => ok(Buffer.concat(chunks).toString()))
        req.on('error', err)
      }))
      const { pid, cols, rows } = body
      if (!pid || !cols || !rows || cols < 20 || rows < 5 || cols > 500 || rows > 600) throw new Error('bad dims')
      // find the deepest descendant tty (script's inner pty)
      let pids = [Number(pid)], tty = null
      for (let d = 0; d < 4 && pids.length; d++) {
        const kids = (await Promise.all(pids.map(p => run('pgrep', ['-P', String(p)]).catch(() => ({ stdout: '' })))))
          .flatMap(r => r.stdout.split('\n').filter(Boolean))
        for (const k of kids) {
          const t = (await run('ps', ['-o', 'tty=', '-p', k])).stdout.trim()
          if (t && t !== '??') tty = t
        }
        pids = kids
      }
      if (!tty) throw new Error('no tty')
      // if the pty is already at the target size, setting it again emits no
      // SIGWINCH and the app never repaints — jiggle one column to force it
      const cur = (await run('stty', ['-f', '/dev/' + tty, 'size'])).stdout.trim().split(/\s+/).map(Number)
      if (cur[0] === rows && cur[1] === cols) {
        await run('stty', ['-f', '/dev/' + tty, 'rows', String(rows), 'columns', String(cols + 1)])
        await new Promise(r => setTimeout(r, 50))
      }
      await run('stty', ['-f', '/dev/' + tty, 'rows', String(rows), 'columns', String(cols)])
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, data: { tty, rows, cols } }))
    } catch (e) {
      res.writeHead(400, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: String(e.message || e) }))
    }
    return
  }

  if (url.pathname === '/tee-data') {
    const pid = Number(url.searchParams.get('pid'))
    const off = Number(url.searchParams.get('off') || 0)
    const log = teePath(pid)
    try {
      const size = statSync(log).size
      const len = Math.min(Math.max(0, size - off), 512 * 1024)
      const buf = Buffer.alloc(len)
      if (len > 0) {
        const fd = openSync(log, 'r')
        readSync(fd, buf, 0, len, off)
        closeSync(fd)
      }
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'x-next-off': String(off + len) })
      res.end(buf)
    } catch (e) {
      res.writeHead(404, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'no tee log' }))
    }
    return
  }

  if (url.pathname.startsWith('/vendor/') || url.pathname.startsWith('/icons/') ||
      url.pathname === '/manifest.json' || url.pathname === '/sw.js') {
    try {
      const sub = url.pathname.startsWith('/vendor/') ? 'vendor' : url.pathname.startsWith('/icons/') ? 'icons' : ''
      const f = path.join(__dirname, sub, path.basename(url.pathname))
      const type = url.pathname.endsWith('.css') ? 'text/css'
        : url.pathname.endsWith('.js') ? 'application/javascript'
        : url.pathname.endsWith('.json') ? 'application/manifest+json'
        : url.pathname.endsWith('.svg') ? 'image/svg+xml'
        : 'image/png'
      res.writeHead(200, { 'content-type': type, 'cache-control': url.pathname === '/sw.js' ? 'no-store' : 'public, max-age=86400' })
      res.end(readFileSync(f))
    } catch { res.writeHead(404); res.end() }
    return
  }

  if (url.pathname === '/agent-session') {
    const pid = Number(url.searchParams.get('pid'))
    const info = pid ? await claudeInfo(pid) : {}
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true, data: { sessionId: info.sessionId || null } }))
    return
  }

  if (url.pathname === '/agent-files') {
    // recently referenced file paths from the conversation, for quick-open chips
    try {
      const pid = Number(url.searchParams.get('pid'))
      const info = await claudeInfo(pid)
      if (!info.file || !info.cwd) throw new Error('no session')
      const text = readFileSync(info.file, 'utf8')
      const lines = text.split('\n').slice(-400)
      const re = /(?:^|[\s"'`(\[])((?:\.{0,2}\/)?[\w.-]+(?:\/[\w.-]+)*\.(?:md|txt|ts|tsx|js|jsx|mjs|cjs|json|jsonc|py|rb|go|rs|java|kt|css|scss|html|xml|yml|yaml|toml|sh|zsh|sql|php|c|h|cpp|hpp|swift|vue|svelte|prisma|graphql|env|conf|ini|csv))(?=$|[\s"'`).\],:;])/g
      const seen = new Map()   // rel path -> recency index
      let idx = 0
      for (const line of lines) {
        idx++
        let m
        while ((m = re.exec(line))) {
          let rel = m[1].replace(/^\.\//, '')
          if (rel.startsWith('/')) {
            if (!rel.startsWith(info.cwd + '/')) continue
            rel = rel.slice(info.cwd.length + 1)
          }
          if (rel.includes('..') || rel.length > 200) continue
          try {
            const st = statSync(path.join(info.cwd, rel))
            if (st.isFile() && st.size < 2 * 1024 * 1024) seen.set(rel, idx)
          } catch {}
        }
      }
      const files = [...seen.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([rel]) => rel)
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, data: { files, cwd: info.cwd } }))
    } catch (e) {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, data: { files: [] } }))
    }
    return
  }

  if (url.pathname === '/file') {
    // read-only file fetch, strictly contained within the agent's cwd
    try {
      const pid = Number(url.searchParams.get('pid'))
      const rel = url.searchParams.get('path') || ''
      const info = await claudeInfo(pid)
      if (!info.cwd) throw new Error('no cwd')
      const root = realpathSync(info.cwd)
      const full = realpathSync(path.join(root, rel))
      if (full !== root && !full.startsWith(root + '/')) throw new Error('outside project')
      const st = statSync(full)
      if (!st.isFile()) throw new Error('not a file')
      if (st.size > 512 * 1024) throw new Error('file too large to preview')
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, data: { path: rel, content: readFileSync(full, 'utf8'), mtime: st.mtimeMs } }))
    } catch (e) {
      res.writeHead(404, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: String(e.message || e) }))
    }
    return
  }

  if (url.pathname === '/agent-history') {
    // paginated conversation transcript from the claude session file
    try {
      const pid = Number(url.searchParams.get('pid'))
      const before = url.searchParams.get('before') ? Number(url.searchParams.get('before')) : null
      const limit = Math.min(Number(url.searchParams.get('limit') || 30), 100)
      const info = await claudeInfo(pid)
      if (!info.file) throw new Error('no session file')
      const text = readFileSync(info.file, 'utf8')
      const msgs = []
      for (const line of text.split('\n')) {
        if (!line) continue
        let j
        try { j = JSON.parse(line) } catch { continue }
        if (j.type !== 'user' && j.type !== 'assistant') continue
        const c = j.message?.content
        let body = ''
        if (typeof c === 'string') body = c
        else if (Array.isArray(c)) body = c.filter(b => b.type === 'text').map(b => b.text).join('\n')
        body = (body || '').trim()
        if (!body) continue
        msgs.push({ role: j.type, text: body.length > 4000 ? body.slice(0, 4000) + '\n…' : body, ts: j.timestamp || null })
      }
      const end = before ?? msgs.length
      const start = Math.max(0, end - limit)
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, data: { messages: msgs.slice(start, end), before: start > 0 ? start : null, total: msgs.length } }))
    } catch (e) {
      res.writeHead(404, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: String(e.message || e) }))
    }
    return
  }

  if (url.pathname === '/agent-titles') {
    // ?procs=<id>:<pid>,<id>:<pid> -> { <id>: "title" | null }
    try {
      const pairs = (url.searchParams.get('procs') || '').split(',').filter(Boolean)
        .map(s => s.split(':').map(Number)).filter(([a, b]) => a && b)
      const out = {}
      await Promise.all(pairs.map(async ([id, pid]) => { out[id] = (await claudeInfo(pid)).title }))
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, data: out }))
    } catch (e) {
      res.writeHead(502, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: String(e.message || e) }))
    }
    return
  }

  if (url.pathname === '/agent-status') {
    try {
      const ids = (url.searchParams.get('ids') || '').split(',').map(Number).filter(Boolean)
      // anonymous MCP session has no project scope; map each id to its project
      const { base, token } = solo()
      const plist = await fetch(base + '/api/processes', { headers: { authorization: `Bearer ${token}` } })
      const procs = (await plist.json()).data?.processes || []
      const byId = Object.fromEntries(procs.map(p => [p.id, p]))
      const out = {}
      await Promise.all(ids.map(async id => {
        try {
          const r = await mcpCall('get_process_status', { process_id: id, project_id: byId[id]?.projectId })
          out[id] = JSON.parse(r.content?.[0]?.text || '{}')
          // session-file age: pty output is noisy (idle screens animate), but
          // the claude session file only changes on real messages/tool calls
          const pid = byId[id]?.pid
          if (pid) {
            const info = await claudeInfo(pid).catch(() => null)
            if (info?.file) out[id].sessionAgeSeconds = Math.max(0, (Date.now() - statSync(info.file).mtimeMs) / 1000)
          }
        } catch { out[id] = null }
      }))
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, data: out }))
    } catch (e) {
      res.writeHead(502, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: String(e.message || e) }))
    }
    return
  }

  if (url.pathname === '/agent-tools') {
    try {
      const r = await mcpCall('list_agent_tools', {})
      const tools = JSON.parse(r.content?.[0]?.text || '[]').filter(t => t.enabled)
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, data: { tools } }))
    } catch (e) {
      res.writeHead(502, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: String(e.message || e) }))
    }
    return
  }

  if (url.pathname === '/' || url.pathname === '/index.html') {
    try {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
      res.end(readFileSync(path.join(__dirname, 'index.html')))
    } catch {
      res.writeHead(500)
      res.end('index.html missing')
    }
    return
  }

  res.writeHead(404)
  res.end('not found')
})

// --- websocket stream for the active terminal (no library: server->client
// binary frames only; input still goes over HTTP POST /input) ---
function wsAccept(key) {
  return crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
}
function wsFrame(data) {
  const len = data.length
  let header
  if (len < 126) header = Buffer.from([0x82, len])
  else if (len < 65536) { header = Buffer.alloc(4); header[0] = 0x82; header[1] = 126; header.writeUInt16BE(len, 2) }
  else { header = Buffer.alloc(10); header[0] = 0x82; header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2) }
  return Buffer.concat([header, data])
}

server.on('upgrade', (req, socket) => {
  const url = new URL(req.url, 'http://x')
  if (url.pathname !== '/ws-term' || !sessionFrom(req)) { socket.destroy(); return }
  const pid = Number(url.searchParams.get('pid'))
  const log = teePath(pid)
  let off = Number(url.searchParams.get('off') || 0)
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${wsAccept(req.headers['sec-websocket-key'])}\r\n\r\n`)

  let closed = false
  const pump = () => {
    if (closed) return
    try {
      const size = statSync(log).size
      while (off < size && !closed) {
        const len = Math.min(size - off, 256 * 1024)
        const buf = Buffer.alloc(len)
        const fd = openSync(log, 'r')
        readSync(fd, buf, 0, len, off)
        closeSync(fd)
        off += len
        socket.write(wsFrame(buf))
      }
    } catch {}
  }
  pump()
  // fs.watch fires on append (fsevents); a slow interval catches anything missed
  let watcher = null
  try { watcher = fsWatch(log, pump) } catch {}
  const iv = setInterval(pump, 500)
  const cleanup = () => {
    if (closed) return
    closed = true
    clearInterval(iv)
    try { watcher?.close() } catch {}
    try { socket.destroy() } catch {}
  }
  socket.on('close', cleanup)
  socket.on('error', cleanup)
  socket.on('data', d => { if (d.length && (d[0] & 0x0f) === 8) cleanup() })   // client close frame
})

server.listen(PORT, '0.0.0.0', () => {
  const ips = Object.values(networkInterfaces()).flat()
    .filter(i => i && i.family === 'IPv4' && !i.internal).map(i => i.address)
  console.log(`Solo Remote listening on:`)
  console.log(`  http://localhost:${PORT}`)
  for (const ip of ips) console.log(`  http://${ip}:${PORT}   <- open this on your phone`)
  console.log(`PIN: ${auth.pin}   (stored in ${AUTH_FILE}; delete that file to rotate)`)
})
