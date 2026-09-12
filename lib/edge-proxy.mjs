/**
 * DSH tunnel edge proxy.
 *
 * Sits between a public tunnel (cloudflared / ngrok / anything) and the loopback
 * DSH web server. It exists because DSH's own security model deliberately refuses
 * to be reached from a non-loopback authority:
 *
 *   - `/api` requests carry a Host/Origin trust fence that accepts only loopback
 *     authorities (or boot-time `--trusted-host` entries). A tunnel delivers the
 *     public hostname in `Host`, so the fence returns 403. Rewriting `Host` alone
 *     is NOT enough: a matching `Origin` is required too (verified: loopback Host
 *     + foreign Origin => 403).
 *   - Every RPC needs a browser-session cookie: HMAC-SHA256 signed with the
 *     `client-connection/browser-session` grant secret in `$DSH_HOME/.credentials.yaml`,
 *     bound to the normalized authority. The per-process `?token=` launch token is
 *     random and lives only in DSH memory, so it cannot be replayed to a remote
 *     browser. This proxy therefore mints an equivalent valid cookie from the
 *     durable secret and injects it.
 *
 * Consequence: THIS PROXY IS THE ONLY AUTHENTICATION GATE for anyone reaching the
 * tunnel. It refuses every request that does not carry a signed session cookie
 * obtained by presenting the configured account and password on its own login
 * page. Credentials are verified against a scrypt digest, never stored in the
 * clear, and repeated failures lock the source out with a growing delay.
 *
 * Plain ESM, zero dependencies. Runs as a file:
 *
 *   node edge-proxy.mjs <listenPort> <targetAuthority> [credentialsFile] [dshHome]
 *
 * `credentialsFile` defaults to `$DSH_HOME/tunnel/credentials.json`; create it
 * with `lib/set-credentials.mjs`. It is REQUIRED — the proxy exits rather than
 * serving an unauthenticated tunnel. `dshHome` empty => `$DSH_HOME`, else `~/.dsh`.
 */

import http from 'node:http'
import net from 'node:net'
import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const [, , LISTEN_PORT_RAW, TARGET_AUTHORITY, CREDENTIALS_FILE_ARG, DSH_HOME_ARG] = process.argv

/** Resolve the Harness home the same way DSH itself does. */
const DSH_HOME =
  typeof DSH_HOME_ARG === 'string' && DSH_HOME_ARG !== ''
    ? DSH_HOME_ARG
    : typeof process.env.DSH_HOME === 'string' && process.env.DSH_HOME !== ''
      ? process.env.DSH_HOME
      : join(homedir(), '.dsh')

const LISTEN_HOST = '127.0.0.1'
const LISTEN_PORT = Number(LISTEN_PORT_RAW)
const TARGET_URL = `http://${TARGET_AUTHORITY}`
const TARGET_HOST = TARGET_AUTHORITY.slice(0, TARGET_AUTHORITY.lastIndexOf(':'))
const TARGET_PORT = Number(TARGET_AUTHORITY.slice(TARGET_AUTHORITY.lastIndexOf(':') + 1))

/** Name of the cookie DSH's own browser auth reads (sha256 of the canonical authority). */
const AUTH_COOKIE_NAME = `dsh-auth-${createHash('sha256').update(TARGET_AUTHORITY).digest('base64url')}`
/** Name of this proxy's own session cookie. */
const SESSION_COOKIE = 'dsh-tunnel-session'
/** Cookie lifetime DSH accepts is bounded by its cookieMaxAgeDays (default 30). */
const COOKIE_TTL_MS = 29 * 24 * 60 * 60 * 1000
/** 登录会话有效期；到期需要重新登录。 */
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000
/** 登录页与登出的保留路径，放在 DSH 自己的路由之外。 */
const LOGIN_PATH = '/__tunnel/login'
const LOGOUT_PATH = '/__tunnel/logout'
/** scrypt 的内存上限：Node 默认 32MB，而 N=2^15、r=8 需要约 33.5MB，不抬高会直接抛错。 */
const SCRYPT_MAXMEM = 96 * 1024 * 1024
/** 连续失败几次后开始锁定。 */
const FAILURE_LIMIT = 5
/** 锁定上限：逐次加倍到 15 分钟封顶。 */
const LOCKOUT_CAP_MS = 15 * 60 * 1000

function fail(message) {
  process.stderr.write(`edge-proxy: ${message}\n`)
  process.exit(1)
}

if (!Number.isInteger(LISTEN_PORT) || LISTEN_PORT <= 0) fail(`invalid listen port ${JSON.stringify(LISTEN_PORT_RAW)}`)
if (!Number.isInteger(TARGET_PORT) || TARGET_PORT <= 0) fail(`invalid target authority ${JSON.stringify(TARGET_AUTHORITY)}`)
if (!existsSync(`${DSH_HOME}/.credentials.yaml`)) fail(`no credentials file at ${DSH_HOME}/.credentials.yaml (set DSH_HOME or pass dshHome)`)
process.stderr.write(`edge-proxy: DSH home = ${DSH_HOME}\n`)

/** 账号密码文件路径；宿主半会给，缺省落在 $DSH_HOME/tunnel/credentials.json。 */
const CREDENTIALS_FILE =
  typeof CREDENTIALS_FILE_ARG === 'string' && CREDENTIALS_FILE_ARG !== ''
    ? CREDENTIALS_FILE_ARG
    : join(DSH_HOME, 'tunnel', 'credentials.json')

/**
 * 读取账号密码。
 *
 * 只接受 scrypt 摘要 —— 文件里没有口令原文，即使泄露也不能直接登录。会话签名密钥单独
 * 存一份，于是 set-credentials 改口令时可以一并轮换，把所有既有会话立刻作废。
 *
 * 文件缺失或损坏时**直接退出**而不是放行：这是唯一的门槛，宁可不提供隧道，也不能
 * 在无认证的情况下把本机 DSH 暴露到公网。
 *
 * @param file - credentials.json 路径。
 * @returns 账号、口令摘要与会话密钥。
 */
function loadCredentials(file) {
  let parsed
  try {
    parsed = JSON.parse(readFileSync(file, 'utf8'))
  } catch (error) {
    const setter = join(dirname(fileURLToPath(import.meta.url)), 'set-credentials.mjs')
    fail(
      `读不出账号密码文件 ${file}（${error.message}）。\n` +
      `        先在本机执行下面这条命令设置账号密码，口令不会经手任何网络：\n` +
      `          node "${setter}"\n` +
      `        然后重新启动隧道。`,
    )
  }
  const shaped =
    parsed !== null && typeof parsed === 'object' &&
    typeof parsed.username === 'string' && parsed.username !== '' &&
    typeof parsed.salt === 'string' && typeof parsed.hash === 'string' &&
    typeof parsed.sessionSecret === 'string' &&
    Number.isInteger(parsed.n) && Number.isInteger(parsed.r) && Number.isInteger(parsed.p)
  if (!shaped) fail(`账号密码文件 ${file} 格式不对，请重新执行 set-credentials.mjs 生成`)
  const salt = Buffer.from(parsed.salt, 'base64url')
  const hash = Buffer.from(parsed.hash, 'base64url')
  const sessionSecret = Buffer.from(parsed.sessionSecret, 'base64url')
  if (hash.byteLength !== 32 || sessionSecret.byteLength !== 32) {
    fail(`账号密码文件 ${file} 的摘要长度不对，请重新执行 set-credentials.mjs 生成`)
  }
  return { username: parsed.username, salt, hash, sessionSecret, n: parsed.n, r: parsed.r, p: parsed.p }
}

const credentials = loadCredentials(CREDENTIALS_FILE)
process.stderr.write(`edge-proxy: 账号 ${JSON.stringify(credentials.username)}（scrypt N=${String(credentials.n)}）\n`)

function constantTimeEquals(a, b) {
  const left = Buffer.from(String(a), 'utf8')
  const right = Buffer.from(String(b), 'utf8')
  return left.byteLength === right.byteLength && timingSafeEqual(left, right)
}

/**
 * 校验账号口令。
 *
 * 无论账号对不对都照样做一次 scrypt：否则「账号不存在」会明显更快，等于把账号名
 * 白送给试探者。比较用 `timingSafeEqual`。
 *
 * @param username - 表单里的账号。
 * @param password - 表单里的口令。
 * @returns 是否通过。
 */
function verifyLogin(username, password) {
  const candidate = scryptSync(password, credentials.salt, 32, {
    N: credentials.n,
    r: credentials.r,
    p: credentials.p,
    maxmem: SCRYPT_MAXMEM,
  })
  const userOk = constantTimeEquals(username, credentials.username)
  const passOk = timingSafeEqual(candidate, credentials.hash)
  return userOk && passOk
}

/** 签发会话 cookie 值：`v1.<payload>.<hmac>`，与 DSH 自己的 cookie 同构。 */
function signSession(username) {
  const now = Date.now()
  const body = Buffer.from(
    JSON.stringify({ v: 1, u: username, iat: now, exp: now + SESSION_TTL_MS }),
    'utf8',
  ).toString('base64url')
  const mac = createHmac('sha256', credentials.sessionSecret).update(body).digest('base64url')
  return `v1.${body}.${mac}`
}

/** 校验会话 cookie；签名、版本或有效期任一不符都返回 undefined。 */
function readSession(value) {
  if (typeof value !== 'string') return undefined
  const parts = value.split('.')
  if (parts.length !== 3 || parts[0] !== 'v1') return undefined
  const expected = createHmac('sha256', credentials.sessionSecret).update(parts[1]).digest()
  const actual = Buffer.from(parts[2], 'base64url')
  if (actual.byteLength !== expected.byteLength || !timingSafeEqual(actual, expected)) return undefined
  let payload
  try {
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
  } catch {
    return undefined
  }
  if (payload === null || typeof payload !== 'object' || payload.v !== 1) return undefined
  if (!Number.isSafeInteger(payload.exp) || payload.exp <= Date.now()) return undefined
  return payload
}

/**
 * 登录失败的来源标识。
 *
 * 不能用 `socket.remoteAddress`：请求都来自本机的 cloudflared，那个值恒为 127.0.0.1，
 * 按它限速等于全局共用一个计数器。Cloudflare 会在 `CF-Connecting-IP` 里带上真实客户端
 * 地址，优先用它。
 */
function clientKey(req) {
  const cf = req.headers['cf-connecting-ip']
  if (typeof cf === 'string' && cf !== '') return cf
  const forwarded = req.headers['x-forwarded-for']
  if (typeof forwarded === 'string' && forwarded !== '') return forwarded.split(',')[0].trim()
  return String(req.socket.remoteAddress ?? 'unknown')
}

/** 失败计数表：key -> {count, lockedUntil}。单用户场景，内存里存一份足够。 */
const failures = new Map()

/** 剩余锁定时间；0 表示可以尝试。 */
function lockRemaining(key) {
  const entry = failures.get(key)
  if (entry === undefined) return 0
  const left = entry.lockedUntil - Date.now()
  return left > 0 ? left : 0
}

/** 记一次失败并按次数升级锁定：第 5 次锁 15 秒，之后 30、60…… 15 分钟封顶。 */
function noteFailure(key) {
  if (failures.size > 512) {
    const now = Date.now()
    for (const [other, entry] of failures) if (entry.lockedUntil < now) failures.delete(other)
  }
  const entry = failures.get(key) ?? { count: 0, lockedUntil: 0 }
  entry.count += 1
  if (entry.count >= FAILURE_LIMIT) {
    const over = entry.count - FAILURE_LIMIT
    entry.lockedUntil = Date.now() + Math.min(15000 * 2 ** over, LOCKOUT_CAP_MS)
  }
  failures.set(key, entry)
}

/**
 * 是否是一次页面导航。
 *
 * 未登录时导航要送去登录页，而脚本、样式、`/api` 请求必须拿到 401 —— 给它们返回
 * 登录页的 HTML 只会变成「Unexpected token <」这类难查的错。
 */
function isNavigation(req) {
  if (req.headers['sec-fetch-dest'] === 'document') return true
  const accept = req.headers.accept
  return typeof accept === 'string' && accept.includes('text/html')
}

/** 读取请求体，超过上限直接拒绝。 */
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > limit) {
        reject(new Error('body too large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

/** HTML 转义，登录页里唯一一处把外部文本拼进标记的地方。 */
function escapeHtml(text) {
  return String(text).replace(/[&<>"']/gu, (ch) =>
    ch === '&' ? '&amp;' : ch === '<' ? '&lt;' : ch === '>' ? '&gt;' : ch === '"' ? '&quot;' : '&#39;')
}

/** 登录页：单文件、无外部资源，跟随系统明暗主题。 */
function loginPage(error) {
  const notice = error === undefined || error === ''
    ? ''
    : `<div class="err">${escapeHtml(error)}</div>`
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>DSH 登录</title>
<style>
:root{color-scheme:light dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  font:14px/1.6 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;
  background:#0f1115;color:#e8ecf3}
@media (prefers-color-scheme:light){body{background:#f6f7f9;color:#1b1f27}}
.card{width:min(360px,calc(100vw - 32px));padding:28px 26px;border-radius:14px;
  border:1px solid rgba(127,127,127,.28);background:rgba(127,127,127,.08);
  box-shadow:0 18px 40px -24px rgba(0,0,0,.55)}
h1{margin:0 0 4px;font-size:17px;font-weight:600}
p.sub{margin:0 0 6px;font-size:12.5px;opacity:.7}
label{display:block;font-size:12px;opacity:.75;margin:14px 0 5px}
input{width:100%;box-sizing:border-box;padding:9px 11px;border-radius:8px;font-size:14px;
  border:1px solid rgba(127,127,127,.42);background:rgba(127,127,127,.10);color:inherit}
input:focus{outline:2px solid #5b8def;outline-offset:1px}
button{width:100%;margin-top:20px;padding:10px;border:0;border-radius:8px;font-size:14px;
  font-weight:600;color:#fff;background:#3b6fd4;cursor:pointer}
button:hover{filter:brightness(1.1)}
.err{margin-top:16px;padding:9px 11px;border-radius:8px;font-size:12.5px;
  border:1px solid rgba(239,107,107,.45);background:rgba(239,107,107,.14)}
</style></head><body>
<form class="card" method="post" action="${LOGIN_PATH}">
  <h1>DSH</h1>
  <p class="sub">这台机器上的 DeepSeek Harness，请先登录。</p>
  <label for="u">账号</label>
  <input id="u" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus>
  <label for="p">密码</label>
  <input id="p" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">登录</button>
  ${notice}
</form></body></html>
`
}

/**
 * 登录 POST 的同源校验。
 *
 * 它只用来挡登录 CSRF，**不是**身份校验 —— 身份由下面的口令负责。这里的尺度刻意放松，
 * 因为已经连续踩过两次：
 *
 * 1. 不能只比 `Host` —— cloudflared 会把 `Host` 改写成源站地址（`127.0.0.1:3081`），
 *    而浏览器的 `Origin` 是公网域名，两者必然不等，正确口令会被一并拒掉。
 * 2. 不能把「解析不了」当成「跨站」—— 浏览器在沙箱化上下文、隐私模式、密码管理器代填、
 *    或经过重定向链时会发 `Origin: null`（不透明来源）。那是合法请求，实际也踩到了。
 *
 * 所以只有一种情况拒绝：`Origin` **能解析**、且与 `Host` / `X-Forwarded-Host` 都对不上 ——
 * 那才是真正的跨站表单提交。即便如此，这套部署只有一个账号，登录 CSRF 本就无从下手，
 * 因此这条检查属于纵深防御，不承担认证职责。
 *
 * @param req - 登录请求。
 * @returns `{ok, seen}`；seen 是用于排错的观察值。
 */
function originAllowed(req) {
  const origin = req.headers.origin
  const host = String(req.headers.host ?? '-')
  const forwarded = String(req.headers['x-forwarded-host'] ?? '-')
  if (typeof origin !== 'string' || origin === '') return { ok: true, seen: `no origin host=${host}` }

  let originHost = null
  try {
    originHost = new URL(origin).host.toLowerCase()
  } catch {
    originHost = null
  }
  // 不透明来源（`null`）与任何解析不出的值一律放行，只记一笔。
  if (originHost === null || originHost === '') {
    return { ok: true, seen: `opaque origin=${JSON.stringify(origin)} host=${host}` }
  }

  const candidates = [req.headers.host, req.headers['x-forwarded-host']]
    .flatMap((value) => (typeof value === 'string' ? value.split(',') : []))
    .map((value) => value.trim().toLowerCase())
    .filter((value) => value !== '')
  return {
    ok: candidates.length === 0 || candidates.includes(originHost),
    seen: `origin=${originHost} host=${host} xfh=${forwarded}`,
  }
}

/** 登录 / 登出端点。 */
async function handleAuthEndpoint(req, res, url) {
  // 只有真正经过 HTTPS 才加 Secure；本机 http 调试时不加，免得 cookie 存不下来。
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : ''

  if (url.pathname === LOGOUT_PATH) {
    res.writeHead(303, {
      'cache-control': 'no-store',
      location: LOGIN_PATH,
      'set-cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`,
    })
    res.end()
    return
  }

  if (req.method === 'GET' || req.method === 'HEAD') {
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
    })
    res.end(req.method === 'HEAD' ? undefined : loginPage(url.searchParams.get('error') ?? undefined))
    return
  }

  if (req.method !== 'POST') {
    res.writeHead(405, { allow: 'GET, HEAD, POST', 'content-type': 'text/plain; charset=utf-8' })
    res.end('edge-proxy: method not allowed\n')
    return
  }

  // 同源校验：只用来挡登录 CSRF，**不是**身份校验 —— 身份由下面的口令负责。
  const sameOrigin = originAllowed(req)
  if (!sameOrigin.ok) {
    process.stderr.write(`edge-proxy: 登录被同源校验拒绝 ${sameOrigin.seen}\n`)
    res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
    res.end(`edge-proxy: cross-origin login rejected (${sameOrigin.seen})\n`)
    return
  }

  const key = clientKey(req)
  const locked = lockRemaining(key)
  if (locked > 0) {
    const seconds = Math.ceil(locked / 1000)
    res.writeHead(429, {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'retry-after': String(seconds),
    })
    res.end(`edge-proxy: too many failed attempts, retry in ${String(seconds)}s\n`)
    return
  }

  let body
  try {
    body = await readBody(req, 4096)
  } catch {
    res.writeHead(413, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
    res.end('edge-proxy: login payload too large\n')
    return
  }

  const params = new URLSearchParams(body)
  const username = params.get('username') ?? ''
  const password = params.get('password') ?? ''

  if (!verifyLogin(username, password)) {
    noteFailure(key)
    const remaining = lockRemaining(key)
    process.stderr.write(
      `edge-proxy: 登录失败 from=${key}${remaining > 0 ? ` 已锁定 ${String(Math.ceil(remaining / 1000))}s` : ''}\n`,
    )
    const message = remaining > 0
      ? `尝试次数过多，请 ${String(Math.ceil(remaining / 1000))} 秒后再试`
      : '账号或密码不正确'
    res.writeHead(303, {
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      location: `${LOGIN_PATH}?error=${encodeURIComponent(message)}`,
    })
    res.end()
    return
  }

  failures.delete(key)
  process.stderr.write(`edge-proxy: 登录成功 user=${JSON.stringify(username)} from=${key}\n`)
  res.writeHead(303, {
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    location: '/',
    'set-cookie': `${SESSION_COOKIE}=${signSession(username)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${String(SESSION_TTL_MS / 1000)}${secure}`,
  })
  res.end()
}

/** Read the durable browser-session signing secret DSH loaded at Connection activation. */
function readSessionSecret() {
  const raw = readFileSync(`${DSH_HOME}/.credentials.yaml`, 'utf8')
  const match = raw.match(/client-connection\/browser-session:[\s\S]*?secret:\s*([A-Za-z0-9_-]+)/)
  if (match === null) throw new Error(`no client-connection/browser-session secret in ${DSH_HOME}/.credentials.yaml`)
  const secret = Buffer.from(match[1], 'base64url')
  if (secret.byteLength !== 32) throw new Error(`browser-session secret is ${secret.byteLength} bytes, expected 32`)
  return secret
}

let secret
try {
  secret = readSessionSecret()
} catch (error) {
  fail(`cannot read the DSH browser-session secret: ${error.message}`)
}

// Minted cookies are cached briefly: the payload is time-bounded, so re-signing
// per request would be pure waste while a long tunnel serves thousands of calls.
let cachedCookie
let cachedCookieAt = 0
function sessionCookie() {
  const now = Date.now()
  if (cachedCookie !== undefined && now - cachedCookieAt < 60_000) return cachedCookie
  const body = Buffer.from(
    JSON.stringify({ version: 1, authority: TARGET_AUTHORITY, issuedAt: now, expiresAt: now + COOKIE_TTL_MS }),
    'utf8',
  ).toString('base64url')
  cachedCookie = `v1.${body}.${createHmac('sha256', secret).update(body).digest('base64url')}`
  cachedCookieAt = now
  return cachedCookie
}

function parseCookie(header, name) {
  if (typeof header !== 'string') return undefined
  for (const segment of header.split(';')) {
    const at = segment.indexOf('=')
    if (at === -1) continue
    if (segment.slice(0, at).trim() === name) return segment.slice(at + 1).trim()
  }
  return undefined
}

/**
 * Rewrite the request for the loopback DSH server.
 *
 * `host` must be the loopback authority or the fence 403s; `origin`/`referer` must
 * agree with it or the same fence catches the mismatch; `cookie` is replaced with a
 * freshly minted valid session so the remote browser never needs DSH's launch token.
 */
function buildForwardHeaders(headers, extraCookie) {
  const forward = { ...headers }
  forward.host = TARGET_AUTHORITY
  if (forward.origin !== undefined) forward.origin = TARGET_URL
  if (typeof forward.referer === 'string') {
    const rewritten = forward.referer.replace(/^https?:\/\/[^/]+/u, TARGET_URL)
    forward.referer = rewritten
  }
  forward.cookie = extraCookie === undefined ? `${AUTH_COOKIE_NAME}=${sessionCookie()}` : `${extraCookie}; ${AUTH_COOKIE_NAME}=${sessionCookie()}`
  // The public hostname must never reach the fence through a forwarding header.
  delete forward['x-forwarded-host']
  delete forward['x-forwarded-proto']
  return forward
}

/** DSH only ever emits relative redirects, but normalize an absolute loopback one just in case. */
function rewriteLocation(value) {
  if (typeof value !== 'string') return value
  return value.startsWith(TARGET_URL) ? value.slice(TARGET_URL.length) || '/' : value
}

const server = http.createServer((req, res) => {
  void handleRequest(req, res)
})

async function handleRequest(req, res) {
  let url
  try {
    url = new URL(req.url ?? '/', TARGET_URL)
  } catch {
    res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' })
    res.end('edge-proxy: malformed request target\n')
    return
  }

  // --- 登录端点：唯一不需要会话就能访问的路径 --------------------------------
  if (url.pathname === LOGIN_PATH || url.pathname === LOGOUT_PATH) {
    await handleAuthEndpoint(req, res, url)
    return
  }

  // --- gate -----------------------------------------------------------------
  const session = readSession(parseCookie(req.headers.cookie, SESSION_COOKIE))
  if (session === undefined) {
    if (isNavigation(req)) {
      res.writeHead(303, {
        'cache-control': 'no-store',
        'referrer-policy': 'no-referrer',
        location: LOGIN_PATH,
      })
      res.end()
      return
    }
    res.writeHead(401, {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
    })
    res.end(`DSH tunnel: authentication required. Sign in at ${LOGIN_PATH}\n`)
    return
  }

  // --- forward --------------------------------------------------------------
  const forwardHeaders = buildForwardHeaders(req.headers, undefined)
  const proxyReq = http.request(
    { host: TARGET_HOST, port: TARGET_PORT, method: req.method, path: url.pathname + url.search, headers: forwardHeaders },
    (proxyRes) => {
      const outHeaders = { ...proxyRes.headers }
      if (outHeaders.location !== undefined) outHeaders.location = rewriteLocation(outHeaders.location)
      // DSH's own cookie is authority-bound to the loopback target and is re-minted
      // per request here; letting the remote browser store it only adds confusion.
      if (outHeaders['set-cookie'] !== undefined) {
        const kept = outHeaders['set-cookie'].filter((entry) => !entry.startsWith('dsh-auth-'))
        if (kept.length === 0) delete outHeaders['set-cookie']
        else outHeaders['set-cookie'] = kept
      }
      res.writeHead(proxyRes.statusCode ?? 502, proxyRes.statusMessage, outHeaders)
      proxyRes.pipe(res)
    },
  )

  proxyReq.on('error', (error) => {
    if (res.headersSent) {
      res.destroy()
      return
    }
    res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
    res.end(`edge-proxy: cannot reach DSH at ${TARGET_AUTHORITY}: ${error.message}\n`)
  })

  req.pipe(proxyReq)
}

/**
 * WebSocket upgrade path. The browser's handshake carries Host and Origin, so the
 * same rewrite applies; without it DSH's fence rejects the socket and the UI hangs
 * on "connecting".
 */
server.on('upgrade', (req, socket, head) => {
  let url
  try {
    url = new URL(req.url ?? '/', TARGET_URL)
  } catch {
    socket.destroy()
    return
  }
  const session = readSession(parseCookie(req.headers.cookie, SESSION_COOKIE))
  if (session === undefined) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
    socket.destroy()
    return
  }

  const forwardHeaders = buildForwardHeaders(req.headers, undefined)
  const proxyReq = http.request({
    host: TARGET_HOST,
    port: TARGET_PORT,
    method: req.method,
    path: url.pathname + url.search,
    headers: forwardHeaders,
  })

  proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
    const statusLine = `HTTP/1.1 ${String(proxyRes.statusCode)} ${proxyRes.statusMessage ?? 'Switching Protocols'}\r\n`
    const headerLines = []
    for (let index = 0; index < proxyRes.rawHeaders.length; index += 2) {
      headerLines.push(`${proxyRes.rawHeaders[index]}: ${proxyRes.rawHeaders[index + 1]}\r\n`)
    }
    socket.write(statusLine + headerLines.join('') + '\r\n')
    if (proxyHead !== undefined && proxyHead.length > 0) socket.write(proxyHead)
    if (head !== undefined && head.length > 0) proxySocket.write(head)
    proxySocket.pipe(socket)
    socket.pipe(proxySocket)
    const teardown = () => {
      proxySocket.destroy()
      socket.destroy()
    }
    proxySocket.on('error', teardown)
    socket.on('error', teardown)
  })

  proxyReq.on('response', (proxyRes) => {
    // The target answered with plain HTTP instead of upgrading.
    socket.write(`HTTP/1.1 ${String(proxyRes.statusCode)} ${proxyRes.statusMessage ?? ''}\r\nConnection: close\r\n\r\n`)
    socket.destroy()
  })

  proxyReq.on('error', () => {
    socket.write('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n')
    socket.destroy()
  })

  proxyReq.end()
})

server.on('clientError', (_error, socket) => {
  if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n')
})

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  // 宿主半靠这一行判断代理已经就绪。这里不再输出任何密钥 —— 认证改由账号密码承担。
  process.stdout.write(`TUNNEL_PROXY_READY=${LISTEN_HOST}:${String(LISTEN_PORT)}->${TARGET_AUTHORITY}\n`)
})

for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(signal, () => {
    server.close(() => process.exit(0))
    setTimeout(() => process.exit(0), 1500).unref()
  })
}

/**
 * Parent watchdog.
 *
 * Windows does not kill a process's children when the parent dies, so a hard-killed
 * DSH would leave this proxy holding 127.0.0.1:3081 and the next start would fail with
 * a confusing EADDRINUSE. Poll the parent instead and exit with it. A normal Cordis
 * unload already terminates this process directly; this only covers the hard-kill path.
 */
const parentPid = process.ppid
const watchdog = setInterval(() => {
  try {
    process.kill(parentPid, 0)
  } catch {
    process.exit(0)
  }
}, 3000)
// The listening server keeps the loop alive; the watchdog must not.
watchdog.unref()
