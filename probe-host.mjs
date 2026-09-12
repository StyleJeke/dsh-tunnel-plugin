/**
 * 宿主半自测。
 *
 * 用桩 ctx 真的 apply 一次，把注册到的路由架在真 HTTP 服务器上，再经**真实公网**
 * （Cloudflare 命名隧道 + 边界代理）回打本机 DSH。认证已从 `?k=` 换成账号密码，
 * 所以这里完整走一遍登录流程：未登录跳转、登录页、错误口令、正确口令、会话 cookie，
 * 以及连续失败后的锁定。
 *
 * 关键：整个过程跑在**临时 DSH_HOME** 里。否则 apply() 会读到并覆写你真实的
 * `~/.dsh/tunnel/credentials.json`，把生产口令换成测试口令。
 */
import { createServer } from 'node:http'
import { spawnSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { randomBytes, scryptSync } from 'node:crypto'
import { tmpdir, homedir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const REAL_HOME = process.env.DSH_HOME ?? join(homedir(), '.dsh')
const HOME = join(tmpdir(), `dsh-tunnel-probe-home-${String(Date.now())}`)
mkdirSync(join(HOME, 'tunnel'), { recursive: true })
// 代理要读 DSH 的浏览器会话密钥来铸造它自己的 cookie，所以真凭据文件必须在场。
copyFileSync(join(REAL_HOME, '.credentials.yaml'), join(HOME, '.credentials.yaml'))

const TEST_USER = 'probe-user'
const TEST_PASS = 'Probe-Passw0rd-2026!'
const LOGIN_PATH = '/__tunnel/login'
const SESSION_COOKIE = 'dsh-tunnel-session'
{
  const salt = randomBytes(16)
  writeFileSync(join(HOME, 'tunnel', 'credentials.json'), JSON.stringify({
    version: 1,
    username: TEST_USER,
    salt: salt.toString('base64url'),
    hash: scryptSync(TEST_PASS, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 96 * 1024 * 1024 }).toString('base64url'),
    sessionSecret: randomBytes(32).toString('base64url'),
    n: 32768,
    r: 8,
    p: 1,
  }))
}
// 必须在 import 插件之前设置：resolveDshHome() 在模块加载期就会被调用。
process.env.DSH_HOME = HOME
// 按生产配置测：有真实的 Named Tunnel 配置就用它（固定域名 + 账号密码才是生产路径），
// 没有则退回快速隧道。刻意不把域名写死在这里 —— 那是使用者的私有域名。
{
  const realNamed = join(REAL_HOME, 'tunnel', 'named-tunnel.json')
  if (existsSync(realNamed)) copyFileSync(realNamed, join(HOME, 'tunnel', 'named-tunnel.json'))
}

const failures = []
const check = (label, ok, detail) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail === undefined || detail === '' ? '' : `  (${detail})`}`)
  if (!ok) failures.push(label)
}

process.on('exit', () => {
  spawnSync('taskkill', ['/F', '/IM', 'cloudflared.exe'], { stdio: 'ignore' })
  try {
    rmSync(HOME, { recursive: true, force: true })
  } catch {
    /* 临时目录清不掉不影响结论 */
  }
})

// --- 桩上下文 ---------------------------------------------------------------
const routes = new Map()
const logs = []
let applyThrew = null

const ctx = {
  logger: {
    info: (message) => logs.push(`INFO  ${message}`),
    warn: (message) => logs.push(`WARN  ${message}`),
  },
  effect(callback) {
    const disposer = callback()
    return () => {
      if (typeof disposer === 'function') disposer()
    }
  },
  webServer: {
    register(route) {
      routes.set(route.path, route.handler)
      return () => routes.delete(route.path)
    },
  },
}

const mod = await import(pathToFileURL('E:/dsh/dsh-tunnel-plugin/lib/index.js').href)
check('导出 inject = ["webServer"]', JSON.stringify(mod.inject) === '["webServer"]', JSON.stringify(mod.inject))
check('导出 apply', typeof mod.apply === 'function')
check('导出 readLoginUser', typeof mod.readLoginUser === 'function')
check('readLoginUser 读到测试账号', mod.readLoginUser(join(HOME, 'tunnel')) === TEST_USER, String(mod.readLoginUser(join(HOME, 'tunnel'))))
check('未配置时 readLoginUser 返回 null', mod.readLoginUser(join(HOME, 'nope')) === null)

try {
  mod.apply(ctx)
} catch (error) {
  applyThrew = error
}
check('apply 不抛错', applyThrew === null, applyThrew?.message)
check('注册了 3 条路由', routes.size === 3, [...routes.keys()].join(', '))

// --- 隧道地址解析（针对真实故障的回归测试）--------------------------------
const REAL_ANNOUNCEMENT = '2026-09-11T17:08:47Z INF |  https://premium-approx-hub-aberdeen.trycloudflare.com                                     |'
const REAL_FAILURE = '2026-09-11T17:09:02Z ERR Failed to request new quick tunnel error="Post \\"https://api.trycloudflare.com/tunnel\\": context deadline exceeded"'
check('能解析真实公布行', mod.extractTunnelUrl(REAL_ANNOUNCEMENT) === 'https://premium-approx-hub-aberdeen.trycloudflare.com')
check('不把控制面地址当隧道地址', mod.extractTunnelUrl(REAL_FAILURE) === undefined)
check('失败日志在前、公布行在后时取公布行', mod.extractTunnelUrl(`${REAL_FAILURE}\n${REAL_ANNOUNCEMENT}`) === 'https://premium-approx-hub-aberdeen.trycloudflare.com')
check('无连字符主机名一律不匹配', mod.extractTunnelUrl('see https://api.trycloudflare.com and https://www.trycloudflare.com') === undefined)

// --- 用真 HTTP 服务器承载已注册的路由 ---------------------------------------
const server = createServer((req, res) => {
  const path = new URL(req.url ?? '/', 'http://placeholder').pathname
  const handler = routes.get(path)
  if (handler === undefined) {
    res.writeHead(404, { 'content-type': 'text/plain' })
    res.end('no such route')
    return
  }
  void handler(req, res)
})
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
const localPort = server.address().port
const call = async (name) => {
  const res = await fetch(`http://127.0.0.1:${String(localPort)}/dsh-tunnel/api/${name}`)
  return res.json()
}

const initial = await call('status')
check('初始状态为 stopped', initial.phase === 'stopped', initial.phase)
check('状态里带登录账号名', initial.loginUser === TEST_USER, String(initial.loginUser))

console.log('\n--- 启动隧道 ---')
const started = await call('start')
console.log(logs.map((l) => `      ${l}`).join('\n'))
check('启动后 phase = running', started.phase === 'running', `${started.phase}${started.error ? ` / ${started.error}` : ''}`)
check('拿到公网地址', typeof started.publicUrl === 'string' && /^https:\/\/[^\s]+$/u.test(started.publicUrl), started.publicUrl ?? '')
check('访问链接里不含任何密钥', typeof started.accessUrl === 'string' && !started.accessUrl.includes('k='), started.accessUrl ?? '')
if (started.namedHostname) {
  check('固定域名模式：地址就是配置的域名', started.publicUrl === `https://${started.namedHostname}`, started.publicUrl ?? '')
}

// --- 经真实公网验证：完整登录流程 -------------------------------------------
if (started.phase === 'running') {
  const publicHost = new URL(started.publicUrl).host
  console.log(`\n--- 经真实公网验证 ${publicHost}（登录流程）---`)

  let ip = null
  for (let attempt = 0; attempt < 20 && ip === null; attempt += 1) {
    try {
      const doh = await (await fetch(`https://223.5.5.5/resolve?name=${publicHost}&type=A`)).json()
      const answer = Array.isArray(doh.Answer) ? doh.Answer.find((a) => a.type === 1) : undefined
      if (answer !== undefined) ip = answer.data
    } catch {
      /* retry */
    }
    if (ip === null) await new Promise((r) => setTimeout(r, 3000))
  }
  ip ??= '104.16.230.132'

  const base = ['--max-time', '40', '--resolve', `${publicHost}:443:${ip}`]
  const curl = (args) => (spawnSync('curl.exe', ['-s', '-o', 'NUL', '-w', '%{http_code}', ...base, ...args], { encoding: 'utf8' }).stdout ?? '').trim()
  const curlBody = (args) => spawnSync('curl.exe', ['-s', ...base, ...args], { encoding: 'utf8' }).stdout ?? ''

  // curl 默认不带 Sec-Fetch-Dest，也不带 Accept: text/html，所以必须显式模拟浏览器导航。
  // 这个区分是刻意的：导航给 303 跳登录页，资源与 /api 给 401（否则脚本会拿到登录页的 HTML）。
  const NAV = ['-H', 'Sec-Fetch-Dest: document', '-H', 'Accept: text/html,application/xhtml+xml']
  const anonymous = curl([...NAV, `${started.publicUrl}/`])
  check('公网 未登录导航 / -> 303 跳登录页', anonymous === '303', anonymous)
  const anonymousApi = curl([`${started.publicUrl}/dsh-tunnel/api/status`])
  check('公网 未登录的非导航请求 -> 401（不返回 HTML）', anonymousApi === '401', anonymousApi)
  const loginCode = curl([`${started.publicUrl}${LOGIN_PATH}`])
  check('公网 登录页 -> 200', loginCode === '200', loginCode)
  const loginHtml = curlBody([`${started.publicUrl}${LOGIN_PATH}`])
  check('登录页是密码表单', loginHtml.includes('<form') && loginHtml.includes('name="password"') && loginHtml.includes('type="password"'))

  // 浏览器提交表单一定会带 Origin，而 curl 默认不带 —— 上一版探针因此整个跳过了同源校验，
  // 让一个「正确口令被当成跨站请求拒掉」的 bug 溜了过去。这里显式带上。
  const ORIGIN = ['-H', `Origin: ${started.publicUrl.replace(/\/$/u, '')}`]

  const badCode = curl([...ORIGIN, '-X', 'POST', '--data', `username=${TEST_USER}&password=wrong-password`, `${started.publicUrl}${LOGIN_PATH}`])
  check('公网 口令错误 -> 303 回登录页', badCode === '303', badCode)

  const crossOrigin = curl(['-H', 'Origin: https://evil.example.com', '-X', 'POST', '--data', `username=${TEST_USER}&password=${encodeURIComponent(TEST_PASS)}`, `${started.publicUrl}${LOGIN_PATH}`])
  check('公网 真跨站 Origin -> 403', crossOrigin === '403', crossOrigin)

  // 浏览器在沙箱化上下文 / 隐私模式 / 密码管理器代填 / 重定向链之后会发 Origin: null，
  // 那是合法请求 —— 它曾经被当成跨站拒掉，所以这里必须锁住这个行为。
  const opaque = curl(['-H', 'Origin: null', '-X', 'POST', '--data', `username=${TEST_USER}&password=${encodeURIComponent(TEST_PASS)}`, `${started.publicUrl}${LOGIN_PATH}`])
  check('公网 Origin: null（不透明来源）-> 放行', opaque === '303', opaque)

  const loginResponse = spawnSync('curl.exe', [
    '-s', '-i', ...base, ...ORIGIN,
    '-X', 'POST', '--data', `username=${TEST_USER}&password=${encodeURIComponent(TEST_PASS)}`,
    `${started.publicUrl}${LOGIN_PATH}`,
  ], { encoding: 'utf8' }).stdout ?? ''
  const setCookie = loginResponse.split(/\r?\n/u).find((line) => line.toLowerCase().startsWith('set-cookie:')) ?? ''
  const sessionCookie = setCookie.split(';')[0].replace(/^set-cookie:\s*/iu, '').trim()
  check('公网 口令正确 -> 下发会话 cookie', sessionCookie.startsWith(`${SESSION_COOKIE}=v1.`), sessionCookie.slice(0, 44))
  check('会话 cookie 带 HttpOnly', /HttpOnly/iu.test(setCookie))
  check('会话 cookie 带 Secure（请求走的是 https）', /Secure/iu.test(setCookie))
  check('会话 cookie 是签名过的三段式', sessionCookie.split('=')[1]?.split('.').length === 3)

  const indexBody = curlBody(['-H', `Cookie: ${sessionCookie}`, `${started.publicUrl}/`])
  check('公网 已登录 -> 拿到 DSH 界面', indexBody.includes('__DSH_BOOT__'), `${String(indexBody.length)} bytes`)

  const statusBody = curlBody(['-H', `Cookie: ${sessionCookie}`, `${started.publicUrl}/dsh-tunnel/api/status`])
  check('公网 带会话能读到状态端点', statusBody.includes('"phase"'), statusBody.slice(0, 80))

  const forged = curl([...NAV, '-H', `Cookie: ${SESSION_COOKIE}=v1.eyJ2IjoxLCJ1IjoieCIsImV4cCI6OTk5OTk5OTk5OTk5OX0.bad`, `${started.publicUrl}/`])
  check('公网 伪造会话被拒（303 回登录页）', forged === '303', forged)

  // --- 连续失败会被锁定 -----------------------------------------------------
  console.log('\n--- 暴力破解限速 ---')
  let locked = false
  for (let attempt = 1; attempt <= 8 && !locked; attempt += 1) {
    const code = curl(['-X', 'POST', '--data', `username=${TEST_USER}&password=nope-${String(attempt)}`, `${started.publicUrl}${LOGIN_PATH}`])
    if (code === '429') locked = true
  }
  check('连错若干次后来源被锁定（429）', locked, locked ? '' : '8 次错误仍未触发锁定')

  // --- 自动重连 -------------------------------------------------------------
  console.log('\n--- 杀掉 cloudflared，看是否自动重连 ---')
  const killed = spawnSync('taskkill', ['/F', '/IM', 'cloudflared.exe'], { encoding: 'utf8' })
  check('已强制结束 cloudflared', killed.status === 0, (killed.stdout ?? '').trim().split(/\r?\n/u)[0])
  let healed = null
  for (let attempt = 0; attempt < 60 && healed === null; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 2000))
    const now = await call('status').catch(() => null)
    if (now !== null && now.renewCount > 0) healed = now
  }
  check('发生了自动重连', healed !== null, healed === null ? '90 秒内没有重连' : `renewCount=${String(healed.renewCount)}`)
  if (healed !== null) {
    check('重连后仍在运行', healed.phase === 'running', healed.phase)
    if (healed.namedHostname) {
      check('固定域名：重连后地址不变', healed.publicUrl === started.publicUrl, `${started.publicUrl} -> ${healed.publicUrl}`)
    } else {
      check('快速隧道：重连后地址确实变了', healed.publicUrl !== started.publicUrl)
    }
    check('lastChange 说明已重连', String(healed.lastChange).includes('重连'), healed.lastChange)
  }
}

console.log('\n--- 停止隧道 ---')
const stopped = await call('stop')
check('停止后 phase = stopped', stopped.phase === 'stopped', stopped.phase)
check('停止后清空访问链接', stopped.accessUrl === null, String(stopped.accessUrl))
check('没有残留 cloudflared 进程', (spawnSync('powershell.exe', ['-NoProfile', '-Command', '(Get-Process cloudflared -ErrorAction SilentlyContinue | Measure-Object).Count'], { encoding: 'utf8' }).stdout ?? '').trim() === '0')

server.close()
console.log(`\n${failures.length === 0 ? '全部通过' : `失败 ${String(failures.length)} 项: ${failures.join(', ')}`}`)
process.exit(failures.length === 0 ? 0 : 1)
