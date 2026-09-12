/**
 * DSH 内网穿透（公网隧道）—— 宿主半。
 *
 * 把本机的 DSH Web 服务通过 Cloudflare 快速隧道发布到公网，让其他电脑用浏览器访问。
 * 隧道前方串一层边界代理（`lib/edge-proxy.mjs`），它负责三件 DSH 自己不会做的事：
 *
 *   1. 把 `Host` / `Origin` 重写成回环权威。DSH 的 `/api` 浏览器信任栅栏只接受
 *      回环或启动时声明的 `--trusted-host`，而隧道投递的是公网主机名 —— 只改 Host
 *      不够，`Origin` 必须同时匹配，否则 WebSocket 握手会被 403。
 *   2. 用 `$DSH_HOME/.credentials.yaml` 里的持久签名密钥铸造一个合法的浏览器会话
 *      cookie 并注入。DSH 每次进程启动生成的 `?token=` 是内存里的随机数，远端浏览器
 *      拿不到，所以无法靠转发链接通过认证。
 *   3. 用一次性访问密钥（`?k=...` 换 cookie）把守入口。因此**这层代理是唯一的口令关卡**。
 *
 * 宿主半只做编排：解析可执行文件、拉起两个子进程、抓取就绪标志与公网地址、维护状态机，
 * 并把状态经自有 HTTP 路由暴露给浏览器半（客户端半不依赖任何 DSH 包，见 package.json 说明）。
 *
 * @module dsh-tunnel
 */
import { spawn } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

/** 本插件独占的路由前缀，避免与产品路由相撞。 */
const ROUTE_PREFIX = '/dsh-tunnel'
/**
 * 快速隧道地址的匹配规则。
 *
 * 不能图省事写成 `https://<任意>\.trycloudflare\.com`：cloudflared 在**创建隧道失败**时
 * 会把控制面地址 `https://api.trycloudflare.com` 打进日志 —— 那是 Cloudflare 的 API 主机，
 * 打开它只会得到 `{"success":false,"result":null,"errors":[{"code":10005,
 * "message":"Method Not Allowed"}]}`。它出现在真正的隧道地址之前，宽松的正则会先把错的抓走，
 * 界面于是显示一个死链接。
 *
 * 所以要求主机名至少含一个连字符：快速隧道的名字由词表拼出（`premium-approx-hub-aberdeen`），
 * 而基础设施主机（api、www 等）都是单个单词。
 */
const TUNNEL_URL = /https:\/\/[a-z0-9]+(?:-[a-z0-9]+)+\.trycloudflare\.com/u
/** 正式公布行形如 `INF |  https://xxx.trycloudflare.com      |`，优先取它。 */
const TUNNEL_ANNOUNCEMENT = /\|\s*(https:\/\/[a-z0-9]+(?:-[a-z0-9]+)+\.trycloudflare\.com)/u
/** 代理就绪时打印的标记。认证改由账号密码承担，不再有密钥要抓。 */
const PROXY_READY_PATTERN = /TUNNEL_PROXY_READY=/u
/** DSH 自己的监听权威，也是代理要重写到的目标。 */
const TARGET_AUTHORITY = '127.0.0.1:3080'
/** 边界代理的监听端口（仅回环）。 */
const PROXY_PORT = 3081
/**
 * 隧道最长存活时间；0 表示**永不自动断开**（当前默认）。
 *
 * 默认取 0 是刻意的。快速隧道的域名只在 cloudflared **进程**存活期间保持不变：进程一旦
 * 重启，Cloudflare 会分配一个新域名。而人在外地时旧链接已经失效、新链接又无从得知 ——
 * 定时断开等于把自己锁在门外。所以安全边界改由「手动停止」和那道一次性访问密钥承担，
 * 而不是靠一个到点就断的计时器。
 *
 * 想恢复定时断开就把它设成毫秒数（例如 12 * 60 * 60 * 1000）。
 */
const AUTO_STOP_MS = 0
/** cloudflared 意外退出后自动重连的最大次数。 */
const MAX_HEAL_ATTEMPTS = 6
/** 每次重连前的等待时间，同时也是重试的节奏。 */
const HEAL_DELAY_MS = 5000
/** 等待代理与隧道就绪的上限。 */
const WAIT_PROXY_MS = 20000
const WAIT_TUNNEL_MS = 75000
/** 子进程日志保留上限，避免长隧道把内存吃满。 */
const LOG_LIMIT = 8192
/**
 * 本插件源码的修订号。
 *
 * 插件包是进程启动时 import 的，改了文件不一定立刻生效；把修订号放进状态里，
 * 就能一眼看出「运行中的进程装的是哪一版」，不必靠猜或反复重启。
 */
const REVISION = 5

/** cloudflared 的常见安装位置，PATH 里找不到时逐一回退。 */
const CLOUDFLARED_FALLBACKS = [
  'C:\\Program Files (x86)\\cloudflared\\cloudflared.exe',
  'C:\\Program Files\\cloudflared\\cloudflared.exe',
  join(homedir(), 'cloudflared.exe'),
]

/**
 * 持久化配置目录（`$DSH_HOME/tunnel`）。里面三样东西共同支撑「链接一直可用」：
 * `credentials.json` 登录账号密码、`named-tunnel.json` 固定域名、`autostart` 让隧道随 DSH 自动开启。
 */
const CONFIG_DIR_NAME = 'tunnel'
/** 等待 Named Tunnel 注册上连接的上限。 */
const WAIT_REGISTER_MS = 60000
/** 自启时延迟多久再开隧道，避开 DSH 自身启动的那一阵忙。 */
const AUTOSTART_DELAY_MS = 5000

/** 硬依赖：没有 HTTP 载体就没有这个浏览器插件。 */
export const inject = ['webServer']

/**
 * 读出登录账号名，只用于在设置页显示「以谁的身份登录」。
 *
 * 认证本身完全在边界代理里做（它读同一个文件里的 scrypt 摘要），宿主半既不接触口令，
 * 也不参与校验 —— 少一处持有秘密的地方。
 *
 * @param configDir - 配置目录。
 * @returns 账号名；文件缺失或损坏时为 null（代理启动时会明确报错）。
 */
export function readLoginUser(configDir) {
  try {
    const parsed = JSON.parse(readFileSync(join(configDir, 'credentials.json'), 'utf8'))
    const username = parsed?.username
    if (typeof username === 'string' && username !== '') return username
  } catch {
    /* 未配置；代理启动时会给出可执行的处理办法 */
  }
  return null
}

/**
 * 读取 Named Tunnel 配置。
 *
 * 存在这个文件就代表用固定域名：启动方式改为 `cloudflared tunnel run <name>`，公布的地址
 * 由 `hostname` 直接给出，不再靠解析日志。文件不存在则退回快速隧道。
 *
 * @param configDir - 配置目录。
 * @returns `{name, hostname}`；未配置时为 null。
 */
export function readNamedTunnel(configDir) {
  try {
    const parsed = JSON.parse(readFileSync(join(configDir, 'named-tunnel.json'), 'utf8'))
    const name = parsed?.name
    const hostname = parsed?.hostname
    if (typeof name === 'string' && name !== '' && typeof hostname === 'string' && hostname !== '') {
      return { name, hostname }
    }
  } catch {
    /* 未配置或文件损坏，退回快速隧道 */
  }
  return null
}

/** Harness 主目录；子进程与代理都以它定位凭据文件。 */
function resolveDshHome() {
  const fromEnv = process.env.DSH_HOME
  if (typeof fromEnv === 'string' && fromEnv !== '') return fromEnv
  return join(homedir(), '.dsh')
}

/**
 * 在 PATH 与常见安装位置里找出 cloudflared。
 * 为什么不用 `@deepseek-ai/dsh-subprocess` 的 resolveExecutable：本地 link 的插件包
 * 解析不到 `@deepseek-ai/*`（profile 的 node_modules 里没有它们），所以只用 Node 内置能力。
 *
 * @returns 绝对路径；找不到时为 null。
 */
function resolveCloudflared() {
  const separator = process.platform === 'win32' ? ';' : ':'
  const names = process.platform === 'win32' ? ['cloudflared.exe', 'cloudflared.cmd'] : ['cloudflared']
  for (const entry of String(process.env.PATH ?? '').split(separator)) {
    if (entry === '') continue
    for (const name of names) {
      const candidate = join(entry, name)
      if (existsSync(candidate)) return candidate
    }
  }
  for (const candidate of CLOUDFLARED_FALLBACKS) {
    if (existsSync(candidate)) return candidate
  }
  return null
}

/**
 * 从 cloudflared 的日志里取出快速隧道地址。
 *
 * 先认公布行（带边框的那一行），认不到再退回宽松匹配；两条都要求主机名含连字符，
 * 因此 `api.trycloudflare.com` 这类控制面地址永远不会被当成隧道地址。
 *
 * @param text - 累积的子进程日志。
 * @returns 隧道地址；尚未公布时为 undefined。
 */
export function extractTunnelUrl(text) {
  const announced = text.match(TUNNEL_ANNOUNCEMENT)
  if (announced !== null) return announced[1]
  const loose = text.match(TUNNEL_URL)
  return loose === null ? undefined : loose[0]
}

/**
 * 轮询直到 `probe` 返回一个值。
 * @param probe - 每轮调用；返回 undefined 表示还没就绪，抛错表示立即失败。
 * @param timeoutMs - 超时上限。
 * @param intervalMs - 轮询间隔。
 * @returns probe 给出的值。
 */
function waitFor(probe, timeoutMs, intervalMs) {
  return new Promise((resolve, reject) => {
    const startedAt = Date.now()
    const tick = () => {
      let value
      try {
        value = probe()
      } catch (error) {
        reject(error)
        return
      }
      if (value !== undefined) {
        resolve(value)
        return
      }
      if (Date.now() - startedAt >= timeoutMs) {
        reject(new Error(`timed out after ${String(timeoutMs)} ms`))
        return
      }
      setTimeout(tick, intervalMs)
    }
    tick()
  })
}

/**
 * 注册隧道控制路由与状态机。
 * @param ctx - 宿主根上下文。
 */
export function apply(ctx) {
  const log = (message) => ctx.logger?.info?.(`dsh-tunnel: ${message}`)
  const warn = (message) => ctx.logger?.warn?.(`dsh-tunnel: ${message}`)

  const proxyScript = join(dirname(fileURLToPath(import.meta.url)), 'edge-proxy.mjs')
  const dshHome = resolveDshHome()
  const configDir = join(dshHome, CONFIG_DIR_NAME)

  // 启动时就定下来的几件事：登录账号、可选固定域名、是否随 DSH 自启。
  // 口令本身不经过宿主半 —— 校验完全在边界代理里做。
  const loginUser = readLoginUser(configDir)
  const credentialsFile = join(configDir, 'credentials.json')
  const named = readNamedTunnel(configDir)
  const autostart = existsSync(join(configDir, 'autostart'))

  /** 对外状态。所有字段都是可 JSON 化的标量，客户端半直接渲染。 */
  const state = {
    phase: 'stopped',
    error: null,
    publicUrl: null,
    accessUrl: null,
    startedAt: null,
    lastChange: null,
    cloudflaredPath: null,
    /** 本轮首次公布的地址，用来判断重连后链接是否变了。 */
    firstPublicUrl: null,
    /** 自动重连成功的次数。 */
    renewCount: 0,
  }
  let proxyChild = null
  let tunnelChild = null
  let autoStopTimer = null
  let healTimer = null
  let healAttempts = 0
  /** 进行中的启停操作；并发点击共用同一个 Promise，避免重复拉起子进程。 */
  let inFlight = null
  let proxyOut = ''
  let proxyErr = ''
  let tunnelOut = ''
  let tunnelErr = ''

  function snapshot() {
    return {
      phase: state.phase,
      revision: REVISION,
      error: state.error,
      publicUrl: state.publicUrl,
      accessUrl: state.accessUrl,
      startedAt: state.startedAt,
      lastChange: state.lastChange,
      proxyPort: PROXY_PORT,
      target: TARGET_AUTHORITY,
      // 0 表示不自动断开，界面据此显示「不自动断开」而不是「0 小时」。
      autoStopHours: AUTO_STOP_MS === 0 ? 0 : Math.round(AUTO_STOP_MS / 3600000),
      cloudflaredPath: state.cloudflaredPath,
      renewCount: state.renewCount,
      // 重连后主机名变了就要显眼地告诉使用者：旧链接已经作废。
      // 配了 Named Tunnel 时域名固定，这里永远是 false。
      linkChanged: state.firstPublicUrl !== null && state.publicUrl !== state.firstPublicUrl,
      /** 固定域名的模式：有值时界面显示「固定域名」而不是「临时链接」。 */
      namedHostname: named === null ? null : named.hostname,
      /** 登录账号名；null 表示还没设置账号密码，隧道会拒绝启动。 */
      loginUser,
      /** 隧道是否随 DSH 自动开启。 */
      autostart,
      configDir,
    }
  }

  /** 保留日志尾部，用于把失败原因连同诊断一起抛回界面。 */
  function append(current, chunk) {
    const next = current + chunk
    return next.length <= LOG_LIMIT ? next : next.slice(next.length - LOG_LIMIT)
  }

  /** 拼出给人看的失败诊断。 */
  function diagnostics() {
    const parts = []
    if (proxyErr.trim() !== '') parts.push(`proxy stderr: ${proxyErr.trim().slice(-500)}`)
    if (proxyOut.trim() !== '') parts.push(`proxy stdout: ${proxyOut.trim().slice(-300)}`)
    if (tunnelErr.trim() !== '') parts.push(`tunnel stderr: ${tunnelErr.trim().slice(-600)}`)
    if (tunnelOut.trim() !== '') parts.push(`tunnel stdout: ${tunnelOut.trim().slice(-300)}`)
    return parts.length === 0 ? '(no child output)' : parts.join(' | ')
  }

  /** 结束一个子进程并等它真正退出，这样重启时端口已经释放。 */
  function killChild(child) {
    if (child === null || child.exitCode !== null) return Promise.resolve()
    return new Promise((resolve) => {
      const done = () => resolve()
      child.once('exit', done)
      try {
        child.kill()
      } catch {
        resolve()
        return
      }
      setTimeout(() => {
        if (child.exitCode === null) {
          try {
            child.kill('SIGKILL')
          } catch {
            /* already gone */
          }
        }
        resolve()
      }, 2500)
    })
  }

  /**
   * 盯住一个已经进入运行态的子进程。
   *
   * 启动阶段的退出由各自的等待循环负责报错；只有「已经在 running 之后才退出」需要在这里
   * 收拾 —— 否则 cloudflared 崩了、代理挂了，界面还会一直显示「运行中」，比报错更糟。
   *
   * 三个必须的细节：
   * - 先确认这个 child 仍是当前那一个。`stopAll` 在杀进程**之前**就把两个引用置空，
   *   所以正常停止触发的 exit 会在这里被挡掉，不会把 lastChange 覆盖成「意外退出」。
   * - cloudflared 意外退出时先尝试自动重连（`healable`），因为出差在外没人能点那个按钮。
   *   代理退出则是致命的：它是唯一入口，没有它重连隧道也没有意义。
   * - 兜底走 `stopAll` 而不是 `haltAll`：后者在 `inFlight` 非空时直接返回。而「cloudflared
   *   公布地址后立刻退出」恰好发生在这个窗口里，会让状态永远停在 running。
   *
   * @param child - 被盯的子进程。
   * @param label - 出现在日志与状态里的名字。
   * @param healable - 是否值得自动重连。
   */
  function watchChild(child, label, healable) {
    child.once('exit', (code, signal) => {
      if (state.phase !== 'running') return
      if (child !== tunnelChild && child !== proxyChild) return
      warn(`${label} 意外退出（code=${String(code)} signal=${String(signal)}）`)
      if (healable && healAttempts < MAX_HEAL_ATTEMPTS) {
        scheduleHeal(label)
        return
      }
      void stopAll(`${label} 意外退出`)
    })
  }

  /**
   * 安排一次自动重连。
   *
   * 只重起 cloudflared，代理原样留着：代理是入口、密钥也在它手里，保住它意味着重连后
   * 链接只有主机名会变，访问口令不变。Cloudflare 分配新域名是不可避免的（快速隧道的
   * 域名随进程走），所以 `linkChanged` 会亮起来提醒使用者换用新链接。
   *
   * @param label - 退出者名字，仅用于文案。
   */
  function scheduleHeal(label) {
    healAttempts += 1
    const attempt = healAttempts
    state.lastChange = `${label} 意外退出，${String(HEAL_DELAY_MS / 1000)} 秒后自动重连（第 ${String(attempt)}/${String(MAX_HEAL_ATTEMPTS)} 次）`
    warn(state.lastChange)
    healTimer = setTimeout(() => {
      healTimer = null
      void reconnect()
    }, HEAL_DELAY_MS)
    // 重连计时器不应把进程钉住不退出。
    healTimer.unref?.()
  }

  /** 执行一次自动重连；失败则继续按节奏重试，直到用完次数。 */
  async function reconnect() {
    if (state.phase !== 'running') return
    const previousUrl = state.publicUrl
    tunnelChild = null
    try {
      const publicUrl = await startTunnel(state.cloudflaredPath)
      state.publicUrl = publicUrl
      state.accessUrl = `${publicUrl}/`
      state.renewCount += 1
      healAttempts = 0
      const same = publicUrl === previousUrl
      state.lastChange = same
        ? `已自动重连，链接不变（第 ${String(state.renewCount)} 次）`
        : `已自动重连，但链接已更换（第 ${String(state.renewCount)} 次）`
      log(state.lastChange)
    } catch (error) {
      const message = String(error?.message ?? error)
      state.lastChange = `自动重连失败：${message}`
      warn(state.lastChange)
      if (healAttempts < MAX_HEAL_ATTEMPTS) scheduleHeal('cloudflared')
      else await stopAll('自动重连次数已达上限，隧道已断开')
    }
  }

  /** 停掉所有子进程并复位状态。reason 会记录在 lastChange 里，便于界面解释变化。 */
  async function stopAll(reason) {
    if (autoStopTimer !== null) {
      clearTimeout(autoStopTimer)
      autoStopTimer = null
    }
    if (healTimer !== null) {
      clearTimeout(healTimer)
      healTimer = null
    }
    healAttempts = 0
    const children = [tunnelChild, proxyChild]
    tunnelChild = null
    proxyChild = null
    for (const child of children) await killChild(child)

    state.phase = 'stopped'
    state.publicUrl = null
    state.accessUrl = null
    state.startedAt = null
    state.firstPublicUrl = null
    state.renewCount = 0
    state.lastChange = reason
    proxyOut = ''
    proxyErr = ''
    tunnelOut = ''
    tunnelErr = ''
    return snapshot()
  }

  /** 拉起边界代理并等它交出访问密钥。 */
  async function startProxy() {
    proxyOut = ''
    proxyErr = ''
    const child = spawn(
      process.execPath,
      // 显式传入持久口令：代理只在拿到空值时才自己生成随机值，这里给的是跨重启固定的那一个。
      [proxyScript, String(PROXY_PORT), TARGET_AUTHORITY, credentialsFile, dshHome],
      { cwd: dirname(proxyScript), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] },
    )
    proxyChild = child
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      proxyOut = append(proxyOut, chunk)
    })
    child.stderr.on('data', (chunk) => {
      proxyErr = append(proxyErr, chunk)
    })

    let exited = false
    child.once('exit', () => {
      exited = true
    })
    watchChild(child, '边界代理', false)

    return waitFor(
      () => {
        // 先判退出再判就绪：失败路径同样会往 stdout/stderr 写东西（例如账号密码文件缺失），
        // 顺序反了会把一次失败当成启动成功，而状态之后再也回不来。
        if (exited) throw new Error(`边界代理启动即退出。${diagnostics()}`)
        return PROXY_READY_PATTERN.test(proxyOut) ? true : undefined
      },
      WAIT_PROXY_MS,
      150,
    )
  }

  /**
   * 拉起 cloudflared 并等它就绪。
   *
   * 两种模式：
   * - **Named Tunnel**（配置了 `named-tunnel.json`）：`tunnel run <name>`，域名由配置直接给出，
   *   不需要解析日志；判据改为「注册上连接」（`Registered tunnel connection`），这样才代表
   *   真的通了，而不是进程还活着。
   * - **快速隧道**：现取的随机域名，从日志里解析。
   *
   * @param cloudflaredPath - cloudflared 可执行文件。
   * @returns 公网基地址（不含口令）。
   */
  async function startTunnel(cloudflaredPath) {
    tunnelOut = ''
    tunnelErr = ''
    const origin = `http://127.0.0.1:${String(PROXY_PORT)}`
    const args = named === null
      ? ['tunnel', '--no-autoupdate', '--url', origin]
      : ['tunnel', '--no-autoupdate', 'run', '--url', origin, named.name]
    const child = spawn(
      cloudflaredPath,
      args,
      { cwd: dirname(proxyScript), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] },
    )
    tunnelChild = child
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      tunnelOut = append(tunnelOut, chunk)
    })
    child.stderr.on('data', (chunk) => {
      tunnelErr = append(tunnelErr, chunk)
    })

    let exited = false
    child.once('exit', () => {
      exited = true
    })
    watchChild(child, 'cloudflared', true)

    return waitFor(
      () => {
        // 顺序至关重要：cloudflared 失败时会先打印含地址的日志再退出。若先取地址，
        // 就会把一次失败当成启动成功，界面显示一个死链接。
        if (exited) throw new Error(`cloudflared 在就绪前退出。${diagnostics()}`)
        if (named !== null) {
          const connected = /Registered tunnel connection/u.test(`${tunnelErr}${tunnelOut}`)
          return connected ? `https://${named.hostname}` : undefined
        }
        return extractTunnelUrl(tunnelErr) ?? extractTunnelUrl(tunnelOut)
      },
      named === null ? WAIT_TUNNEL_MS : WAIT_REGISTER_MS,
      250,
    )
  }

  /** 启动隧道。并发调用共用同一次启动。 */
  function startAll() {
    if (inFlight !== null) return inFlight
    if (state.phase === 'running') return Promise.resolve(snapshot())

    inFlight = (async () => {
      state.phase = 'starting'
      state.error = null
      try {
        if (!existsSync(proxyScript)) throw new Error(`边界代理脚本缺失：${proxyScript}`)
        const cloudflaredPath = resolveCloudflared()
        if (cloudflaredPath === null) {
          throw new Error('找不到 cloudflared。安装：winget install Cloudflare.cloudflared（装完需重启 dsh web 以刷新 PATH）')
        }
        state.cloudflaredPath = cloudflaredPath

        await startProxy()
        const publicUrl = await startTunnel(cloudflaredPath)

        state.publicUrl = publicUrl
        state.firstPublicUrl = publicUrl
        state.renewCount = 0
        healAttempts = 0
        // 链接就是域名本身；登录在浏览器里完成，地址栏里不再带任何密钥。
        state.accessUrl = `${publicUrl}/`
        state.startedAt = Date.now()
        state.phase = 'running'
        state.lastChange = '隧道已启动'
        log(`已发布 ${publicUrl}`)

        // AUTO_STOP_MS 为 0 表示不自动断开：出差在外时一条定时断开的隧道等于把自己锁在门外。
        if (AUTO_STOP_MS > 0) {
          autoStopTimer = setTimeout(() => {
            void stopAll(`已达最长运行时间 ${String(Math.round(AUTO_STOP_MS / 3600000))} 小时，自动断开`)
            log('自动断开：超过最长运行时间')
          }, AUTO_STOP_MS)
          // 计时器不应把进程钉住不退出。
          autoStopTimer.unref?.()
        }
      } catch (error) {
        const message = String(error?.message ?? error)
        await stopAll('启动失败')
        state.phase = 'error'
        state.error = message
        warn(`启动失败：${message}`)
      }
      return snapshot()
    })().finally(() => {
      inFlight = null
    })

    return inFlight
  }

  /** 停止隧道。并发调用共用同一次停止。 */
  function haltAll(reason) {
    if (inFlight !== null) return inFlight
    inFlight = stopAll(reason).finally(() => {
      inFlight = null
    })
    return inFlight
  }

  /** 统一 JSON 响应。 */
  function sendJson(res, status, payload) {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
    res.end(JSON.stringify(payload))
  }

  /** 注册一条只回 JSON 的路由；每个端点自己吞掉异常，不让 500 冒成连接中断。 */
  function route(path, handle) {
    ctx.effect(() => ctx.webServer.register({
      kind: 'exact',
      path: `${ROUTE_PREFIX}${path}`,
      handler: async (req, res) => {
        try {
          sendJson(res, 200, await handle())
        } catch (error) {
          sendJson(res, 500, { ok: false, error: String(error?.message ?? error).slice(0, 400) })
        }
      },
    }))
  }

  route('/api/status', () => snapshot())
  route('/api/start', () => startAll())
  route('/api/stop', () => haltAll('已在设置页停止'))

  // 插件卸载（profile 重载、DSH 退出）时必须断开隧道：否则公网入口会留着一个
  // 没人管的监听，而代理进程本身已经不属于任何 fiber。
  ctx.effect(() => () => {
    void stopAll('插件已卸载')
  })

  // 自启：开机后没人能点那个按钮，所以由配置目录里的 `autostart` 文件决定是否自动开隧道。
  // 延迟几秒是为了避开 DSH 自身启动的那一阵忙，也让 webServer 先把路由挂好。
  if (autostart) {
    const timer = setTimeout(() => {
      log('autostart 已启用，自动开启隧道')
      void startAll()
    }, AUTOSTART_DELAY_MS)
    timer.unref?.()
    ctx.effect(() => () => clearTimeout(timer))
  }

  log(`已就绪：设置 → 内网穿透（${named === null ? '快速隧道' : `固定域名 ${named.hostname}`}${autostart ? '，已启用自启' : ''}）`)
}
