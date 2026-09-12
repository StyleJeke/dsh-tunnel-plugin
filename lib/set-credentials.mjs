/**
 * 设置隧道登录用的账号密码。
 *
 * 只在本机交互式运行：
 *
 *   node C:\plugins\dsh-tunnel-plugin\lib\set-credentials.mjs
 *
 * 口令通过隐藏输入读取，**不接受命令行参数**（那会出现在进程列表和 shell 历史里），
 * 也不写入任何日志。落盘的只有 scrypt 摘要。
 *
 * 每次写入都会同时轮换会话签名密钥，于是所有已经登录的浏览器立刻失效 —— 改口令之后
 * 应当发生的事。
 *
 * @module dsh-tunnel/set-credentials
 */
import { randomBytes, scryptSync } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { createInterface } from 'node:readline'

/**
 * scrypt 参数。
 *
 * **`N` 必须大写。** Node 的选项名就是大写的 `N`，小写 `n` 会被**静默忽略**、回落到默认的
 * 16384。曾经写成小写，于是摘要按 16384 算、文件里却记着 32768，代理照着 32768 校验，
 * 正确口令永远对不上 —— 一个只在校验时才暴露的错。下面的自检就是为了让这类错在写入时
 * 当场炸掉，而不是等到登录失败。
 */
const SCRYPT = { N: 32768, r: 8, p: 1 }
const SCRYPT_MAXMEM = 96 * 1024 * 1024
/** 绝对长度下限；低于这个值无论字符多杂都不接受。 */
const MIN_LENGTH = 8
/** 硬性熵下限：只用来挡住真正退化的口令（例如 8 位纯数字）。 */
const MIN_BITS_HARD = 30
/** 建议线：低于它不拒绝，只提醒一句。 */
const MIN_BITS_ADVISE = 60

const DSH_HOME = typeof process.env.DSH_HOME === 'string' && process.env.DSH_HOME !== ''
  ? process.env.DSH_HOME
  : join(homedir(), '.dsh')
const FILE = process.argv[2] ?? join(DSH_HOME, 'tunnel', 'credentials.json')

/** 常见弱口令的一小撮；命中直接拒绝。 */
const WEAK = new Set([
  'password', 'passw0rd', '12345678', '123456789', '1234567890', 'qwertyuiop',
  'administrator', 'admin123', 'letmein123', 'iloveyou', 'dsh123456',
])

/**
 * 粗估口令熵（bit）。
 *
 * 为什么不数「字符种类」：那条规则是拉丁中心的 —— 一串同样长度的中文口令会被它判成
 * 只有一类而拒绝，可每个汉字的信息量远高于一个英文字母。按每类字符的近似信息量求和，
 * 中英文与符号串就落在同一把尺子上。
 *
 * 这只是**下限**估计：它看不穿 `Password123` 这种「词 + 后缀」的低熵模式，所以
 * {@link WEAK} 之外仍然建议用互不相关的多词短语。
 *
 * @param password - 候选口令。
 * @returns 估算熵（bit，四舍五入）。
 */
function estimateBits(password) {
  let cjk = 0
  let lower = 0
  let upper = 0
  let digit = 0
  let other = 0
  for (const ch of password) {
    if (/[\u3400-\u9FFF\uF900-\uFAFF\u3040-\u30FF\uAC00-\uD7AF]/u.test(ch)) cjk += 1
    else if (/[a-z]/u.test(ch)) lower += 1
    else if (/[A-Z]/u.test(ch)) upper += 1
    else if (/[0-9]/u.test(ch)) digit += 1
    else other += 1
  }
  // 每类字符的近似信息量：汉字 ~11bit，符号 ~5bit，大小写字母 ~4.7bit，数字 ~3.3bit。
  return Math.round(cjk * 11 + other * 5 + lower * 4.7 + upper * 4.7 + digit * 3.3)
}

/**
 * 评估口令强度。
 *
 * 判定尺度刻意放松：真正扛住在线爆破的是代理那条按来源 IP 逐次加倍的锁定，而不是这里的
 * 字符规则；这里的硬下限只用来挡住「12345678」这类退化口令，其余情况给出估算强度和建议
 * 但放行 —— 这是使用者自己的机器，由他自己权衡。
 *
 * @param password - 候选口令。
 * @returns `{bits, reason, advice}`；reason 为 null 表示通过，advice 为提醒文本。
 */
function assess(password) {
  const bits = estimateBits(password)
  if (password.length < MIN_LENGTH) {
    return { bits, reason: `至少需要 ${String(MIN_LENGTH)} 个字符（当前 ${String(password.length)}）`, advice: null }
  }
  if (WEAK.has(password.toLowerCase())) return { bits, reason: '这是常见弱口令', advice: null }
  if (/^(.)\1+$/u.test(password)) return { bits, reason: '不能是同一个字符的重复', advice: null }
  if (bits < MIN_BITS_HARD) {
    return { bits, reason: `估算强度只有约 ${String(bits)} bit，太容易被猜到。加几个字符，或换几个互不相关的词`, advice: null }
  }
  const advice = bits < MIN_BITS_ADVISE
    ? `提示：估算强度约 ${String(bits)} bit。够用（代理有登录限速），但换成几个互不相关的词拼成的短语会更稳。`
    : null
  return { bits, reason: null, advice }
}

/** 普通（可见）提问。 */
function ask(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close()
      resolve(answer.trim())
    })
  })
}

/**
 * 隐藏输入提问：开 raw 模式，回显自然关闭。
 * @param prompt - 提示文本。
 * @returns 输入内容。
 */
function askHidden(prompt) {
  return new Promise((resolve, reject) => {
    if (process.stdin.isTTY !== true) {
      reject(new Error('需要交互式终端：请在真实终端里运行本脚本，不要通过管道调用'))
      return
    }
    process.stdout.write(prompt)
    process.stdin.setRawMode(true)
    process.stdin.resume()
    process.stdin.setEncoding('utf8')
    let value = ''
    const cleanup = () => {
      process.stdin.removeListener('data', onData)
      process.stdin.setRawMode(false)
      process.stdin.pause()
    }
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') {
          cleanup()
          process.stdout.write('\n')
          resolve(value)
          return
        }
        if (ch === '\u0003') {
          cleanup()
          process.stdout.write('\n已取消。\n')
          process.exit(130)
        }
        if (ch === '\u007f' || ch === '\b') {
          value = value.slice(0, -1)
          continue
        }
        if (ch < ' ') continue
        value += ch
      }
    }
    process.stdin.on('data', onData)
  })
}

const existing = existsSync(FILE) ? (() => {
  try {
    return JSON.parse(readFileSync(FILE, 'utf8'))
  } catch {
    return undefined
  }
})() : undefined

console.log('=== 设置 DSH 隧道登录账号 ===')
console.log(`写入位置：${FILE}`)
if (existing !== undefined) console.log(`当前账号：${String(existing.username)}（改口令后所有已登录的浏览器会立刻失效）`)
console.log('口令只在本机输入，不会经过网络，也不会写进任何日志或命令历史。\n')

const defaultUser = typeof existing?.username === 'string' && existing.username !== '' ? existing.username : 'admin'
const username = (await ask(`账号 [${defaultUser}]: `)) || defaultUser
if (username === '' || /\s/u.test(username)) {
  console.error('账号不能为空，也不能包含空白字符。')
  process.exit(1)
}

const password = await askHidden(`密码（至少 ${String(MIN_LENGTH)} 位，输入时不回显）: `)
const verdict = assess(password)
if (verdict.reason !== null) {
  console.error(`\n口令不合格：${verdict.reason}`)
  process.exit(1)
}
if (verdict.advice !== null) console.log(`\n${verdict.advice}`)

const again = await askHidden('再输一次确认: ')
if (again !== password) {
  console.error('\n两次输入不一致。')
  process.exit(1)
}

const salt = randomBytes(16)
const hash = scryptSync(password, salt, 32, { ...SCRYPT, maxmem: SCRYPT_MAXMEM })

// 写入前自检：用「代理将来会用的那组参数」重新算一遍，确认能对上。
// 这条正是为了拦住「参数名写错、摘要按别的参数算」那类只在登录时才暴露的错。
const roundTrip = scryptSync(password, salt, 32, {
  N: SCRYPT.N,
  r: SCRYPT.r,
  p: SCRYPT.p,
  maxmem: SCRYPT_MAXMEM,
})
if (!roundTrip.equals(hash)) {
  console.error('\n内部错误：口令摘要自检不通过（scrypt 参数不一致）。文件未写入，请把这条报给维护者。')
  process.exit(1)
}

mkdirSync(dirname(FILE), { recursive: true })
writeFileSync(FILE, `${JSON.stringify({
  version: 1,
  username,
  salt: salt.toString('base64url'),
  hash: hash.toString('base64url'),
  // 每次轮换：既有的会话 cookie 全部作废。
  sessionSecret: randomBytes(32).toString('base64url'),
  // 注意这里是数据字段 `n`（代理照它读取），与上面 Node 选项的大写 `N` 不是一回事。
  n: SCRYPT.N,
  r: SCRYPT.r,
  p: SCRYPT.p,
  updatedAt: new Date().toISOString(),
}, null, 2)}\n`, { mode: 0o600 })

console.log(`\n已保存（账号 ${username}，估算强度约 ${String(verdict.bits)} bit）。`)
// 域名从配置里读，不写死在代码里 —— 这是使用者的私有域名，不该出现在源码中。
let publicHost
try {
  publicHost = JSON.parse(readFileSync(join(dirname(FILE), 'named-tunnel.json'), 'utf8')).hostname
} catch {
  publicHost = undefined
}
console.log(typeof publicHost === 'string' && publicHost !== ''
  ? `访问 https://${publicHost}/ 会看到登录页；登录后 30 天内免登录。`
  : '隧道启动后访问它的公网地址会看到登录页；登录后 30 天内免登录。')
console.log('如果隧道正在运行，先在设置页点一次「停止」再「启动」，让它读到新配置。')
